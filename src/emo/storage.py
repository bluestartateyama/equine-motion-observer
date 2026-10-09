"""Atomic local files, operating-system locks, Windows CurrentUser DPAPI."""
import ctypes
import json
import os
import subprocess
import tempfile
from contextlib import contextmanager
from ctypes import wintypes
from pathlib import Path

def local_root():
    if os.name != 'nt' or not os.environ.get('LOCALAPPDATA'):
        raise RuntimeError('Windows local credential storage required')
    root = Path(os.environ['LOCALAPPDATA']) / 'EquineMotionObserver'
    # Credentials must not reside on a redirected/cloud-backed user folder.
    root = root.absolute()
    if any('onedrive' in p.lower() for p in root.parts):
        raise RuntimeError('Cloud-backed credential storage rejected')
    return root

def atomic_write(path, raw):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix='.writing-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)

@contextmanager
def file_lock(path):
    """No waiting/retry; the OS releases the lock when a process exits."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    stream = path.open('a+b')
    try:
        stream.seek(0, 2)
        if stream.tell() == 0:
            stream.write(b'0')
            stream.flush()
        stream.seek(0)
        if os.name == 'nt':
            import msvcrt
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == 'nt':
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
    finally:
        stream.close()

class Blob(ctypes.Structure):
    _fields_ = [('size', wintypes.DWORD), ('data', ctypes.POINTER(ctypes.c_ubyte))]

class WindowsProtector:
    def protect(self, data):
        return self._call(data, False)

    def unprotect(self, data):
        return self._call(data, True)

    @staticmethod
    def _call(raw, decrypt):
        if os.name != 'nt':
            raise RuntimeError('DPAPI unavailable')
        buf = (ctypes.c_ubyte * len(raw)).from_buffer_copy(raw)
        source = Blob(len(raw), buf)
        target = Blob()
        crypto = ctypes.WinDLL('crypt32', use_last_error=True)
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        func = crypto.CryptUnprotectData if decrypt else crypto.CryptProtectData
        func.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.POINTER(Blob),
                         ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
        func.restype = wintypes.BOOL
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.LocalFree.restype = ctypes.c_void_p
        if not func(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(target)):
            raise RuntimeError('Windows credential protection failed')
        try:
            return ctypes.string_at(target.data, target.size)
        finally:
            kernel.LocalFree(target.data)

def owner_acl(directory):
    """Set a protected directory DACL allowing only this Windows user."""
    if os.name != 'nt':
        raise RuntimeError('Owner-only Windows ACL required')
    directory = Path(directory).absolute()
    if any(p.is_symlink() or p.is_junction() for p in (directory, *directory.parents)):
        raise RuntimeError('Redirected credential path rejected')
    directory.mkdir(parents=True, exist_ok=True)
    query = subprocess.run(['whoami', '/user', '/fo', 'csv', '/nh'], capture_output=True,
                           text=True, check=True, creationflags=0x08000000)
    import csv
    sid = next(csv.reader([query.stdout.strip()]))[-1]
    if not sid.startswith('S-1-'):
        raise RuntimeError('Windows user lookup failed')
    # Replace the whole DACL instead of retaining unknown explicit ACEs.
    advapi = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    descriptor = ctypes.c_void_p()
    convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    convert.restype = wintypes.BOOL
    apply = advapi.SetFileSecurityW
    apply.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    apply.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    if not convert(f'D:P(A;OICI;FA;;;{sid})', 1, ctypes.byref(descriptor), None):
        raise RuntimeError('Credential ACL creation failed')
    try:
        if not apply(str(directory), 0x00000004 | 0x80000000, descriptor):
            raise RuntimeError('Credential ACL setup failed')
    finally:
        kernel.LocalFree(descriptor)

class CredentialStore:
    def __init__(self, directory, protector=None, secure=True):
        self.directory = Path(directory)
        if secure:
            owner_acl(self.directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.protector = protector or WindowsProtector()
        self.path = self.directory / 'credentials.dpapi'

    @contextmanager
    def transaction(self):
        with file_lock(self.directory / 'credentials.lock'):
            yield self

    def read(self):
        if not self.path.exists():
            return {'host_id': None, 'active': None, 'registrations': {}}
        try:
            raw = self.protector.unprotect(self.path.read_bytes())
            value = json.loads(raw)
            if not isinstance(value, dict) or set(value) != {'host_id', 'active', 'registrations'}:
                raise ValueError()
            return value
        except Exception:
            raise RuntimeError('Credential record unavailable; no automatic reset') from None

    def write(self, value):
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False).encode('utf-8')
        atomic_write(self.path, self.protector.protect(encoded))

class ResultStore:
    def __init__(self, directory):
        self.directory = Path(directory)

    def save(self, record):
        import uuid
        result_id = str(uuid.UUID(record['result_id']))
        self.directory.mkdir(parents=True, exist_ok=True)
        path = self.directory / (result_id + '.json')
        with file_lock(self.directory / 'results.lock'):
            if path.exists():
                raise ValueError('Result already saved')
            atomic_write(path, json.dumps(record, ensure_ascii=False, indent=2, allow_nan=False).encode('utf-8'))
        return path
