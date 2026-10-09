"""Read original bytes once; preview transformations never enter inference."""
import base64
import hashlib
import io
import warnings
from dataclasses import dataclass, field
from pathlib import Path

from PIL import Image

MAX_BYTES = 20 * 1024 * 1024
MAX_PIXELS = 40_000_000

@dataclass(frozen=True)
class LocalImage:
    name: str
    raw: bytes = field(repr=False)
    sha256: str
    width: int
    height: int
    format: str
    frame_id: str

    @classmethod
    def load(cls, path, frame_id='frame-1'):
        path = Path(path)
        if path.suffix.lower() not in {'.jpg', '.jpeg', '.png'}:
            raise ValueError('JPEG or PNG required')
        with path.open('rb') as stream:
            raw = stream.read(MAX_BYTES + 1)
        if not raw or len(raw) > MAX_BYTES:
            raise ValueError('Image size limit')
        with warnings.catch_warnings():
            warnings.simplefilter('error', Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(raw)) as im:
                width, height = im.size
                fmt = im.format
                if fmt not in {'JPEG', 'PNG'} or width * height > MAX_PIXELS:
                    raise ValueError('Unsupported image')
                if getattr(im, 'n_frames', 1) != 1:
                    raise ValueError('Single frame required')
                im.verify()
            with Image.open(io.BytesIO(raw)) as im:
                im.load()
        if not isinstance(frame_id, str) or not frame_id.strip() or len(frame_id) > 100:
            raise ValueError('Invalid local frame ID')
        return cls(path.name, raw, hashlib.sha256(raw).hexdigest(), width, height, fmt, frame_id)

    def preview(self, size=(640, 440)):
        with Image.open(io.BytesIO(self.raw)) as im:
            image = im.convert('RGB')
        image.thumbnail(size)
        return image

    def manifest(self):
        return {'reference': self.name, 'sha256': self.sha256, 'width': self.width,
                'height': self.height, 'format': self.format, 'order': 0,
                'detail': 'high', 'client_processing': 'none', 'frame_id': self.frame_id}

    def data_uri(self):
        if hashlib.sha256(self.raw).hexdigest() != self.sha256:
            raise ValueError('Image integrity failure')
        mime = 'image/jpeg' if self.format == 'JPEG' else 'image/png'
        return f'data:{mime};base64,' + base64.b64encode(self.raw).decode('ascii')
