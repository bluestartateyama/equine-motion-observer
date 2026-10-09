"""Single-shot fixed-endpoint HTTPS. No retries, redirects, proxies or API keys."""
import json
import ssl
import time
import threading
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass, field

ISSUER = 'https://auth.openai.com'
RESOURCE = 'https://api.openai.com/v1'
AUTHORIZE = ISSUER + '/api/accounts/authorize'
TOKEN = ISSUER + '/api/accounts/oauth/token'
DISCOVERY = ISSUER + '/.well-known/openid-configuration'
MODELS = RESOURCE + '/models'
RESPONSES = RESOURCE + '/responses'

class TransportError(RuntimeError):
    pass

@dataclass
class Reply:
    status: int
    headers: dict
    body: bytes = field(repr=False)

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise TransportError('Redirect rejected')

class HTTPSClient:
    def __init__(self, enabled=False):
        self.enabled = enabled
        self.discovered = set()
        self._stream_lock = threading.Lock()
        self._active_stream = None
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()))

    def allow_discovered(self, url, method='GET'):
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != 'https' or parts.netloc != 'auth.openai.com' or parts.query or parts.fragment:
            raise TransportError('Untrusted identity endpoint')
        if method not in {'GET', 'POST'}:
            raise TransportError('Identity endpoint method rejected')
        self.discovered.add((method, url))

    def _request(self, method, url, headers, body):
        if not self.enabled:
            raise TransportError('Live connection disabled')
        allowed = {('GET', DISCOVERY), ('POST', TOKEN), ('GET', MODELS), ('POST', RESPONSES)}
        if (method, url) not in allowed and (method, url) not in self.discovered:
            raise TransportError('Endpoint rejected')
        parts = urllib.parse.urlsplit(url)
        if parts.query or parts.fragment or parts.username or parts.password:
            raise TransportError('Credential-bearing URL rejected')
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            return self.opener.open(request, timeout=30)
        except urllib.error.HTTPError as error:
            return error
        except Exception:
            raise TransportError('HTTPS request did not complete; do not resend') from None

    def request(self, method, url, headers=None, body=None):
        with self._request(method, url, headers or {}, body) as response:
            raw = response.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise TransportError('Response limit exceeded')
            return Reply(response.status, dict(response.headers), raw)

    @contextmanager
    def stream(self, url, headers, body):
        response = self._request('POST', url, headers, body)
        with self._stream_lock:
            self._active_stream = response
        try:
            def chunks():
                total = 0
                start = time.monotonic()
                while True:
                    if time.monotonic() - start > 180:
                        raise TransportError('Stream time limit; completion unknown')
                    part = response.read1(16384)
                    if not part:
                        break
                    total += len(part)
                    if total > 4 * 1024 * 1024:
                        raise TransportError('Stream size limit')
                    yield part
            yield response.status, dict(response.headers), chunks()
        except TransportError:
            raise
        except Exception:
            raise TransportError('Stream interrupted; completion unknown') from None
        finally:
            with self._stream_lock:
                self._active_stream = None
            response.close()

    def stop_receiving(self):
        """Close only this local receiver; server execution may continue."""
        with self._stream_lock:
            response = self._active_stream
        if response is not None:
            response.close()

def json_reply(reply):
    if reply.status != 200:
        raise TransportError(f'HTTP {reply.status}; no retry')
    from .observation import strict_json
    try:
        value = strict_json(reply.body.decode('utf-8'))
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (ValueError, UnicodeError):
        raise TransportError('Invalid endpoint response') from None

def form_request(transport, url, fields):
    return transport.request('POST', url, {'Content-Type': 'application/x-www-form-urlencoded'},
        urllib.parse.urlencode(fields).encode('ascii'))
