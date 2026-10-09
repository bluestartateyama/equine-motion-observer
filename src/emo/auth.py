"""Official public-client SIWC, implemented from protocol documentation."""
import base64
import hashlib
import secrets
import threading
import time
import urllib.parse
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .observation import strict_json
from .transport import (AUTHORIZE, DISCOVERY, ISSUER, RESOURCE, TOKEN, TransportError,
                        form_request, json_reply)

SCOPES = frozenset({'openid', 'profile', 'email', 'offline_access', 'resource.invoke', 'chatgpt.tokens.use.direct'})
APP_NAME = 'Equine Motion Observer'
DYNAMIC = 'dynamic_agent_client'

def b64url(raw):
    return base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')

def unb64(value):
    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))

def challenge(verifier):
    return b64url(hashlib.sha256(verifier.encode('ascii')).digest())

@dataclass(repr=False)
class Pending:
    host_id: str
    redirect_uri: str
    client_id: str = DYNAMIC
    registration_id: str | None = None
    subject: str | None = None
    id_hint: str | None = field(default=None, repr=False)
    state: str = field(default_factory=lambda: secrets.token_urlsafe(32), repr=False)
    nonce: str = field(default_factory=lambda: secrets.token_urlsafe(32), repr=False)
    verifier: str = field(default_factory=lambda: secrets.token_urlsafe(64), repr=False)
    created: float = field(default_factory=time.time)
    consumed: bool = False
    exchanged: bool = False
    callback_result: tuple | None = field(default=None, repr=False)

    def __repr__(self):
        return '<Pending SIWC authorization>'

    def url(self):
        fields = {'client_id': self.client_id, 'ext_agent_host_id': self.host_id,
            'response_type': 'code', 'redirect_uri': self.redirect_uri, 'scope': ' '.join(sorted(SCOPES)),
            'resource': RESOURCE, 'state': self.state, 'nonce': self.nonce,
            'code_challenge_method': 'S256', 'code_challenge': challenge(self.verifier)}
        if self.client_id == DYNAMIC:
            fields['agent_name_hint'] = APP_NAME
        elif self.id_hint:
            fields['id_token_hint'] = self.id_hint
        return AUTHORIZE + '?' + urllib.parse.urlencode(fields)

    def callback(self, query):
        if self.consumed or time.time() - self.created > 180:
            raise ValueError('Authorization expired or consumed')
        values = urllib.parse.parse_qs(query, keep_blank_values=True, max_num_fields=12)
        if any(len(v) != 1 for v in values.values()):
            raise ValueError('Duplicate callback parameters')
        if not secrets.compare_digest(values.get('state', [''])[0].encode('utf-8'), self.state.encode('utf-8')):
            raise ValueError('Authorization state mismatch')
        self.consumed = True
        if 'error' in values:
            raise ValueError('Authorization declined or failed')
        code = values.get('code', [''])[0]
        supplied = values.get('client_id', [''])[0]
        client = supplied or self.client_id
        if not code or len(code) > 4096 or not client or client == DYNAMIC or len(client) > 256 or any(c.isspace() for c in client):
            raise ValueError('Incomplete issued registration')
        if self.client_id != DYNAMIC and client != self.client_id:
            raise ValueError('Returning client identity mismatch')
        self.callback_result = code, client
        return self.callback_result

class Loopback:
    """Only loopback /auth/callback; queries never enter access logs."""
    def __init__(self):
        owner = self
        self.result = None
        self.done = threading.Event()
        self.pending = None

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                parts = urllib.parse.urlsplit(self.path)
                if parts.path != '/auth/callback' or len(self.path) > 8192:
                    self.send_error(404)
                    return
                try:
                    if owner.pending is None or owner.done.is_set():
                        raise ValueError('No pending authorization')
                    result = owner.pending.callback(parts.query)
                except ValueError:
                    self.send_response(400)
                    self.send_header('Content-Type', 'text/plain; charset=utf-8')
                    self.send_header('Cache-Control', 'no-store')
                    self.end_headers()
                    self.wfile.write(b'Authorization not accepted. Return to the local application.')
                    if owner.pending and owner.pending.consumed:
                        owner.result = ValueError('Authorization declined or failed')
                        owner.done.set()
                    return
                owner.result = result
                owner.done.set()
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.send_header('Cache-Control', 'no-store')
                self.end_headers()
                self.wfile.write(b'Authorization received. You may close this tab.')

        self.server = HTTPServer(('127.0.0.1', 0), Handler)
        self.uri = f'http://127.0.0.1:{self.server.server_port}/auth/callback'
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def wait(self):
        if not self.done.wait(180):
            raise ValueError('Authorization timeout')
        if isinstance(self.result, Exception):
            raise self.result
        return self.result

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

def verify_id(token, jwks, client_id, nonce=None, subject=None, now=None):
    """Allow only RS256 and locally selected published RSA keys."""
    now = time.time() if now is None else now
    try:
        parts = token.split('.')
        if len(parts) != 3 or len(token) > 32768:
            raise ValueError()
        header = strict_json(unb64(parts[0]).decode('utf-8'))
        claims = strict_json(unb64(parts[1]).decode('utf-8'))
        if header.get('alg') != 'RS256' or header.get('crit') or 'jku' in header or 'x5u' in header:
            raise ValueError()
        matches = [k for k in jwks['keys'] if k.get('kid') == header.get('kid') and
                   k.get('kty') == 'RSA' and k.get('use', 'sig') == 'sig' and k.get('alg', 'RS256') == 'RS256']
        if len(matches) != 1:
            raise ValueError()
        key = matches[0]
        modulus = int.from_bytes(unb64(key['n']), 'big')
        exponent = int.from_bytes(unb64(key['e']), 'big')
        if modulus.bit_length() < 2048:
            raise ValueError()
        rsa.RSAPublicNumbers(exponent, modulus).public_key().verify(unb64(parts[2]),
            (parts[0] + '.' + parts[1]).encode('ascii'), padding.PKCS1v15(), hashes.SHA256())
        audience = claims.get('aud')
        if isinstance(audience, list):
            if client_id not in audience or (len(audience) > 1 and claims.get('azp') != client_id):
                raise ValueError()
        elif audience != client_id:
            raise ValueError()
        if claims.get('iss') != ISSUER or type(claims.get('exp')) not in (int, float) or claims['exp'] <= now:
            raise ValueError()
        if type(claims.get('iat')) not in (int, float) or claims['iat'] > now + 60:
            raise ValueError()
        if 'nbf' in claims and (type(claims['nbf']) not in (int, float) or claims['nbf'] > now + 60):
            raise ValueError()
        if not isinstance(claims.get('sub'), str) or not claims['sub']:
            raise ValueError()
        if nonce is not None and claims.get('nonce') != nonce:
            raise ValueError()
        if subject is not None and claims['sub'] != subject:
            raise ValueError()
        return claims
    except Exception:
        raise ValueError('ID-token validation failed') from None

def token_set(value, now=None):
    now = time.time() if now is None else now
    if value.get('token_type', '').lower() != 'bearer' or not isinstance(value.get('scope'), str):
        raise ValueError('Invalid OAuth token response')
    scopes = set(value['scope'].split())
    if not SCOPES.issubset(scopes):
        raise ValueError('Required plan-use grant missing')
    for key in ('access_token', 'refresh_token'):
        if not isinstance(value.get(key), str) or not value[key] or any(c.isspace() for c in value[key]):
            raise ValueError('Incomplete token response')
    seconds = value.get('expires_in')
    if type(seconds) not in (int, float) or not 0 < seconds <= 86400:
        raise ValueError('Invalid token expiry')
    earliest = value.get('earliest_refresh_at', now)
    if isinstance(earliest, str):
        from datetime import datetime
        try:
            earliest = datetime.fromisoformat(earliest.replace('Z', '+00:00')).timestamp()
        except ValueError:
            raise ValueError('Unknown refresh time format') from None
    if type(earliest) not in (int, float) or earliest < 0:
        raise ValueError('Invalid refresh time')
    return {'access_token': value['access_token'], 'refresh_token': value['refresh_token'],
        'id_token': value.get('id_token'), 'scopes': sorted(scopes), 'token_type': 'Bearer',
        'saved_at': now, 'expires_at': now + seconds, 'earliest_refresh_at': earliest}

class OAuthClient:
    def __init__(self, store, transport):
        self.store = store
        self.transport = transport

    def prepare(self, redirect_uri, registration_id=None):
        parts = urllib.parse.urlsplit(redirect_uri)
        if parts.scheme != 'http' or parts.hostname != '127.0.0.1' or parts.path != '/auth/callback' or not parts.port or parts.query or parts.fragment:
            raise ValueError('Invalid loopback callback URI')
        with self.store.transaction():
            state = self.store.read()
            if state['host_id'] is None:
                state['host_id'] = 'urn:uuid:' + str(uuid.uuid4())
                self.store.write(state)
            registration = state['registrations'].get(registration_id) if registration_id else None
            if registration_id and registration is None:
                raise ValueError('Unknown account registration')
            return Pending(state['host_id'], redirect_uri,
                registration['client_id'] if registration else DYNAMIC,
                registration_id, registration['subject'] if registration else None,
                registration.get('tokens', {}).get('id_token') if registration else None)

    def discovery(self):
        data = json_reply(self.transport.request('GET', DISCOVERY))
        if data.get('issuer') != ISSUER:
            raise ValueError('Untrusted identity discovery')
        for key, method in (('jwks_uri', 'GET'), ('revocation_endpoint', 'POST')):
            self.transport.allow_discovered(data[key], method)
        return data

    def keys(self):
        discovery = self.discovery()
        return json_reply(self.transport.request('GET', discovery['jwks_uri']))

    def complete(self, pending, code, issued):
        # A callback-validated tuple is required; never exchange a reused code.
        if not pending.consumed or pending.exchanged or issued == DYNAMIC or pending.callback_result != (code, issued):
            raise ValueError('Validated callback required')
        pending.exchanged = True
        # The client was issued by the state-bound callback even when exchange
        # fails. Retain this INCOMPLETE mapping, never tokens or active identity.
        with self.store.transaction():
            state = self.store.read()
            if state['host_id'] != pending.host_id:
                raise ValueError('Host identity changed')
            if pending.registration_id is None:
                if any(r['client_id'] == issued for r in state['registrations'].values()):
                    raise ValueError('Issued registration exists; select it first')
                rid = str(uuid.uuid4())
                state['registrations'][rid] = {'client_id': issued, 'subject': None,
                    'label': 'ChatGPT registration ' + rid[:8], 'tokens': {}}
                self.store.write(state)
                pending.registration_id = rid
                pending.client_id = issued
        fields = {'grant_type': 'authorization_code', 'client_id': issued, 'code': code,
            'code_verifier': pending.verifier, 'redirect_uri': pending.redirect_uri, 'resource': RESOURCE}
        value = json_reply(form_request(self.transport, TOKEN, fields))
        tokens = token_set(value)
        claims = verify_id(value.get('id_token', ''), self.keys(), issued, pending.nonce, pending.subject)
        with self.store.transaction():
            state = self.store.read()
            if state['host_id'] != pending.host_id:
                raise ValueError('Host identity changed')
            rid = pending.registration_id
            existing = state['registrations'].get(rid)
            if not existing or existing['client_id'] != issued or existing['subject'] not in {None, claims['sub']}:
                raise ValueError('Registration changed during authorization')
            state['registrations'][rid] = {'client_id': issued, 'subject': claims['sub'],
                'label': 'ChatGPT registration ' + rid[:8], 'tokens': tokens}
            state['active'] = rid
            self.store.write(state)
        return rid

    def accounts(self):
        with self.store.transaction():
            state = self.store.read()
            return [(rid, entry['label']) for rid, entry in state['registrations'].items()]

    def select(self, registration_id):
        with self.store.transaction():
            state = self.store.read()
            if registration_id not in state['registrations']:
                raise ValueError('Unknown account')
            state['active'] = registration_id
            self.store.write(state)

    def access(self, registration_id=None):
        with self.store.transaction():
            state = self.store.read()
            rid = registration_id or state['active']
            entry = state['registrations'].get(rid)
            if not entry or not entry.get('tokens'):
                raise ValueError('Continue with ChatGPT required')
            tokens = entry['tokens']
            if entry.get('refresh_pending'):
                raise ValueError('Refresh completion unknown; reauthorize')
            if tokens['expires_at'] <= time.time() + 60:
                raise ValueError('Session renewal required; no automatic request')
            if not SCOPES.issubset(tokens['scopes']):
                raise ValueError('Plan-use permission missing')
            return tokens['access_token']

    def refresh(self, registration_id):
        # Serialize the complete rotating-token exchange across processes.
        with self.store.transaction():
            state = self.store.read()
            entry = state['registrations'][registration_id]
            old = entry.get('tokens')
            if not old or time.time() < old['earliest_refresh_at']:
                raise ValueError('Refresh not available yet')
            # Persist an in-flight marker BEFORE dispatch: uncertainty blocks reuse.
            if entry.get('refresh_pending'):
                raise ValueError('Prior refresh completion unknown; reauthorize')
            entry['refresh_pending'] = True
            self.store.write(state)
            value = json_reply(form_request(self.transport, TOKEN, {'grant_type': 'refresh_token',
                'client_id': entry['client_id'], 'refresh_token': old['refresh_token'], 'resource': RESOURCE}))
            replacement = token_set(value)
            if replacement['refresh_token'] == old['refresh_token']:
                raise ValueError('Refresh did not rotate')
            if value.get('id_token'):
                verify_id(value['id_token'], self.keys(), entry['client_id'], subject=entry['subject'])
            else:
                replacement['id_token'] = old['id_token']
            entry['tokens'] = replacement
            entry.pop('refresh_pending', None)
            self.store.write(state)

    def logout(self, registration_id):
        with self.store.transaction():
            state = self.store.read()
            entry = state['registrations'][registration_id]
            tokens = entry.get('tokens')
            entry['tokens'] = {}
            entry.pop('refresh_pending', None)
            if state['active'] == registration_id:
                state['active'] = None
            self.store.write(state)  # Stop local requests even if the process fails next.
            if not tokens:
                return 'local_signed_out_remote_unverified'
            try:
                endpoint = self.discovery()['revocation_endpoint']
                reply = form_request(self.transport, endpoint, {'token': tokens['refresh_token'],
                    'token_type_hint': 'refresh_token', 'client_id': entry['client_id']})
                if reply.status == 200 and not reply.body:
                    return 'local_signed_out_remote_revoked'
            except Exception:
                pass
            return 'local_signed_out_remote_unverified'
