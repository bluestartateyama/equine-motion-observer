"""New synthetic fixtures only. External sockets and browsers are forbidden."""
import base64
import copy
import hashlib
import io
import json
import os
import socket
import tempfile
import threading
import time
import unittest
import urllib.parse
import uuid
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from PIL import Image
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from emo.auth import (DYNAMIC, SCOPES, OAuthClient, Pending, b64url, challenge,
                      token_set, verify_id)
from emo.images import LocalImage
from emo.observation import (FEATURES, OBSERVATION_SCHEMA, empty_observation,
                             make_record, strict_json, validate)
from emo.provider import DispatchLedger, MODEL, ResponsesProvider
from emo.sse import CompletionGuard, SSEParser, StreamRejected
from emo.storage import (CredentialStore, ResultStore, WindowsProtector,
                         atomic_write, file_lock)
from emo.transport import (DISCOVERY, ISSUER, MODELS, RESOURCE, RESPONSES, TOKEN,
                           HTTPSClient, Reply, TransportError, json_reply)

class SyntheticProtector:
    """Injectable fixture, never used by the application's live entrypoint."""
    def protect(self, raw):
        return b'fixture:' + base64.b64encode(raw)

    def unprotect(self, raw):
        if not raw.startswith(b'fixture:'):
            raise ValueError('Invalid fixture envelope')
        return base64.b64decode(raw[8:])

class SyntheticTransport:
    def __init__(self):
        self.calls = []
        self.reply_queue = []
        self.status = 200
        self.headers = {'Content-Type': 'text/event-stream', 'X-Request-ID': 'synthetic-request'}
        self.chunks = []
        self.stream_calls = 0

    def allow_discovered(self, url, method='GET'):
        HTTPSClient().allow_discovered(url, method)

    def request(self, method, url, headers=None, body=None):
        self.calls.append((method, url, headers, body))
        reply = self.reply_queue.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply

    @contextmanager
    def stream(self, url, headers, body):
        self.stream_calls += 1
        self.calls.append(('POST', url, headers, body))
        def iterate():
            for part in self.chunks:
                if isinstance(part, Exception):
                    raise part
                yield part
        yield self.status, self.headers, iterate()

def reply(value, status=200):
    return Reply(status, {'Content-Type': 'application/json'}, json.dumps(value).encode())

def event(value, event_name=None, event_id=None, ending='\n'):
    parts = []
    if event_name:
        parts.append('event: ' + event_name)
    if event_id:
        parts.append('id: ' + event_id)
    parts.append('data: ' + json.dumps(value, ensure_ascii=False))
    return (ending.join(parts) + ending + ending).encode('utf-8')

def completed(text, **changes):
    response = {'id': 'synthetic-response', 'model': MODEL, 'status': 'completed',
        'output': [{'type': 'message', 'role': 'assistant', 'status': 'completed',
                    'content': [{'type': 'output_text', 'text': text}]}],
        'usage': {'input_tokens': 10, 'output_tokens': 5, 'total_tokens': 15}}
    response.update(changes)
    return {'type': 'response.completed', 'response': response}

class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = cls.private_key.public_key().public_numbers()
        cls.jwks = {'keys': [{'kid': 'synthetic-key', 'kty': 'RSA', 'alg': 'RS256', 'use': 'sig',
            'n': b64url(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, 'big')),
            'e': b64url(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, 'big'))}]}

    def setUp(self):
        temp_root = Path(__file__).resolve().parents[1] / '.runtime/test-temp'
        temp_root.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix='emo-synthetic-', dir=temp_root)
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        image = Image.new('RGB', (80, 60), (30, 100, 140))
        image.save(self.directory / 'synthetic.png')
        image.save(self.directory / 'synthetic.jpg', quality=90)
        self.image = LocalImage.load(self.directory / 'synthetic.png')
        self.observation = empty_observation('synthetic-subject')
        self.transport = SyntheticTransport()
        self.ledger = DispatchLedger(self.directory / 'ledger')
        self.provider = ResponsesProvider(self.transport, self.ledger)
        self.store = CredentialStore(self.directory / 'auth', SyntheticProtector(), secure=False)
        self.auth = OAuthClient(self.store, self.transport)
        # None of these tests may contact external networks or open login pages.
        self.addCleanup(patch.stopall)
        patch('socket.create_connection', side_effect=AssertionError('External network forbidden')).start()
        patch('socket.socket.connect', side_effect=AssertionError('External network forbidden')).start()
        patch('socket.socket.connect_ex', side_effect=AssertionError('External network forbidden')).start()
        patch('webbrowser.open', side_effect=AssertionError('Browser authorization forbidden')).start()

    def jwt(self, client='oaiapp_synthetic', nonce='synthetic-nonce', subject='synthetic-subject', **changes):
        now = time.time()
        claims = {'iss': ISSUER, 'aud': client, 'sub': subject, 'nonce': nonce,
                  'iat': int(now) - 1, 'exp': int(now) + 1000}
        claims.update(changes)
        first = b64url(json.dumps({'alg': 'RS256', 'kid': 'synthetic-key'}).encode())
        second = b64url(json.dumps(claims).encode())
        unsigned = (first + '.' + second).encode()
        signature = self.private_key.sign(unsigned, padding.PKCS1v15(), hashes.SHA256())
        return unsigned.decode() + '.' + b64url(signature)

    def token(self, id_token=None, access='synthetic-access', refresh='synthetic-refresh', **changes):
        out = {'access_token': access, 'refresh_token': refresh, 'id_token': id_token,
            'token_type': 'Bearer', 'expires_in': 3600, 'scope': ' '.join(sorted(SCOPES)),
            'earliest_refresh_at': 0}
        out.update(changes)
        return out

    def discovery(self):
        return {'issuer': ISSUER, 'jwks_uri': ISSUER + '/synthetic-jwks',
                'revocation_endpoint': ISSUER + '/synthetic-revoke'}

    def register(self):
        pending = self.auth.prepare('http://127.0.0.1:15001/auth/callback')
        code, client = pending.callback(urllib.parse.urlencode({'state': pending.state,
            'code': 'synthetic-code', 'client_id': 'oaiapp_synthetic'}))
        self.transport.reply_queue += [reply(self.token(self.jwt(nonce=pending.nonce))),
            reply(self.discovery()), reply(self.jwks)]
        return self.auth.complete(pending, code, client)

    def catalog(self, access='synthetic-access'):
        self.transport.reply_queue.append(reply({'models': [{'slug': MODEL, 'visibility': 'list', 'display_name': 'Sol'}]}))
        self.provider.discover(access)

    def dispatch(self, text=None):
        text = json.dumps(self.observation, ensure_ascii=False) if text is None else text
        self.transport.chunks = [event(completed(text))]
        self.catalog()
        return self.provider.observe('synthetic-task', 'synthetic-access', self.image, 'synthetic-subject')

class ImageAndObservationTests(Base):
    def test_original_png_byte_identity(self):
        original = (self.directory / 'synthetic.png').read_bytes()
        self.assertEqual(self.image.raw, original)
        self.assertEqual(self.image.sha256, hashlib.sha256(original).hexdigest())
        self.assertEqual(base64.b64decode(self.image.data_uri().split(',')[1]), original)

    def test_jpeg_bytes_dimensions_and_format(self):
        image = LocalImage.load(self.directory / 'synthetic.jpg', 'local-frame-2')
        self.assertEqual((image.width, image.height, image.format), (80, 60, 'JPEG'))
        self.assertEqual(base64.b64decode(image.data_uri().split(',')[1]), image.raw)
        self.assertEqual(image.manifest()['frame_id'], 'local-frame-2')

    def test_preview_never_modifies_original(self):
        before = self.image.raw
        self.assertEqual(self.image.preview((20, 20)).size, (20, 15))
        self.assertEqual(self.image.raw, before)
        self.assertEqual(self.image.manifest()['client_processing'], 'none')

    def test_corrupt_image_rejected(self):
        p = self.directory / 'corrupt.png'
        p.write_bytes(b'not an image')
        with self.assertRaises(Exception):
            LocalImage.load(p)

    def test_other_format_rejected(self):
        p = self.directory / 'synthetic.gif'
        Image.new('RGB', (8, 8)).save(p)
        with self.assertRaises(ValueError):
            LocalImage.load(p)

    def test_animated_image_rejected(self):
        p = self.directory / 'animated.png'
        frames = [Image.new('RGB', (10, 10), c) for c in ['red', 'blue']]
        frames[0].save(p, save_all=True, append_images=frames[1:], duration=10)
        with self.assertRaises(ValueError):
            LocalImage.load(p)

    def test_size_limit(self):
        with patch('emo.images.MAX_BYTES', 8), self.assertRaises(ValueError):
            LocalImage.load(self.directory / 'synthetic.png')

    def test_tampered_manifest_image_rejected(self):
        from dataclasses import replace
        altered = replace(self.image, raw=b'changed')
        with self.assertRaises(ValueError):
            altered.data_uri()

    def test_null_is_preserved(self):
        result = validate(self.observation, self.image, 'synthetic-subject')
        self.assertIsNone(result['features']['gait']['description'])
        self.assertIsNone(result['features']['gait']['confidence'])

    def test_observed_feature_requires_visual_evidence(self):
        self.observation['features']['posture'] = {'description': 'Synthetic geometry only',
            'confidence': 0.8, 'status': 'observed', 'reason': None}
        with self.assertRaises(ValueError):
            validate(self.observation, self.image, 'synthetic-subject')
        self.observation['evidence'] = [{'feature': 'posture', 'image_index': 0,
            'frame_id': self.image.frame_id, 'sha256': self.image.sha256, 'description': 'Fixture check, not a horse.'}]
        validate(self.observation, self.image, 'synthetic-subject')

    def test_wrong_subject_not_self_report_pass(self):
        with self.assertRaises(ValueError):
            validate(self.observation, self.image, 'different-subject')

    def test_evidence_hash_frame_index_mismatch(self):
        self.test_observed_feature_requires_visual_evidence()
        for field, value in [('sha256', '0' * 64), ('frame_id', 'wrong'), ('image_index', 1), ('image_index', True)]:
            with self.subTest(field=field, value=value):
                altered = copy.deepcopy(self.observation)
                altered['evidence'][0][field] = value
                with self.assertRaises(ValueError):
                    validate(altered, self.image, 'synthetic-subject')

    def test_unknown_requires_null_and_reason(self):
        for field, value in [('description', 'invented'), ('confidence', 0.7), ('reason', None)]:
            with self.subTest(field=field):
                altered = copy.deepcopy(self.observation)
                altered['features']['gait'][field] = value
                with self.assertRaises(ValueError):
                    validate(altered, self.image, 'synthetic-subject')

    def test_confidence_range_type_nonfinite(self):
        for value in [True, -0.1, 1.1, float('nan'), float('inf'), '0.8']:
            with self.subTest(value=str(value)):
                altered = copy.deepcopy(self.observation)
                altered['features']['gait']['confidence'] = value
                with self.assertRaises(ValueError):
                    validate(altered, self.image, 'synthetic-subject')

    def test_extra_properties_rejected(self):
        for location in [self.observation, self.observation['features'], self.observation['features']['gait']]:
            location['unexpected'] = 1
            with self.assertRaises(ValueError):
                validate(self.observation, self.image, 'synthetic-subject')
            del location['unexpected']

    def test_strict_json_duplicate_nonfinite(self):
        for text in ['{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}']:
            with self.assertRaises(ValueError):
                strict_json(text)

    def test_result_save_roundtrip_no_overwrite(self):
        record = make_record(self.observation, self.image, 'synthetic')
        store = ResultStore(self.directory / 'results')
        path = store.save(record)
        self.assertEqual(json.loads(path.read_text('utf-8')), record)
        self.assertEqual(record['image']['sha256'], self.image.sha256)
        uuid.UUID(record['result_id'])
        self.assertEqual(record['schema_version'], '1.0')
        self.assertNotIn(str(self.directory), path.read_text('utf-8'))
        with self.assertRaises(ValueError):
            store.save(record)

    def test_result_id_cannot_escape_directory(self):
        record = make_record(self.observation, self.image)
        record['result_id'] = '../escape'
        with self.assertRaises(ValueError):
            ResultStore(self.directory / 'results').save(record)

class OAuthTests(Base):
    def test_pkce_rfc7636_vector(self):
        self.assertEqual(challenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'),
                         'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM')

    def test_dynamic_fields_fresh_secrets_stable_host(self):
        first = self.auth.prepare('http://127.0.0.1:15001/auth/callback')
        second = self.auth.prepare('http://127.0.0.1:15002/auth/callback')
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(first.url()).query)
        self.assertEqual(q['client_id'], [DYNAMIC])
        self.assertEqual(q['agent_name_hint'], ['Equine Motion Observer'])
        self.assertEqual(first.host_id, second.host_id)
        self.assertNotEqual(first.state, second.state)
        self.assertNotEqual(first.nonce, second.nonce)
        self.assertNotEqual(first.verifier, second.verifier)
        self.assertNotIn(first.verifier, first.url())
        self.assertNotIn(first.state, repr(first))

    def test_callback_uri_strict(self):
        for uri in ['http://localhost:15001/auth/callback', 'https://127.0.0.1:15001/auth/callback',
                    'http://127.0.0.1:15001/callback', 'http://127.0.0.1/auth/callback']:
            with self.assertRaises(ValueError):
                self.auth.prepare(uri)

    def test_state_error_and_duplicate_callback(self):
        pending = Pending('synthetic-host', 'http://127.0.0.1:15001/auth/callback')
        with self.assertRaises(ValueError):
            pending.callback('state=wrong&code=synthetic')
        with self.assertRaises(ValueError):
            pending.callback(urllib.parse.urlencode({'state': pending.state, 'error': 'access_denied'}))
        with self.assertRaises(ValueError):
            pending.callback(urllib.parse.urlencode({'state': pending.state, 'code': 'synthetic', 'client_id': 'oaiapp_synthetic'}))
        self.assertEqual(self.transport.calls, [])

    def test_callback_duplicate_parameters(self):
        pending = Pending('synthetic-host', 'http://127.0.0.1:15001/auth/callback')
        with self.assertRaises(ValueError):
            pending.callback(f'state={pending.state}&state={pending.state}&code=synthetic')

    def test_dynamic_entrypoint_not_persisted_as_issued(self):
        for client in ['', DYNAMIC]:
            pending = Pending('synthetic-host', 'http://127.0.0.1:15001/auth/callback')
            with self.assertRaises(ValueError):
                pending.callback(urllib.parse.urlencode({'state': pending.state, 'code': 'synthetic', 'client_id': client}))

    def test_signature_and_claim_validation(self):
        token = self.jwt()
        self.assertEqual(verify_id(token, self.jwks, 'oaiapp_synthetic', 'synthetic-nonce')['sub'], 'synthetic-subject')
        for changes in [{'iss': 'https://invalid.example'}, {'aud': 'wrong'}, {'exp': 1},
                        {'nonce': 'wrong'}, {'sub': ''}, {'iat': time.time() + 10000}, {'nbf': time.time() + 10000}]:
            with self.subTest(fields=list(changes)):
                with self.assertRaises(ValueError):
                    verify_id(self.jwt(**changes), self.jwks, 'oaiapp_synthetic', 'synthetic-nonce')
        other = copy.deepcopy(self.jwks)
        other['keys'][0]['n'] = self.jwks['keys'][0]['n'][::-1]
        with self.assertRaises(ValueError):
            verify_id(token, other, 'oaiapp_synthetic', 'synthetic-nonce')

    def test_jwt_alg_none_and_remote_key_url_rejected(self):
        original = self.jwt().split('.')
        for header in [{'alg': 'none', 'kid': 'synthetic-key'},
                       {'alg': 'RS256', 'kid': 'synthetic-key', 'jku': 'https://invalid.example/key'}]:
            token = '.'.join([b64url(json.dumps(header).encode()), original[1], original[2]])
            with self.assertRaises(ValueError):
                verify_id(token, self.jwks, 'oaiapp_synthetic')

    def test_token_grants_expiry_and_refresh_time(self):
        value = token_set(self.token())
        self.assertEqual(value['refresh_token'], 'synthetic-refresh')
        self.assertGreater(value['expires_at'], time.time())
        for changes in [{'scope': 'openid profile email'}, {'expires_in': -1}, {'expires_in': True},
                        {'token_type': 'Basic'}, {'earliest_refresh_at': 'invalid-time'}]:
            with self.assertRaises(ValueError):
                token_set(self.token(**changes))
        self.assertGreater(token_set(self.token(earliest_refresh_at='2026-10-09T00:00:00Z'))['earliest_refresh_at'], 0)

    def test_complete_registration_code_exchange_exact_uri(self):
        rid = self.register()
        state = self.store.read()
        self.assertEqual(state['active'], rid)
        self.assertEqual(state['registrations'][rid]['client_id'], 'oaiapp_synthetic')
        self.assertEqual(self.auth.access(), 'synthetic-access')
        method, url, headers, body = self.transport.calls[0]
        self.assertEqual((method, url), ('POST', TOKEN))
        q = urllib.parse.parse_qs(body.decode())
        self.assertEqual(q['redirect_uri'], ['http://127.0.0.1:15001/auth/callback'])
        self.assertEqual(q['resource'], [RESOURCE])
        self.assertNotIn('client_secret', q)

    def test_returning_registration_identity_and_client(self):
        rid = self.register()
        pending = self.auth.prepare('http://127.0.0.1:16001/auth/callback', rid)
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(pending.url()).query)
        self.assertNotIn('agent_name_hint', q)
        self.assertEqual(q['client_id'], ['oaiapp_synthetic'])
        self.assertIn('id_token_hint', q)
        code, client = pending.callback(urllib.parse.urlencode({'state': pending.state, 'code': 'new-synthetic-code'}))
        self.assertEqual(client, 'oaiapp_synthetic')
        self.transport.reply_queue += [reply(self.token(self.jwt(nonce=pending.nonce, subject='other-synthetic-subject'))),
            reply(self.discovery()), reply(self.jwks)]
        with self.assertRaises(ValueError):
            self.auth.complete(pending, code, client)
        self.assertEqual(self.store.read()['registrations'][rid]['subject'], 'synthetic-subject')

    def test_returning_client_mismatch(self):
        pending = Pending('synthetic-host', 'http://127.0.0.1:15001/auth/callback', 'oaiapp_synthetic')
        with self.assertRaises(ValueError):
            pending.callback(urllib.parse.urlencode({'state': pending.state, 'code': 'synthetic', 'client_id': 'oaiapp_other'}))

    def test_no_code_exchange_replay(self):
        rid = self.register()
        pending = self.auth.prepare('http://127.0.0.1:16001/auth/callback', rid)
        code, client = pending.callback(urllib.parse.urlencode({'state': pending.state, 'code': 'new-synthetic-code'}))
        self.transport.reply_queue.append(reply({'error': 'invalid_grant'}, 400))
        with self.assertRaises(TransportError):
            self.auth.complete(pending, code, client)
        count = len(self.transport.calls)
        with self.assertRaises(ValueError):
            self.auth.complete(pending, code, client)
        self.assertEqual(len(self.transport.calls), count)

    def test_refresh_rotates_atomically_and_omits_scope(self):
        rid = self.register()
        self.transport.reply_queue.append(reply(self.token(access='synthetic-next-access', refresh='synthetic-next-refresh')))
        self.auth.refresh(rid)
        self.assertEqual(self.auth.access(), 'synthetic-next-access')
        q = urllib.parse.parse_qs(self.transport.calls[-1][3].decode())
        self.assertNotIn('scope', q)
        self.assertEqual(q['client_id'], ['oaiapp_synthetic'])
        self.assertEqual(self.store.read()['registrations'][rid]['tokens']['refresh_token'], 'synthetic-next-refresh')

    def test_uncertain_refresh_blocks_reuse_and_access(self):
        rid = self.register()
        self.transport.reply_queue.append(TransportError('synthetic disconnect'))
        with self.assertRaises(TransportError):
            self.auth.refresh(rid)
        count = len(self.transport.calls)
        with self.assertRaises(ValueError):
            self.auth.refresh(rid)
        with self.assertRaises(ValueError):
            self.auth.access()
        self.assertEqual(len(self.transport.calls), count)

    def test_initial_invalid_grant_retains_issued_id_for_new_authorization(self):
        pending = self.auth.prepare('http://127.0.0.1:15001/auth/callback')
        code, client = pending.callback(urllib.parse.urlencode({'state': pending.state,
            'code': 'synthetic-code', 'client_id': 'oaiapp_incomplete'}))
        self.transport.reply_queue.append(reply({'error': 'invalid_grant'}, 400))
        with self.assertRaises(TransportError):
            self.auth.complete(pending, code, client)
        state = self.store.read()
        self.assertIsNone(state['active'])
        rid = next(iter(state['registrations']))
        self.assertEqual(state['registrations'][rid]['tokens'], {})
        fresh = self.auth.prepare('http://127.0.0.1:16001/auth/callback', rid)
        self.assertEqual(fresh.client_id, 'oaiapp_incomplete')
        self.assertNotEqual(fresh.state, pending.state)
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(fresh.url()).query)
        self.assertNotIn('agent_name_hint', q)

    def test_code_tuple_tampering_rejected_before_exchange(self):
        pending = self.auth.prepare('http://127.0.0.1:15001/auth/callback')
        pending.callback(urllib.parse.urlencode({'state': pending.state,
            'code': 'synthetic-code', 'client_id': 'oaiapp_synthetic'}))
        with self.assertRaises(ValueError):
            self.auth.complete(pending, 'changed-code', 'oaiapp_synthetic')
        self.assertEqual(self.transport.calls, [])

    def test_refresh_too_early_no_dispatch(self):
        rid = self.register()
        state = self.store.read()
        state['registrations'][rid]['tokens']['earliest_refresh_at'] = time.time() + 1000
        self.store.write(state)
        count = len(self.transport.calls)
        with self.assertRaises(ValueError):
            self.auth.refresh(rid)
        self.assertEqual(len(self.transport.calls), count)

    def test_logout_remote_success_retains_registration(self):
        rid = self.register()
        host = self.store.read()['host_id']
        self.transport.reply_queue += [reply(self.discovery()), Reply(200, {}, b'')]
        self.assertEqual(self.auth.logout(rid), 'local_signed_out_remote_revoked')
        state = self.store.read()
        self.assertEqual(state['host_id'], host)
        self.assertEqual(state['registrations'][rid]['tokens'], {})
        self.assertIsNone(state['active'])
        pending = self.auth.prepare('http://127.0.0.1:16001/auth/callback', rid)
        self.assertEqual(pending.client_id, 'oaiapp_synthetic')
        self.assertIsNone(pending.id_hint)

    def test_logout_network_unknown_clears_local_no_retry(self):
        rid = self.register()
        self.transport.reply_queue.append(TransportError('synthetic disconnect'))
        before = len(self.transport.calls)
        self.assertEqual(self.auth.logout(rid), 'local_signed_out_remote_unverified')
        self.assertEqual(len(self.transport.calls), before + 1)
        self.assertEqual(self.store.read()['registrations'][rid]['tokens'], {})

    def test_same_subject_separate_workspace_clients(self):
        rid = self.register()
        pending = self.auth.prepare('http://127.0.0.1:15002/auth/callback')
        code, client = pending.callback(urllib.parse.urlencode({'state': pending.state, 'code': 'synthetic-two', 'client_id': 'oaiapp_second'}))
        self.transport.reply_queue += [reply(self.token(self.jwt(client='oaiapp_second', nonce=pending.nonce))),
            reply(self.discovery()), reply(self.jwks)]
        second = self.auth.complete(pending, code, client)
        self.assertNotEqual(rid, second)
        self.assertEqual(len(self.auth.accounts()), 2)
        self.auth.select(rid)
        self.assertEqual(self.store.read()['active'], rid)

class StreamAndProviderTests(Base):
    def test_timing_progress_and_reasoning_usage(self):
        self.catalog()
        text = json.dumps(self.observation)
        finish = completed(text)
        finish['response']['usage']['output_tokens_details'] = {'reasoning_tokens': 3}
        self.transport.chunks = [event({'type': 'response.output_text.delta', 'delta': text}), event(finish)]
        stages = []
        _, metrics = self.provider.observe('timing-task', 'synthetic-access', self.image,
            'synthetic-subject', progress=stages.append)
        timing = metrics['timing']
        order = [timing[k] for k in ('first_sse_event_seconds', 'first_text_seconds',
            'response_completed_seconds', 'validation_completed_seconds')]
        self.assertEqual(order, sorted(order))
        self.assertGreaterEqual(timing['total_wall_seconds'], order[-1])
        self.assertEqual(metrics['reasoning_tokens'], 3)
        self.assertEqual(stages, ['dispatch_started', 'first_sse_event', 'first_text',
            'response_completed', 'validation_completed'])
        self.assertEqual(self.transport.stream_calls, 1)

    def test_stop_before_dispatch_has_no_post(self):
        self.catalog()
        cancel = threading.Event(); cancel.set()
        with self.assertRaises(StreamRejected):
            self.provider.observe('stop-task', 'synthetic-access', self.image,
                'synthetic-subject', cancel=cancel)
        self.assertEqual(self.transport.stream_calls, 0)
        self.assertEqual(self.ledger._read(), {})

    def test_stop_during_stream_blocks_adoption_and_resend(self):
        self.catalog()
        self.transport.chunks = [event({'type': 'response.output_text.delta', 'delta': '{}'}),
                                 event(completed(json.dumps(self.observation)))]
        cancel = threading.Event()
        def progress(stage):
            if stage == 'first_text': cancel.set()
        with self.assertRaises(StreamRejected):
            self.provider.observe('stop-task', 'synthetic-access', self.image,
                'synthetic-subject', progress=progress, cancel=cancel)
        row = self.ledger._read()['stop-task']
        self.assertEqual(row['state'], 'server_completion_unknown')
        self.assertFalse(row['metrics']['completion_seen'])
        with self.assertRaises(ValueError):
            self.provider.observe('stop-task', 'synthetic-access', self.image, 'synthetic-subject')
        self.assertEqual(self.transport.stream_calls, 1)

    def test_disconnect_after_completed_retains_known_server_state(self):
        self.catalog()
        self.transport.chunks = [event(completed(json.dumps(self.observation))), TransportError('synthetic disconnect')]
        with self.assertRaises(ValueError):
            self.provider.observe('completed-disconnect', 'synthetic-access', self.image, 'synthetic-subject')
        row = self.ledger._read()['completed-disconnect']
        self.assertEqual(row['state'], 'completed_invalid')
        self.assertTrue(row['metrics']['completion_seen'])
        self.assertIsNone(row['metrics']['timing']['validation_completed_seconds'])

    def test_reasoning_usage_invalid_rejected(self):
        for value in (True, -1, 6, '3'):
            guard = CompletionGuard(MODEL)
            finish = completed('synthetic')
            finish['response']['usage']['output_tokens_details'] = {'reasoning_tokens': value}
            with self.assertRaises(StreamRejected):
                guard.accept((None, json.dumps(finish), None))

    def test_completed_observation_metrics(self):
        observation, metrics = self.dispatch()
        self.assertEqual(observation, self.observation)
        self.assertEqual(metrics['usage']['total_tokens'], 15)
        self.assertGreaterEqual(metrics['wall_time_seconds'], 0)
        self.assertEqual(metrics['completion'], 'response.completed')
        self.assertEqual(self.ledger._read()['synthetic-task']['state'], 'completed')

    def test_request_preview_contract_original_image(self):
        for effort in ('medium', 'high'):
            body = self.provider.image_request(self.image, 'synthetic-subject', effort)
            self.assertFalse(body['store'])
            self.assertTrue(body['stream'])
            self.assertEqual(body['reasoning']['effort'], effort)
            self.assertIsInstance(body['input'], list)
            content = body['input'][0]['content'][1]
            self.assertEqual(content['detail'], 'high')
            self.assertEqual(base64.b64decode(content['image_url'].split(',')[1]), self.image.raw)
            self.assertTrue(body['text']['format']['strict'])
            self.assertEqual(body['text']['format']['schema'], OBSERVATION_SCHEMA)
            self.assertNotIn('max_output_tokens', body)
        with self.assertRaises(ValueError):
            self.provider.image_request(self.image, 'synthetic-subject', 'none')

    def test_no_catalog_no_dispatch(self):
        with self.assertRaises(ValueError):
            self.provider.observe('synthetic-task', 'synthetic-access', self.image, 'synthetic-subject')
        self.assertEqual(self.transport.stream_calls, 0)
        self.assertFalse(self.ledger.path.exists())

    def test_missing_or_hidden_model_no_fallback(self):
        for models in [[], [{'slug': MODEL, 'visibility': 'hidden'}], [{'slug': 'other-model', 'visibility': 'list'}]]:
            self.transport.reply_queue.append(reply({'models': models}))
            with self.assertRaises(ValueError):
                self.provider.discover('synthetic-access')
        self.assertEqual(self.transport.stream_calls, 0)

    def test_catalog_wrong_session_and_expiry(self):
        self.catalog()
        with self.assertRaises(ValueError):
            self.provider.observe('synthetic-task', 'synthetic-other-access', self.image, 'synthetic-subject')
        self.provider.catalog_time -= 301
        with self.assertRaises(ValueError):
            self.provider.observe('synthetic-task', 'synthetic-access', self.image, 'synthetic-subject')
        self.assertEqual(self.transport.stream_calls, 0)

    def test_http_errors_no_retry_or_fallback(self):
        for status in [400, 401, 403, 429, 500, 503]:
            with self.subTest(status=status):
                self.catalog()
                self.transport.status = status
                before = self.transport.stream_calls
                with self.assertRaises(StreamRejected):
                    self.provider.observe('http-' + str(status), 'synthetic-access', self.image, 'synthetic-subject')
                self.assertEqual(self.transport.stream_calls, before + 1)
                self.assertEqual(self.ledger._read()['http-' + str(status)]['state'], 'rejected')

    def test_sse_content_type_required(self):
        self.catalog()
        self.transport.headers = {'Content-Type': 'application/json'}
        with self.assertRaises(StreamRejected):
            self.provider.observe('synthetic-task', 'synthetic-access', self.image, 'synthetic-subject')

    def test_disconnect_blocks_restart_resend(self):
        self.catalog()
        self.transport.chunks = [event({'type': 'response.output_text.delta', 'delta': '{'}), TransportError('synthetic interruption')]
        with self.assertRaises(ValueError):
            self.provider.observe('synthetic-task', 'synthetic-access', self.image, 'synthetic-subject')
        new = ResponsesProvider(self.transport, DispatchLedger(self.directory / 'ledger'))
        self.provider = new
        self.catalog()
        before = self.transport.stream_calls
        with self.assertRaises(ValueError):
            new.observe('synthetic-task', 'synthetic-access', self.image, 'synthetic-subject')
        self.assertEqual(self.transport.stream_calls, before)
        self.assertEqual(self.ledger._read()['synthetic-task']['state'], 'server_completion_unknown')
        diagnostic = self.ledger._read()['synthetic-task']['metrics']
        self.assertGreaterEqual(diagnostic['wall_time_seconds'], 0)
        self.assertIsNone(diagnostic['usage'])
        self.assertFalse(diagnostic['completion_seen'])

    def test_partial_done_not_completed(self):
        guard = CompletionGuard(MODEL)
        with self.assertRaises(StreamRejected):
            guard.accept(('', '[DONE]', None))
        with self.assertRaises(StreamRejected):
            guard.finish()

    def test_failed_incomplete_refusal_terminal(self):
        for kind in ['response.failed', 'response.incomplete', 'response.refusal.delta', 'error']:
            self.catalog()
            self.transport.chunks = [event({'type': kind})]
            with self.assertRaises(StreamRejected):
                self.provider.observe(kind.replace('.', '_'), 'synthetic-access', self.image, 'synthetic-subject')

    def test_wrong_schema_or_evidence_not_accepted(self):
        for text in ['not JSON', '{}', json.dumps(dict(self.observation, subject_id='wrong'))]:
            self.catalog()
            self.transport.chunks = [event(completed(text))]
            task = 'invalid-' + str(uuid.uuid4())
            with self.assertRaises(ValueError):
                self.provider.observe(task, 'synthetic-access', self.image, 'synthetic-subject')
            self.assertNotEqual(self.ledger._read()[task]['state'], 'completed')
            row = self.ledger._read()[task]
            self.assertEqual(row['state'], 'completed_invalid')
            self.assertTrue(row['metrics']['completion_seen'])
            self.assertEqual(row['metrics']['usage']['total_tokens'], 15)

    def test_response_model_status_and_identity_mismatch(self):
        for changes in [{'model': 'other-model'}, {'status': 'incomplete'}, {'id': ''},
                        {'usage': {'input_tokens': 1, 'output_tokens': 2, 'total_tokens': 99}}]:
            guard = CompletionGuard(MODEL)
            with self.assertRaises(StreamRejected):
                guard.accept(('', json.dumps(completed('hello', **changes)), None))
        guard = CompletionGuard(MODEL)
        guard.accept(('', json.dumps({'type': 'response.created', 'response': {'id': 'different', 'model': MODEL}}), None))
        with self.assertRaises(StreamRejected):
            guard.accept(('', json.dumps(completed('hello')), None))

    def test_delta_completion_mismatch(self):
        guard = CompletionGuard(MODEL)
        guard.accept(('', json.dumps({'type': 'response.output_text.delta', 'delta': 'a'}), None))
        with self.assertRaises(StreamRejected):
            guard.accept(('', json.dumps(completed('b')), None))

    def test_reasoning_output_before_message_supported(self):
        guard = CompletionGuard(MODEL)
        guard.accept(('', json.dumps({'type': 'response.output_text.delta', 'output_index': 1, 'content_index': 0, 'delta': 'hello'}), None))
        value = completed('hello')
        value['response']['output'].insert(0, {'type': 'reasoning', 'summary': []})
        guard.accept(('', json.dumps(value), None))
        self.assertEqual(guard.finish()['text'], 'hello')

    def test_duplicate_and_out_of_order_events(self):
        value = {'type': 'response.output_text.delta', 'delta': 'a', 'sequence_number': 2}
        for duplicate_id in [True, False]:
            guard = CompletionGuard(MODEL)
            guard.accept(('', json.dumps(value), 'event-1'))
            with self.assertRaises(StreamRejected):
                guard.accept(('', json.dumps(value), 'event-1' if duplicate_id else 'event-2'))

    def test_multiple_output_messages_and_delta_slots(self):
        guard = CompletionGuard(MODEL)
        guard.accept(('', json.dumps({'type': 'response.output_text.delta', 'delta': 'a', 'output_index': 1}), None))
        with self.assertRaises(StreamRejected):
            guard.accept(('', json.dumps({'type': 'response.output_text.delta', 'delta': 'b', 'output_index': 2}), None))
        value = completed('hello')
        value['response']['output'] *= 2
        with self.assertRaises(StreamRejected):
            CompletionGuard(MODEL).accept(('', json.dumps(value), None))

    def test_incremental_utf8_all_byte_chunks_and_crlf(self):
        raw = event(completed('観察：合成画像'), event_name='response.completed', ending='\r\n')
        parser, guard = SSEParser(), CompletionGuard(MODEL)
        for byte in raw:
            for value in parser.feed(bytes([byte])):
                guard.accept(value)
        parser.finish()
        self.assertEqual(guard.finish()['text'], '観察：合成画像')

    def test_sse_multiline_comments_and_event_mismatch(self):
        parser = SSEParser()
        events = parser.feed(b': keepalive\n\nevent: response.completed\ndata: {\ndata: "type":"response.completed"}\n\n')
        self.assertEqual(len(events), 1)
        self.assertIn('\n', events[0][1])
        with self.assertRaises(StreamRejected):
            CompletionGuard(MODEL).accept(('wrong-name', json.dumps(completed('hello')), None))

    def test_truncated_invalid_utf8_and_stream_limit(self):
        parser = SSEParser()
        with self.assertRaises(StreamRejected):
            parser.feed(b'\xff')
        parser = SSEParser()
        parser.feed(b'data: {}\n')
        with self.assertRaises(StreamRejected):
            parser.finish()
        parser = SSEParser()
        with self.assertRaises(StreamRejected):
            parser.feed(b'x' * (4 * 1024 * 1024 + 1))

    def test_event_after_completion_rejected(self):
        guard = CompletionGuard(MODEL)
        guard.accept(('', json.dumps(completed('hello')), None))
        with self.assertRaises(StreamRejected):
            guard.accept(('', json.dumps(completed('hello')), None))

    def test_success_without_usage_is_explicit_null(self):
        guard = CompletionGuard(MODEL)
        guard.accept(('', json.dumps(completed('hello', usage=None)), None))
        self.assertIsNone(guard.finish()['usage'])

    def test_minimal_text_pilot_medium_one_dispatch(self):
        self.catalog()
        self.transport.chunks = [event(completed('Hello, world!'))]
        output, metrics = self.provider.text_pilot('text-pilot', 'synthetic-access')
        self.assertEqual(output, 'Hello, world!')
        body = json.loads(self.transport.calls[-1][3])
        self.assertEqual(body['reasoning']['effort'], 'medium')
        self.assertNotIn('text', body)
        self.assertEqual(self.transport.stream_calls, 1)
        with self.assertRaises(ValueError):
            self.provider.text_pilot('text-pilot', 'synthetic-access')
        self.assertEqual(self.transport.stream_calls, 1)

class SecurityAndUITests(Base):
    def test_local_stop_closes_receiver_without_another_request(self):
        client = HTTPSClient()
        class Receiver:
            closed = False
            def close(self): self.closed = True
        receiver = Receiver()
        client._active_stream = receiver
        with patch.object(client, '_request', side_effect=AssertionError('No request allowed')):
            client.stop_receiving()
        self.assertTrue(receiver.closed)

    def test_gui_stop_button_sets_cancel_and_closes_receiver(self):
        import tkinter as tk
        from emo.ui import ObserverApp
        root = tk.Tk(); root.withdraw()
        self.addCleanup(root.destroy)
        app = ObserverApp(root, data_directory=self.directory / 'ui-stop')
        closed = threading.Event()
        class Transport:
            def stop_receiving(self): closed.set()
        class Provider:
            transport = Transport()
        app.provider = Provider()
        app.busy = True
        app.stop_button.configure(state='normal')
        app.stop_observation()
        self.assertTrue(app.stop_event.is_set())
        self.assertTrue(closed.wait(1))
        self.assertEqual(str(app.stop_button['state']), 'disabled')
        self.assertIn('サーバー', app.status.get())

    def test_default_transport_no_network(self):
        client = HTTPSClient()
        with self.assertRaises(TransportError):
            client.request('GET', DISCOVERY)

    def test_fixed_endpoints_and_identity_endpoint_allowlist(self):
        client = HTTPSClient(enabled=True)
        for url in ['https://invalid.example/responses', RESOURCE + '/responses?token=synthetic',
                    'http://api.openai.com/v1/responses', 'https://auth.openai.com.evil.example/jwks']:
            with self.assertRaises(TransportError):
                client.request('POST', url)
        for url in ['https://invalid.example/jwks', 'http://auth.openai.com/jwks', ISSUER + '/jwks?x=1']:
            with self.assertRaises(TransportError):
                client.allow_discovered(url)

    def test_tls_validation_no_redirect_no_proxy(self):
        client = HTTPSClient()
        from emo.transport import NoRedirect
        with self.assertRaises(TransportError):
            NoRedirect().redirect_request(None, None, None, None, None, None)
        https = next(h for h in client.opener.handlers if h.__class__.__name__ == 'HTTPSHandler')
        self.assertTrue(https._context.check_hostname)
        import ssl
        self.assertEqual(https._context.verify_mode, ssl.CERT_REQUIRED)
        self.assertFalse(any(h.__class__.__name__ == 'ProxyHandler' and h.proxies for h in client.opener.handlers))

    def test_ledger_atomic_concurrent_reservation(self):
        successes, failures = [], []
        barrier = threading.Barrier(2)
        def reserve():
            barrier.wait()
            try:
                self.ledger.reserve('same-task', 'synthetic-fingerprint')
                successes.append(True)
            except (ValueError, OSError):
                failures.append(True)
        threads = [threading.Thread(target=reserve) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 1)
        self.assertEqual(self.ledger._read()['same-task']['state'], 'reserved')

    def test_ledger_corruption_fails_closed(self):
        self.ledger.directory.mkdir()
        self.ledger.path.write_text('{corrupt', 'utf-8')
        with self.assertRaises(ValueError):
            self.ledger.reserve('new-task', 'synthetic-fingerprint')

    def test_ledger_transition_no_terminal_reset(self):
        self.ledger.reserve('task', 'synthetic-fingerprint')
        self.ledger.transition('task', 'dispatched')
        self.ledger.transition('task', 'server_completion_unknown')
        with self.assertRaises(ValueError):
            self.ledger.transition('task', 'dispatched')
        with self.assertRaises(ValueError):
            self.ledger.reserve('task', 'synthetic-fingerprint')

    def test_credential_transaction_conflict(self):
        with self.store.transaction():
            with self.assertRaises(OSError):
                with self.store.transaction():
                    pass

    def test_credential_corruption_not_reset(self):
        self.store.path.write_bytes(b'corrupt')
        with self.assertRaises(RuntimeError):
            self.store.read()
        self.assertEqual(self.store.path.read_bytes(), b'corrupt')

    @unittest.skipUnless(os.name == 'nt', 'Windows security test')
    def test_dpapi_and_owner_acl_synthetic_roundtrip(self):
        protected = CredentialStore(self.directory / 'windows-auth')
        data = {'host_id': 'synthetic-host', 'active': None, 'registrations': {}}
        with protected.transaction():
            protected.write(data)
            self.assertEqual(protected.read(), data)
        self.assertNotIn(b'synthetic-host', protected.path.read_bytes())
        raw = WindowsProtector().protect(b'synthetic-not-a-token')
        self.assertEqual(WindowsProtector().unprotect(raw), b'synthetic-not-a-token')
        import subprocess
        acl = subprocess.run(['icacls', str(protected.directory)], capture_output=True, text=True, check=True).stdout
        self.assertNotIn('(I)', acl)
        self.assertNotIn('Everyone', acl)
        self.assertNotIn('BUILTIN', acl)

    def test_cloud_default_credentials_rejected(self):
        from emo.storage import local_root
        with patch.dict(os.environ, {'LOCALAPPDATA': str(self.directory / 'OneDrive/Local')}):
            with self.assertRaises(RuntimeError):
                local_root()

    def test_ledger_diagnostic_does_not_accept_tokens(self):
        self.ledger.reserve('safe-diagnostic', 'synthetic-fingerprint')
        with self.assertRaises(ValueError):
            self.ledger.transition('safe-diagnostic', 'dispatched', {'access_token': 'synthetic-access'})

    def test_callback_unicode_state_is_safely_rejected(self):
        pending = Pending('synthetic-host', 'http://127.0.0.1:15001/auth/callback')
        with self.assertRaises(ValueError):
            pending.callback('state=' + urllib.parse.quote('異なる値'))

    def test_no_environment_api_key_or_cookie_access(self):
        import ast
        source = Path(__file__).resolve().parents[1] / 'src/emo'
        for path in source.glob('*.py'):
            tree = ast.parse(path.read_text('utf-8'))
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    self.assertNotIn(node.value, {'OPENAI_API_KEY', 'auth.json', 'Cookie', 'api_key'})

    def test_gui_offline_select_preview_record_json(self):
        import tkinter as tk
        from emo.ui import ObserverApp
        root = tk.Tk()
        root.withdraw()
        self.addCleanup(root.destroy)
        app = ObserverApp(root, data_directory=self.directory / 'ui-results')
        app.load_image(self.directory / 'synthetic.png')
        root.update_idletasks()
        self.assertIsNotNone(app.preview.cget('image'))
        self.assertEqual(str(app.ai_button.cget('state')), 'disabled')
        self.assertIsNone(app.auth)
        saved = json.loads(app.save_record().read_text('utf-8'))
        self.assertEqual(saved['observation']['subject_id'], 'subject-1')
        self.assertIsNone(saved['observation']['features']['gait']['confidence'])
        app.frame.set('changed-frame')
        with self.assertRaises(ValueError):
            app.save_record()

    def test_gui_ai_requires_human_review_and_subject_binding(self):
        import tkinter as tk
        from emo.ui import ObserverApp
        root = tk.Tk()
        root.withdraw()
        self.addCleanup(root.destroy)
        app = ObserverApp(root, data_directory=self.directory / 'ui-results')
        app.load_image(self.directory / 'synthetic.png')
        app.origin = 'siwc'
        app.ai_binding = (app.subject.get(), app.image.sha256)
        with self.assertRaises(ValueError):
            app.save_record()
        app.review.set(True)
        path = app.save_record()
        self.assertEqual(json.loads(path.read_text('utf-8'))['human_review'], 'reviewed_by_user')
        app.subject.set('different-subject')
        with self.assertRaises(ValueError):
            app.save_record()

    def test_cross_process_lock_blocks_rotating_token_race(self):
        import subprocess
        import sys
        lock = self.directory / 'cross-process.lock'
        code = ('import sys; from emo.storage import file_lock; '
                'context=file_lock(sys.argv[1]); '
                '\ntry: context.__enter__()\nexcept OSError: sys.exit(7)\n'
                'context.__exit__(None,None,None)')
        env = dict(os.environ)
        env['PYTHONPATH'] = str(Path(__file__).resolve().parents[1] / 'src')
        args = [sys.executable, '-B', '-c', code, str(lock)]
        with file_lock(lock):
            self.assertEqual(subprocess.run(args, env=env, capture_output=True).returncode, 7)
        self.assertEqual(subprocess.run(args, env=env, capture_output=True).returncode, 0)

if __name__ == '__main__':
    unittest.main()
