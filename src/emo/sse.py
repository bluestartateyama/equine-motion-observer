"""Incremental UTF-8 SSE and a fail-closed Responses lifecycle guard."""
import codecs
import re
from .observation import strict_json

class StreamRejected(ValueError):
    def __init__(self, state):
        self.state = state
        super().__init__(state)

class SSEParser:
    def __init__(self):
        self.decoder = codecs.getincrementaldecoder('utf-8')('strict')
        self.buffer = ''
        self.lines = []
        self.total = 0
        self.pending_cr = False

    def feed(self, raw):
        self.total += len(raw)
        if self.total > 4 * 1024 * 1024:
            raise StreamRejected('stream_limit')
        try:
            text = self.decoder.decode(raw)
        except UnicodeError:
            raise StreamRejected('invalid_utf8') from None
        # Normalize CRLF even when the pair crosses chunks.
        if self.pending_cr and text.startswith('\n'):
            text = text[1:]
        self.pending_cr = text.endswith('\r') if text else self.pending_cr
        self.buffer += text.replace('\r\n', '\n').replace('\r', '\n')
        events = []
        while '\n' in self.buffer:
            line, self.buffer = self.buffer.split('\n', 1)
            if line:
                self.lines.append(line)
            else:
                event = self._event()
                self.lines.clear()
                if event is not None:
                    events.append(event)
        if len(self.buffer) > 1024 * 1024 or sum(map(len, self.lines)) > 1024 * 1024:
            raise StreamRejected('event_limit')
        return events

    def _event(self):
        data, event_type, event_id = [], '', None
        for line in self.lines:
            if line.startswith(':'):
                continue
            key, _, value = line.partition(':')
            if value.startswith(' '):
                value = value[1:]
            if key == 'data':
                data.append(value)
            elif key == 'event':
                event_type = value
            elif key == 'id':
                event_id = value
        if not data:
            return None
        return event_type, '\n'.join(data), event_id

    def finish(self):
        try:
            tail = self.decoder.decode(b'', final=True)
        except UnicodeError:
            raise StreamRejected('invalid_utf8') from None
        if tail or self.buffer or self.lines:
            raise StreamRejected('truncated_sse')

class CompletionGuard:
    def __init__(self, model):
        self.model = model
        self.response_id = None
        self.completed = None
        self.delta = []
        self.text_slot = None
        self.ids = set()
        self.sequences = set()
        self.last_sequence = -1

    def accept(self, event):
        event_name, data, event_id = event
        if data == '[DONE]':
            if self.completed is None:
                raise StreamRejected('done_without_completion')
            return
        if self.completed is not None:
            raise StreamRejected('event_after_completion')
        if event_id is not None:
            if event_id in self.ids:
                raise StreamRejected('duplicate_event')
            self.ids.add(event_id)
        try:
            value = strict_json(data)
        except (ValueError, TypeError):
            raise StreamRejected('event_json_invalid') from None
        if not isinstance(value, dict) or not isinstance(value.get('type'), str):
            raise StreamRejected('event_type_missing')
        kind = value['type']
        if event_name and event_name != kind:
            raise StreamRejected('event_type_mismatch')
        sequence = value.get('sequence_number')
        if sequence is not None:
            if type(sequence) is not int or sequence <= self.last_sequence:
                raise StreamRejected('sequence_mismatch')
            self.sequences.add(sequence)
            self.last_sequence = sequence
        if kind in {'response.failed', 'response.incomplete', 'error', 'response.error'}:
            raise StreamRejected(kind.replace('.', '_'))
        if 'refusal' in kind:
            raise StreamRejected('response_refused')
        response = value.get('response')
        if isinstance(response, dict):
            rid = response.get('id')
            if not isinstance(rid, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,200}', rid):
                raise StreamRejected('response_id_missing')
            if self.response_id and self.response_id != rid:
                raise StreamRejected('response_id_mismatch')
            self.response_id = rid
            if response.get('model', self.model) != self.model:
                raise StreamRejected('response_model_mismatch')
        if kind == 'response.output_text.delta':
            if not isinstance(value.get('delta'), str):
                raise StreamRejected('invalid_delta')
            # The application's schema expects exactly one text output.
            slot = (value.get('output_index', 0), value.get('content_index', 0))
            if any(type(i) is not int or i < 0 for i in slot):
                raise StreamRejected('invalid_output_index')
            if self.text_slot is not None and self.text_slot != slot:
                raise StreamRejected('multiple_outputs')
            self.text_slot = slot
            self.delta.append(value['delta'])
        if kind == 'response.completed':
            if not isinstance(response, dict) or response.get('status') != 'completed':
                raise StreamRejected('completion_status_invalid')
            if response.get('model') != self.model or response.get('error') or response.get('incomplete_details'):
                raise StreamRejected('completion_metadata_invalid')
            output = response.get('output')
            if not isinstance(output, list):
                raise StreamRejected('completion_output_invalid')
            texts = []
            for item in output:
                if not isinstance(item, dict):
                    raise StreamRejected('completion_output_invalid')
                if item.get('type') == 'reasoning':
                    continue
                if item.get('type') != 'message' or item.get('role') != 'assistant' or item.get('status') != 'completed':
                    raise StreamRejected('completion_message_invalid')
                for content in item.get('content', []):
                    if content.get('type') == 'refusal':
                        raise StreamRejected('response_refused')
                    if content.get('type') != 'output_text' or not isinstance(content.get('text'), str):
                        raise StreamRejected('completion_content_invalid')
                    texts.append(content['text'])
            if len(texts) != 1 or not texts[0]:
                raise StreamRejected('completion_text_missing')
            if self.delta and ''.join(self.delta) != texts[0]:
                raise StreamRejected('delta_completion_mismatch')
            usage = response.get('usage')
            if usage is not None:
                if not isinstance(usage, dict):
                    raise StreamRejected('usage_invalid')
                for key in ('input_tokens', 'output_tokens', 'total_tokens'):
                    if type(usage.get(key)) is not int or usage[key] < 0:
                        raise StreamRejected('usage_invalid')
                if usage['input_tokens'] + usage['output_tokens'] != usage['total_tokens']:
                    raise StreamRejected('usage_inconsistent')
                details = usage.get('output_tokens_details')
                if details is not None:
                    if not isinstance(details, dict):
                        raise StreamRejected('usage_invalid')
                    reasoning = details.get('reasoning_tokens')
                    if reasoning is not None and (type(reasoning) is not int or not 0 <= reasoning <= usage['output_tokens']):
                        raise StreamRejected('usage_invalid')
            self.completed = {'text': texts[0], 'usage': usage, 'response_id': self.response_id}

    def finish(self):
        if self.completed is None:
            raise StreamRejected('server_completion_unknown')
        return self.completed
