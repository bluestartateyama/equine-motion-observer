"""Fresh observation schema: descriptive features, no performance scores."""
import json
import math
import uuid
from datetime import datetime, timezone

FEATURES = ('gait', 'posture', 'body_appearance', 'hindlimbs', 'coordination', 'vitality', 'sweat')
SCHEMA_VERSION = '1.0'

def object_schema(properties):
    return {'type': 'object', 'properties': properties, 'required': list(properties), 'additionalProperties': False}

NULL_TEXT = {'type': ['string', 'null']}
FEATURE_SCHEMA = object_schema({'description': NULL_TEXT,
    'confidence': {'type': ['number', 'null']},
    'status': {'type': 'string', 'enum': ['observed', 'unknown', 'unobservable']},
    'reason': NULL_TEXT})
EVIDENCE_SCHEMA = object_schema({'feature': {'type': 'string', 'enum': list(FEATURES)},
    'image_index': {'type': 'integer'}, 'frame_id': {'type': 'string'},
    'sha256': {'type': 'string'}, 'description': {'type': 'string'}})
OBSERVATION_SCHEMA = object_schema({'subject_id': {'type': 'string'},
    'features': object_schema({key: FEATURE_SCHEMA for key in FEATURES}),
    'evidence': {'type': 'array', 'items': EVIDENCE_SCHEMA}})

def strict_json(text):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ValueError('Duplicate JSON property')
            out[key] = value
        return out
    return json.loads(text, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite JSON')))

def exact_keys(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError('Schema properties mismatch')

def text_value(value, nullable=False, limit=2000):
    if value is None and nullable:
        return
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError('Invalid text value')

def validate(observation, image, subject_id):
    exact_keys(observation, ('subject_id', 'features', 'evidence'))
    text_value(subject_id, limit=100)
    if observation['subject_id'] != subject_id:
        raise ValueError('Subject identity mismatch')
    exact_keys(observation['features'], FEATURES)
    for key, value in observation['features'].items():
        exact_keys(value, ('description', 'confidence', 'status', 'reason'))
        if value['status'] not in {'observed', 'unknown', 'unobservable'}:
            raise ValueError('Unknown observation status')
        confidence = value['confidence']
        if confidence is not None and (type(confidence) not in (int, float)
                or not math.isfinite(confidence) or not 0 <= confidence <= 1):
            raise ValueError('Invalid confidence')
        text_value(value['description'], nullable=True)
        text_value(value['reason'], nullable=True)
        if value['status'] == 'observed':
            text_value(value['description'])
        elif value['description'] is not None or confidence is not None or value['reason'] is None:
            raise ValueError('Unavailable features require null values and a reason')
    evidence = observation['evidence']
    if not isinstance(evidence, list) or len(evidence) > 100:
        raise ValueError('Invalid evidence list')
    covered = set()
    for entry in evidence:
        exact_keys(entry, ('feature', 'image_index', 'frame_id', 'sha256', 'description'))
        if entry['feature'] not in FEATURES or type(entry['image_index']) is not int or entry['image_index'] != 0:
            raise ValueError('Invalid evidence index')
        if entry['frame_id'] != image.frame_id or entry['sha256'] != image.sha256:
            raise ValueError('Evidence image mismatch')
        text_value(entry['description'])
        if observation['features'][entry['feature']]['status'] != 'observed':
            raise ValueError('Evidence cannot assert an unavailable feature')
        covered.add(entry['feature'])
    if any(v['status'] == 'observed' and k not in covered for k, v in observation['features'].items()):
        raise ValueError('Observed feature lacks evidence')
    return observation

def empty_observation(subject_id):
    return {'subject_id': subject_id, 'features': {key: {
        'description': None, 'confidence': None, 'status': 'unobservable',
        'reason': 'Cannot establish this feature from the selected image.'} for key in FEATURES}, 'evidence': []}

def make_record(observation, image, origin='manual', metrics=None):
    validate(observation, image, observation['subject_id'])
    if origin not in {'manual', 'synthetic', 'siwc'}:
        raise ValueError('Invalid observation origin')
    return {'schema_version': SCHEMA_VERSION, 'result_id': str(uuid.uuid4()),
        'timestamp': datetime.now(timezone.utc).isoformat(), 'origin': origin,
        'image': image.manifest(), 'observation': observation,
        'human_review': 'required' if origin == 'siwc' else 'recorded_by_user',
        'metrics': metrics or {}, 'server_image_representation': 'unverified'}
