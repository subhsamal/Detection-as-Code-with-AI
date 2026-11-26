"""Fixed-scope MCP contracts and synthetic backend."""

from base64 import urlsafe_b64decode, urlsafe_b64encode
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import math
import re
import secrets
from time import monotonic
from uuid import UUID

SPACE = 'default'
RULE_ID = 'P1-PS-001'
MAX_OUTPUT = 16 * 1024
CAP = 200
EXPIRY = 300
SEVERITIES = ('low', 'medium', 'high', 'critical')
STATUSES = ('open', 'acknowledged', 'closed')
UTC_PATTERN = r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$'
RULE_TOOL = 'get_detection_rule'
ALERT_TOOL = 'list_detection_alerts'
SCOPE = {'space': {'type': 'string', 'const': SPACE}, 'rule_id': {'type': 'string', 'const': RULE_ID}}
SCHEMAS = {
    RULE_TOOL: {'type': 'object', 'properties': SCOPE, 'required': list(SCOPE), 'additionalProperties': False},
    ALERT_TOOL: {
        'type': 'object',
        'properties': {**SCOPE, 'start': {'type': 'string', 'pattern': UTC_PATTERN},
                       'end': {'type': 'string', 'pattern': UTC_PATTERN},
                       'limit': {'type': 'integer', 'minimum': 1, 'maximum': 50, 'default': 20},
                       'cursor': {'type': 'string', 'minLength': 1, 'maxLength': 1024}},
        'required': [*SCOPE, 'start', 'end'], 'additionalProperties': False,
    },
}


def object_schema(properties):
    return {'type': 'object', 'properties': properties, 'required': list(properties),
            'additionalProperties': False}


PRIORITY_SCHEMA = {
    'severity': {'type': 'string', 'enum': list(SEVERITIES)},
    'risk_score': {'type': 'number', 'minimum': 0, 'maximum': 100},
}
OUTPUT_SCHEMAS = {
    RULE_TOOL: object_schema({
        **SCOPE, 'uuid': {'type': 'string', 'format': 'uuid'}, 'type': {'const': 'esql'},
        'enabled': {'type': 'boolean'}, 'revision': {'type': 'integer', 'minimum': 0, 'maximum': 2**53 - 1},
        'interval': {'type': 'string', 'pattern': r'^[1-9][0-9]{0,5}[smh]$'}, **PRIORITY_SCHEMA,
    }),
    ALERT_TOOL: object_schema({
        'alerts': {'type': 'array', 'maxItems': 50, 'items': object_schema({
            'alert_id': {'type': 'string', 'pattern': (
                r'^(?:[0-9a-f]{64}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})$'
            )},
            'timestamp': {'type': 'string', 'pattern': UTC_PATTERN},
            'rule_id': SCOPE['rule_id'],
            'workflow_status': {'type': 'string', 'enum': list(STATUSES)},
            **PRIORITY_SCHEMA,
        })},
        'next_cursor': {'type': ['string', 'null'], 'maxLength': 1024},
        'capped': {'type': 'boolean'},
    }),
}


class Fault(Exception):
    """Controlled error code."""


def require(condition, code):
    if not condition:
        raise Fault(code)


def compact(value):
    return json.dumps(value, allow_nan=False, separators=(',', ':'), sort_keys=True).encode()


def utc(value, code):
    require(type(value) is str and len(value) <= 27 and re.fullmatch(UTC_PATTERN, value), code)
    try:
        return datetime.fromisoformat(value[:-1] + '+00:00')
    except ValueError:
        raise Fault(code) from None


def stamp(value):
    return value.isoformat(timespec='microseconds').replace('+00:00', 'Z')


def canonical_uuid(value):
    try:
        return type(value) is str and len(value) == 36 and str(UUID(value)) == value
    except ValueError:
        return False


def validate(name, args):
    require(name in SCHEMAS, 'UNKNOWN_TOOL')
    schema = SCHEMAS[name]
    require(type(args) is dict and set(schema['required']) <= args.keys() <= schema['properties'].keys(),
            'INVALID_INPUT')
    require(all(type(args[key]) is str for key in SCOPE), 'INVALID_INPUT')
    require(args['space'] == SPACE and args['rule_id'] == RULE_ID, 'DENIED_SCOPE')
    if name == RULE_TOOL:
        return None
    start, end = (utc(args[key], 'INVALID_INPUT') for key in ('start', 'end'))
    limit = args.get('limit', 20)
    require(timedelta(0) < end - start <= timedelta(hours=24) and type(limit) is int and 1 <= limit <= 50,
            'INVALID_INPUT')
    if 'cursor' in args:
        cursor = args['cursor']
        require(type(cursor) is str and 0 < len(cursor) <= 1024, 'INVALID_CURSOR')
    return start, end, limit


def priority(data):
    score = data['risk_score']
    require(data['severity'] in SEVERITIES and type(score) in (int, float) and
            0 <= score <= 100 and math.isfinite(score), 'INVALID_RESPONSE')
    return {'severity': data['severity'], 'risk_score': score}


def rule_projection(data):
    require(type(data) is dict and data['rule_id'] == RULE_ID and canonical_uuid(data['uuid']) and
            data['type'] == 'esql' and type(data['enabled']) is bool and type(data['revision']) is int and
            0 <= data['revision'] <= 2**53 - 1 and type(data['interval']) is str and
            re.fullmatch(r'[1-9][0-9]{0,5}[smh]', data['interval']), 'INVALID_RESPONSE')
    fields = ('rule_id', 'uuid', 'type', 'enabled', 'revision', 'interval')
    return {'space': SPACE, **{key: data[key] for key in fields}, **priority(data)}


def alert_projection(data, start, end):
    timestamp = utc(data['timestamp'], 'INVALID_RESPONSE')
    alert_id = data['alert_id']
    require(start <= timestamp < end and type(alert_id) is str and
            (canonical_uuid(alert_id) or (len(alert_id) == 64 and re.fullmatch(r'[0-9a-f]{64}', alert_id))) and
            data['rule_id'] == RULE_ID and data['workflow_status'] in STATUSES, 'INVALID_RESPONSE')
    return {'alert_id': alert_id, 'timestamp': stamp(timestamp), 'rule_id': RULE_ID,
            'workflow_status': data['workflow_status'], **priority(data)}


class FakeBackend:
    """Deterministic synthetic fixtures, with no transport or credential handling."""

    def rule(self):
        return {'rule_id': RULE_ID, 'uuid': '1eaa1a10-79a5-4cf4-89dc-21292bd17401',
                'type': 'esql', 'enabled': False, 'revision': 1, 'interval': '5m',
                'severity': 'medium', 'risk_score': 47}

    def alerts(self, start, end, after, size):
        fixture_time = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
        if not start <= fixture_time < end:
            return []
        timestamp = stamp(fixture_time)
        rows = []
        for number in range(229, -1, -1):
            alert_id = f'{number:064x}'
            if after is not None and (timestamp, alert_id) >= after:
                continue
            rows.append({'alert_id': alert_id, 'timestamp': timestamp, 'rule_id': RULE_ID,
                         'severity': 'medium', 'risk_score': 47, 'workflow_status': 'open'})
            if len(rows) == size:
                break
        return rows


def encode(data):
    return urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


class ReadTools:
    def __init__(self, backend, *, clock=monotonic):
        self.backend = backend
        self.clock = clock
        self._key = secrets.token_bytes(32)

    def _open_cursor(self, token, scope):
        require(re.fullmatch(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', token), 'INVALID_CURSOR')
        payload, signature = token.split('.')
        expected = encode(hmac.digest(self._key, payload.encode(), hashlib.sha256))
        require(hmac.compare_digest(signature, expected), 'INVALID_CURSOR')
        state = json.loads(urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
        require(state['scope'] == scope and self.clock() < state['expires'], 'INVALID_CURSOR')
        return tuple(state['after']), state['remaining'], state['expires']

    def _cursor(self, scope, after, remaining, expires):
        payload = encode(compact({'scope': scope, 'after': after, 'remaining': remaining, 'expires': expires}))
        return payload + '.' + encode(hmac.digest(self._key, payload.encode(), hashlib.sha256))

    def read(self, name, arguments, bounds):
        if name == RULE_TOOL:
            data = self.backend.rule()
            require(data is not None, 'NOT_FOUND')
            return rule_projection(data)
        start, end, limit = bounds
        scope = [SPACE, RULE_ID, arguments['start'], arguments['end'], limit]
        after, remaining, expires = None, CAP, self.clock() + EXPIRY
        if 'cursor' in arguments:
            after, remaining, expires = self._open_cursor(arguments['cursor'], scope)
        count = min(limit, remaining)
        data = self.backend.alerts(start, end, after, count + 1)
        require(type(data) is list and len(data) <= count + 1, 'INVALID_RESPONSE')
        rows = [alert_projection(row, start, end) for row in data]
        keys = [(row['timestamp'], row['alert_id']) for row in rows]
        require(all(a > b for a, b in zip(keys, keys[1:])) and
                (not keys or after is None or keys[0] < after) and
                len({row['alert_id'] for row in rows}) == len(rows), 'INVALID_RESPONSE')
        more = len(rows) > count
        next_cursor = self._cursor(scope, keys[count - 1], remaining - count, expires) if more and count < remaining else None
        return {'alerts': rows[:count], 'next_cursor': next_cursor, 'capped': more and count == remaining}
