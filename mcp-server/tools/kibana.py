"""Fixed Kibana 8.13 rule read for the Day 5 MCP server."""

import os
import stat

from detections.processing.connected_plan import KibanaHTTPS
from detections.processing.kibana_rule_reader import RESPONSE_FIELDS, KibanaRuleReader
from scripts.ci.validate import ValidationError, strict_json

from tools.keychain import READER, read_keychain_password
from tools.security import RULE_ID, SPACE, Fault, canonical_uuid, require, rule_projection

ORIGIN = 'https://127.0.0.1:5601'
MAX_PASSWORD_BYTES = 1024


class RuleHTTPS(KibanaHTTPS):
    response_limit = 256 * 1024


def read_password(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
                stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1, 'CREDENTIAL_UNAVAILABLE')
        raw = source.read(MAX_PASSWORD_BYTES + 1)
    require(0 < len(raw) <= MAX_PASSWORD_BYTES, 'CREDENTIAL_UNAVAILABLE')
    password = raw.decode('utf-8').removesuffix('\n')
    require(bool(password) and not any(character in password for character in '\r\n\0'),
            'CREDENTIAL_UNAVAILABLE')
    return password


class KibanaBackend:
    def __init__(self, ca_file, password_file, expected_uuid, *, keychain=False):
        require(canonical_uuid(expected_uuid) and keychain != bool(password_file), 'INVALID_LAUNCH_ARGUMENTS')
        transport = RuleHTTPS(ORIGIN, SPACE, ca_file)
        self._expected_uuid = expected_uuid
        self._password_file = password_file
        self._keychain = keychain
        self._authorized_password = None
        self._reader = KibanaRuleReader(ORIGIN, SPACE, self._get(transport), projection=self._project)

    def preauthorize_keychain(self):
        require(self._keychain, 'INVALID_LAUNCH_ARGUMENTS')
        self._authorized_password = read_keychain_password()

    def _get(self, transport):
        def get(path):
            try:
                password = self._authorized_password
                if password is None:
                    password = read_keychain_password() if self._keychain else read_password(self._password_file)
            except (OSError, UnicodeError):
                raise Fault('CREDENTIAL_UNAVAILABLE') from None
            try:
                return transport.read(path, READER, password)
            except ValidationError as error:
                code = {
                    'Kibana rule request blocked by HTTP 401': 'AUTHENTICATION_FAILED',
                    'Kibana rule request blocked by HTTP 403': 'AUTHORIZATION_FAILED',
                    'Kibana rule request blocked by HTTP 404': 'NOT_FOUND',
                    'Kibana TLS certificate or hostname verification failed': 'TLS_FAILURE',
                    'Kibana TLS handshake failed': 'TLS_FAILURE',
                    'Kibana HTTPS request timed out': 'BACKEND_TIMEOUT',
                    'Unsupported Kibana response media type': 'INVALID_RESPONSE',
                    'Kibana response exceeds size limit': 'INVALID_RESPONSE',
                }.get(str(error), 'BACKEND_FAILURE')
                raise Fault(code) from None
        return get

    def _project(self, body, rule_id):
        try:
            data = strict_json(body)
        except (ValueError, ValidationError, RecursionError):
            raise Fault('INVALID_RESPONSE') from None
        fields = ('rule_id', 'type', 'enabled', 'interval', 'severity', 'risk_score', 'revision')
        require(type(data) is dict and set(fields) | {'id', 'language'} <= data.keys() <= RESPONSE_FIELDS and
                data['rule_id'] == rule_id and data['id'] == self._expected_uuid and
                data['language'] == 'esql' and data.get('output_index', '') == '', 'INVALID_RESPONSE')
        return rule_projection({**{key: data[key] for key in fields}, 'uuid': data['id']})

    def rule(self):
        return self._reader.read(RULE_ID)

    def alerts(self, *_):
        raise Fault('BACKEND_UNAVAILABLE')
