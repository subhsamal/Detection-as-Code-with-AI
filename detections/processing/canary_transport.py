"""Wire boundary for the fixed Day 4 canary. The deployment engine owns approval."""

from uuid import UUID

from detections.processing.canary_profile import CANARY_INTERVALS, CANARY_SPACE, CANARY_WRITER
from detections.processing.connected_plan import _KibanaHTTPSConnection
from detections.processing.kibana_rule_reader import rule_path
from scripts.ci.validate import require


class _CanaryHTTPS(_KibanaHTTPSConnection):
    def __init__(self, origin, ca_file, expected_uuid, password):
        require(isinstance(expected_uuid, str) and str(UUID(expected_uuid)) == expected_uuid,
                'Expected a canonical canary UUID')
        require(isinstance(password, str) and password, 'Missing canary writer password')
        self._read_path = rule_path(CANARY_SPACE, canary=True)
        self._patch_path = self._read_path.partition('?')[0]
        self._uuid = expected_uuid
        self._password = password
        super().__init__(origin, ca_file)

    def _exchange(self, method, path, body, *, authorize_write=False):
        if method == 'GET':
            require(path == self._read_path and body is None, 'Unsupported canary GET')
        else:
            require(method == 'PATCH' and path == self._patch_path, 'Unsupported canary route or method')
            require(authorize_write is True, 'Canary PATCH needs an approved journaled operation')
            require(isinstance(body, dict) and body.keys() == {'id', 'enabled', 'interval'} and
                    body['id'] == self._uuid and body['enabled'] is False and
                    body['interval'] in CANARY_INTERVALS, 'Unsupported canary PATCH body')
        return self._request(method, path, CANARY_WRITER, self._password, body)
