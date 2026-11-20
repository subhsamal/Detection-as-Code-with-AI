"""Local-lab API transport with exact mutation allowlists and no secret output."""
import base64
import json
from pathlib import Path
import ssl
import urllib.error
import urllib.request

RULE = 'P1-PS-001'
INDEX = 'logs-p1-powershell-synthetic'
ALERTS = '.alerts-security.alerts-default'
ROOT = Path(__file__).resolve().parents[2]


class Stop(RuntimeError):
    """Sanitized stop reason suitable for recording."""


def authorize(service, path, method, body, admin, writes):
    """Validate operation BEFORE loading credentials or opening a connection."""
    reads = {
        'kb': {'/api/detection_engine/rules?rule_id=' + RULE,
               '/api/security/role/p1_detection_operator', '/api/status'},
        'es': {'/_cluster/health', '/_cat/shards?format=json&h=index,prirep,state',
               '/_security/role/p1_detection_operator',
               '/_security/api_key?username=p1_detection_operator&with_limited_by=true&active_only=true',
               '/' + INDEX + '/_count', '/' + INDEX + '/_mapping', '/' + INDEX + '/_settings?flat_settings=true'},
    }
    if method == 'GET' and (path in reads.get(service, set())
                            or service == 'kb' and path.startswith('/api/alerting/rule/')
                            and len(path.removeprefix('/api/alerting/rule/')) == 36
                            and all(c in '0123456789abcdef-' for c in path.removeprefix('/api/alerting/rule/'))):
        return
    if service == 'es' and method == 'POST' and path in {
            '/_query', '/' + INDEX + '/_search', '/' + ALERTS + '/_search',
            '/.kibana-event-log-*/_search'}:
        return
    if service == 'kb' and method == 'PATCH' and path == '/api/detection_engine/rules':
        if (not admin and isinstance(body, dict) and set(body) == {'rule_id', 'enabled'}
                and body['rule_id'] == RULE and type(body['enabled']) is bool
                and ('enable' if body['enabled'] else 'disable') in writes):
            return
    if service == 'es' and method == 'POST' and path == '/' + INDEX + '/_bulk':
        if not admin or 'ingest' not in writes or not isinstance(body, str):
            raise Stop('Create-only ingestion is not authorized')
        try:
            lines = [json.loads(line) for line in body.splitlines()]
            if len(lines) != 58:
                raise ValueError()
            ids = []
            for i in range(0, len(lines), 2):
                operation = lines[i]
                if (not isinstance(operation, dict) or set(operation) != {'create'}
                        or not isinstance(operation['create'], dict) or set(operation['create']) != {'_id'}
                        or not isinstance(operation['create']['_id'], str)
                        or not operation['create']['_id'] or not isinstance(lines[i+1], dict)
                        or '@timestamp' not in lines[i+1]):
                    raise ValueError()
                ids.append(operation['create']['_id'])
            if len(set(ids)) != 29:
                raise ValueError()
        except (ValueError, TypeError, KeyError):
            raise Stop('Bulk must contain exactly 29 unique create-only operations') from None
        return
    raise Stop('API operation outside the reviewed allowlist')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Stop('Redirect refused')


class Client:
    def __init__(self, *, writes=()):
        self.writes = frozenset(writes)
        self._cfg = None

    def call(self, service, path, body=None, *, admin=False, method=None):
        method = method or ('POST' if body is not None else 'GET')
        authorize(service, path, method, body, admin, self.writes)
        if self._cfg is None:
            secret_file = ROOT / 'infra/.env'
            if secret_file.stat().st_mode & 0o077:
                raise Stop('Credential file permissions must be restricted')
            self._cfg = {}
            for line in secret_file.read_text().splitlines():
                if '=' in line and not line.lstrip().startswith('#'):
                    key, value = line.split('=', 1)
                    self._cfg[key.strip()] = value.strip().strip('\"\'')
        try:
            cfg = self._cfg
            port = cfg['ES_PORT' if service == 'es' else 'KIBANA_PORT']
            if not port.isdecimal() or not 0 < int(port) < 65536:
                raise Stop('Invalid local service port')
            base = 'https://127.0.0.1:' + port
            password = cfg['ELASTIC_PASSWORD' if admin else 'P1_DETECTION_PASSWORD']
            user = 'elastic' if admin else 'p1_detection_operator'
            headers = {'Authorization': 'Basic ' + base64.b64encode((user+':'+password).encode()).decode(),
                       'Content-Type': 'application/x-ndjson' if isinstance(body, str) else 'application/json',
                       'kbn-xsrf': 'local-approved-validation'}
            data = body.encode() if isinstance(body, str) else json.dumps(body).encode() if body is not None else None
            request = urllib.request.Request(base+path, headers=headers, data=data, method=method)
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(ROOT/'infra/certs/ca.crt'))))
            with opener.open(request, timeout=20) as response:
                return json.load(response)
        except Stop:
            raise
        except Exception:
            raise Stop('Local API request failed; sensitive response suppressed') from None
