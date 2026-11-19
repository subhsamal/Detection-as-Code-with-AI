"""Credential-free offline checks. These do not parse ES|QL in Elasticsearch."""
import argparse
import ast
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]


class ValidationError(ValueError):
    """Only sanitized, policy-authored diagnostics may reach CI logs."""


def require(condition, message):
    if not condition:
        raise ValidationError(message)


def files(root=ROOT):
    result = subprocess.run(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'],
                            cwd=root, capture_output=True, check=True)
    return sorted({root / os.fsdecode(path) for path in result.stdout.split(b'\0') if path})


def strict_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'Duplicate JSON key')
            result[key] = value
        return result

    def invalid(_):
        raise ValueError('Non-finite JSON number')

    value = json.loads(text, object_pairs_hook=pairs, parse_constant=invalid)
    # Decimal exponents can overflow without invoking parse_constant.
    json.dumps(value, allow_nan=False)
    return value


def yaml(path):
    result = subprocess.run(['ruby', str(ROOT/'scripts/ci/strict_yaml.rb'), '--json', str(path)],
                            capture_output=True, text=True)
    require(result.returncode == 0, 'Strict YAML parsing failed: ' + path.name)
    return strict_json(result.stdout)


def field(mapping, name):
    value = mapping['mappings']
    for part in name.split('.'):
        value = value['properties'][part]
    return value


def seconds(text):
    match = re.fullmatch(r'([1-9][0-9]*)([smh])', text)
    require(match is not None, 'Unsupported interval')
    return int(match[1]) * {'s': 1, 'm': 60, 'h': 3600}[match[2]]


def detection_contract(rule, query, mapping):
    required = {'rule_id', 'name', 'description', 'type', 'language', 'version', 'enabled',
                'severity', 'risk_score', 'query', 'interval', 'from', 'to', 'max_signals',
                'actions', 'severity_mapping', 'risk_score_mapping'}
    require(isinstance(rule, dict) and required <= set(rule), 'Missing detection fields')
    for key in ('rule_id', 'name', 'description', 'query'):
        require(isinstance(rule[key], str) and rule[key].strip(), 'Empty detection text')
    require(rule['enabled'] is False and rule['actions'] == [], 'Rule must remain disabled without actions')
    require(rule['type'] == rule['language'] == 'esql', 'Only reviewed ES|QL contract supported')
    require(type(rule['version']) is int and rule['version'] >= 1, 'Invalid rule version')
    require(rule['severity'] in {'low', 'medium', 'high', 'critical'}, 'Invalid severity')
    require(type(rule['risk_score']) is int and 0 <= rule['risk_score'] <= 100, 'Invalid risk score')
    require(type(rule['max_signals']) is int and 1 <= rule['max_signals'] <= 10000, 'Invalid alert limit')
    require(rule['query'] == query.rstrip(), 'YAML/ES|QL query mismatch')
    require(rule['to'] == 'now' and rule['from'].startswith('now-'), 'Unsupported time bounds')
    require(seconds(rule['from'][4:]) >= seconds(rule['interval']), 'Look-back shorter than interval')
    first = re.fullmatch(r'FROM ([a-z0-9._-]+) \[metadata _id, _index, _version\]', query.splitlines()[0])
    require(first is not None, 'Kibana 8.13 metadata/source contract mismatch')
    limit = re.search(r'\| LIMIT ([1-9][0-9]*)\s*$', query)
    require(limit is not None and int(limit[1]) == rule['max_signals'], 'LIMIT/max_signals mismatch')
    require(mapping['mappings']['dynamic'] == 'strict', 'Source mapping must be strict')
    require(field(mapping, '@timestamp')['type'] == 'date', 'Timestamp mapping must be date')
    for name in set(re.findall(r'\b(?:event|host|process|p1)\.[A-Za-z0-9_.]+', query)):
        field(mapping, name)
    for item in rule['severity_mapping']:
        require(item['operator'] == 'equals' and item['severity'] in {'low', 'medium', 'high', 'critical'}
                and isinstance(item['value'], str) and field(mapping, item['field'])['type'] == 'keyword',
                'Invalid severity mapping')
    for item in rule['risk_score_mapping']:
        require(item['operator'] == 'equals' and item['value'] == ''
                and field(mapping, item['field'])['type'] in {'integer', 'long', 'float', 'double'},
                'Invalid numeric risk mapping')
    return first[1]


def contracts():
    paths = sorted((ROOT/'detections/rules').glob('*.y*ml'))
    require(bool(paths), 'No detection rules found')
    identifiers = set()
    companions = set()
    for path in paths:
        rule = yaml(path)
        query_path = path.with_suffix('.esql')
        query = query_path.read_text()
        source = re.fullmatch(r'FROM ([a-z0-9._-]+) \[metadata _id, _index, _version\]', query.splitlines()[0])
        require(source is not None, 'Invalid source contract')
        mapping = strict_json((ROOT/'detections/mappings'/f'{source[1]}.json').read_text())
        detection_contract(rule, query, mapping)
        exported = subprocess.run(['ruby', str(ROOT/'detections/processing/export_rule.rb'), str(path)],
                                  capture_output=True, text=True, check=True)
        require(strict_json(exported.stdout) == rule, 'Exporter/parser disagree')
        require(rule['rule_id'] not in identifiers, 'Duplicate rule ID')
        identifiers.add(rule['rule_id'])
        companions.add(query_path)
    require(companions == set((ROOT/'detections/rules').glob('*.esql')), 'Orphan ES|QL file')
    print('PASS | Offline detection contracts; ES|QL engine syntax/compatibility NOT tested')


def configurations():
    for path in files():
        if path.suffix in {'.yaml', '.yml'}:
            yaml(path)
        elif path.suffix == '.json':
            strict_json(path.read_text())
        elif path.suffix == '.py':
            ast.parse(path.read_text(), filename=str(path))
    es = yaml(ROOT/'infra/elasticsearch/elasticsearch.yml')
    kb = yaml(ROOT/'infra/kibana/kibana.yml')
    require(es['xpack.security.enabled'] is True and es['xpack.security.http.ssl.enabled'] is True,
            'Elasticsearch security/TLS must remain enabled')
    require(kb['elasticsearch.ssl.verificationMode'] == 'full', 'Hostname verification must remain full')
    require(kb['elasticsearch.serviceAccountToken'] == '${KIBANA_SERVICE_ACCOUNT_TOKEN}', 'Token must be an environment reference')
    require(kb['xpack.encryptedSavedObjects.encryptionKey'] == '${KIBANA_ENCRYPTION_KEY}', 'Persistent key reference required')
    compose = yaml(ROOT/'infra/docker-compose.yml')
    require(set(compose['services']) == {'elasticsearch', 'kibana', 'n8n'}, 'Unexpected infrastructure services')
    for service in compose['services'].values():
        require(all(isinstance(port, str) and port.startswith('127.0.0.1:') for port in service['ports']),
                'Published ports must remain localhost-only')
        for mount in service.get('volumes', []):
            if isinstance(mount, dict) and str(mount.get('source', '')).startswith('./certs/'):
                require(mount.get('read_only') is True and mount.get('bind', {}).get('create_host_path') is False,
                        'Certificate mounts must be read-only/non-creating')
    print('PASS | Strict YAML/JSON, Python syntax and offline security configuration policy')


def compose_config(binary):
    # No inherited application credentials; no repository .env lookup or output.
    env = {k: os.environ[k] for k in ('PATH', 'HOME', 'SYSTEMROOT') if k in os.environ}
    env.update({'COMPOSE_DISABLE_ENV_FILE': 'true', 'ES_VERSION': '8.13.0',
                'ES_PORT': '9200', 'KIBANA_PORT': '5601', 'N8N_PORT': '5678',
                'ELASTIC_PASSWORD': 'ci-placeholder-not-authentication',
                'KIBANA_SERVICE_ACCOUNT_TOKEN': 'ci-placeholder-not-authentication',
                'KIBANA_ENCRYPTION_KEY': 'ci-placeholder-not-a-real-encryption-key'})
    result = subprocess.run([binary, '--env-file', os.devnull, '-f', str(ROOT/'infra/docker-compose.yml'),
                             'config', '--no-env-resolution', '--quiet'], env=env,
                            capture_output=True, text=True)
    require(result.returncode == 0, 'Compose config-only validation failed; rendered content suppressed')
    print('PASS | Compose config-only with non-secret placeholders; no services/certificates tested')


def artifacts():
    blocked = []
    for path in files():
        relative = path.relative_to(ROOT)
        if (relative.parts[:2] in [('infra', 'certs'), ('docs', 'recordings')]
                or path.name == '.env' or path.name.endswith('.env')
                or path.suffix.lower() in {'.key', '.pem', '.p12', '.pfx', '.mov', '.mp4', '.mkv', '.webm',
                                         '.tmp', '.bak', '.zip', '.gz', '.tgz', '.xz', '.iso', '.dmg', '.exe'}):
            blocked.append(str(relative))
    require(not blocked, 'Forbidden publishable artifact paths: ' + ', '.join(blocked))
    result = subprocess.run(['git', 'check-ignore', '--no-index', '-q', '--stdin'], cwd=ROOT,
                            input='infra/.env\ninfra/certs/ci-check.key\ndocs/recordings/ci-check.mp4\n',
                            capture_output=True, text=True)
    # Check each independently: check-ignore's aggregate exit code only means ANY matched.
    require(result.returncode == 0, 'Missing secret/recording ignore policy')
    for path in ('infra/.env', 'infra/certs/ci-check.key', 'docs/recordings/ci-check.mp4'):
        require(subprocess.run(['git', 'check-ignore', '--no-index', '-q', path], cwd=ROOT).returncode == 0,
                'Missing ignore policy')
    print('PASS | Publishable artifact and ignore policies')


def formatting(base=None):
    command = ['git', 'diff', '--check'] + ([base, 'HEAD'] if base else ['HEAD'])
    require(subprocess.run(command, cwd=ROOT, capture_output=True).returncode == 0, 'Git diff whitespace failure')
    # Include newly authored local files; checkout files are all tracked in CI.
    for path in files():
        require(path.is_file(), 'Non-file project entry')
        tracked = subprocess.run(['git', 'ls-files', '--error-unmatch', str(path.relative_to(ROOT))],
                                 cwd=ROOT, capture_output=True).returncode == 0
        if not tracked:
            check = subprocess.run(['git', 'diff', '--no-index', '--check', os.devnull, str(path)], capture_output=True)
            require(check.returncode in (0, 1), 'Untracked-file whitespace failure')
    print('PASS | Git diff formatting')


def completion(results):
    expected = {'detection-tests', 'configuration-quality', 'secrets-artifacts'}
    require(isinstance(results, dict) and set(results) == expected, 'Required CI jobs missing')
    require(all(value.get('result') == 'success' for value in results.values()),
            'A required CI job failed, was cancelled, or was skipped')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('contracts', 'config', 'compose', 'artifacts', 'format', 'completion'))
    parser.add_argument('--compose-bin', default='compose')
    parser.add_argument('--base')
    args = parser.parse_args()
    try:
        if args.mode == 'contracts':
            contracts()
        elif args.mode == 'config':
            configurations()
        elif args.mode == 'compose':
            compose_config(args.compose_bin)
        elif args.mode == 'artifacts':
            artifacts()
        elif args.mode == 'format':
            if args.base:
                require(re.fullmatch(r'[0-9a-f]{40}', args.base) is not None, 'Invalid base commit')
            formatting(args.base)
        else:
            completion(strict_json(os.environ['CI_JOB_RESULTS']))
            print('PASS | All required CI jobs succeeded')
    except ValidationError as error:
        raise SystemExit('FAIL | ' + str(error)) from None
    except (ValueError, KeyError, IndexError, OSError, subprocess.SubprocessError):
        raise SystemExit('FAIL | Offline validation failed; document contents and sensitive diagnostics suppressed') from None


if __name__ == '__main__':
    main()
