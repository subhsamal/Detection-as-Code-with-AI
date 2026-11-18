"""Offline regression tests for CI policy; no services or credential reads."""
from contextlib import redirect_stdout
from copy import deepcopy
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'scripts/ci'))
ci = importlib.import_module('validate')
installer = importlib.import_module('install_tools')
scanner = importlib.import_module('secret_scan')


class StrictDataTests(unittest.TestCase):
    def parse_yaml(self, text):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'sample.yml'
            path.write_text(text)
            return ci.yaml(path)

    def test_yaml12_workflow_keys_booleans_and_environment_references(self):
        parsed = self.parse_yaml('on:\n  push: null\nenabled: false\nvalue: "${KEY}"\n')
        self.assertIn('on', parsed)
        self.assertIs(parsed['enabled'], False)
        self.assertEqual(parsed['value'], '${KEY}')

    def test_yaml_rejects_duplicate_keys_aliases_merges_tags_and_multiple_documents(self):
        for text in ('key: 1\nkey: 2\n', 'a: &x value\nb: *x\n',
                     'a: &x {key: value}\nb: {<<: *x}\n',
                     'a: !ruby/object:Something {}\n', '---\na: 1\n---\na: 2\n',
                     'a: [broken\n', 'a: .nan\n'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.parse_yaml(text)

    def test_json_rejects_nested_duplicates_nonfinite_and_invalid_data(self):
        for text in ('{"a":1,"a":2}', '{"outer":{"a":1,"a":2}}',
                     '{"a":NaN}', '{"a":Infinity}', '{"a":1e999}', '{broken}'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                ci.strict_json(text)


class DetectionContractTests(unittest.TestCase):
    def setUp(self):
        self.rule = ci.yaml(ROOT/'detections/rules/P1-PS-001_Office_Encoded_PowerShell.yml')
        self.query = (ROOT/'detections/rules/P1-PS-001_Office_Encoded_PowerShell.esql').read_text()
        self.mapping = ci.strict_json((ROOT/'detections/mappings/logs-p1-powershell-synthetic.json').read_text())

    def test_current_contract_passes_without_engine(self):
        self.assertEqual(ci.detection_contract(self.rule, self.query, self.mapping),
                         'logs-p1-powershell-synthetic')

    def test_bad_rule_metadata_types_bounds_and_actions_fail(self):
        changes = [('enabled', True), ('risk_score', True), ('risk_score', 101),
                   ('severity', 'urgent'), ('version', 0), ('max_signals', 99),
                   ('from', 'now-1m'), ('actions', [{'id': 'connector'}])]
        for key, value in changes:
            changed = deepcopy(self.rule);changed[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                ci.detection_contract(changed, self.query, self.mapping)

    def test_query_parity_metadata_and_mapping_are_contracts_not_engine_parser(self):
        with self.assertRaises(ValueError):
            ci.detection_contract(self.rule, self.query+'\n| LIMIT 1', self.mapping)
        changed = self.query.replace('[metadata _id, _index, _version]', 'METADATA _id, _index, _version')
        rule = deepcopy(self.rule);rule['query'] = changed.rstrip()
        with self.assertRaises(ValueError):
            ci.detection_contract(rule, changed, self.mapping)
        mapping = deepcopy(self.mapping);del mapping['mappings']['properties']['p1']
        with self.assertRaises(KeyError):
            ci.detection_contract(self.rule, self.query, mapping)


class WorkflowSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = ci.yaml(ROOT/'.github/workflows/ci.yml')
        cls.lock = ci.strict_json((ROOT/'scripts/ci/tools.lock.json').read_text())

    def test_triggers_permissions_parallelism_timeouts_and_pins(self):
        workflow = self.workflow
        self.assertEqual(set(workflow['on']), {'pull_request', 'push'})
        self.assertEqual(workflow['on']['pull_request']['branches'], ['main'])
        self.assertEqual(workflow['on']['push']['branches'], ['main'])
        self.assertEqual(workflow['permissions'], {'contents': 'read'})
        self.assertEqual(len(workflow['jobs']), 4)
        for job_id, job in workflow['jobs'].items():
            self.assertEqual(job['runs-on'], 'ubuntu-24.04')
            self.assertGreater(job['timeout-minutes'], 0)
            self.assertNotIn('services', job)
            if job_id != 'completion':
                self.assertNotIn('needs', job)
            for step in job['steps']:
                if 'uses' in step:
                    name, sha = step['uses'].split('@')
                    self.assertEqual(sha, self.lock['actions'][name]['sha'])
                    self.assertRegex(sha, r'^[0-9a-f]{40}$')
                    if name == 'actions/checkout':
                        self.assertIs(step['with']['persist-credentials'], False)
                        self.assertEqual(step['with']['fetch-depth'], 0)
                    elif name == 'actions/setup-python':
                        self.assertEqual(step['with']['python-version'], self.lock['runtimes']['python'])
                        self.assertTrue(step['with']['python-version'].startswith('3.11.'))
                    elif name == 'ruby/setup-ruby':
                        self.assertEqual(step['with']['ruby-version'], self.lock['runtimes']['ruby'])

    def test_completion_script_fails_closed_on_failure_cancellation_skip_or_missing_result(self):
        job = self.workflow['jobs']['completion']
        self.assertEqual(set(job['needs']), {'detection-tests', 'configuration-quality', 'secrets-artifacts'})
        self.assertEqual(job['if'], '${{ always() }}')
        self.assertEqual(job['permissions'], {})
        script = job['steps'][0]['run']
        keys = ('DETECTION_RESULT', 'CONFIGURATION_RESULT', 'SECRETS_RESULT')
        baseline = {key: 'success' for key in keys}
        self.assertEqual(subprocess.run(['bash', '-eu', '-c', script], env=baseline,
                                       capture_output=True).returncode, 0)
        for key in keys:
            for state in ('failure', 'cancelled', 'skipped', ''):
                env = {**baseline, key: state}
                self.assertNotEqual(subprocess.run(['bash', '-eu', '-c', script], env=env,
                                                   capture_output=True).returncode, 0)

    def test_discovery_and_no_credentials_or_live_runtime_commands(self):
        text = (ROOT/'.github/workflows/ci.yml').read_text()
        self.assertIn("unittest discover -s detections/tests -p 'test_*.py'", text)
        for forbidden in ('secrets.', 'pull_request_target', 'docker compose up',
                          'runtime_validation.py warmup', 'runtime_validation.py ingest',
                          'runtime_validation.py audit', '--env-file infra/.env', 'continue-on-error'):
            self.assertNotIn(forbidden, text)

    def test_tools_have_pinned_https_assets_and_checksums(self):
        self.assertEqual(set(self.lock['tools']), {'ruff', 'actionlint', 'gitleaks', 'compose'})
        for tool in self.lock['tools'].values():
            for spec in tool['platforms'].values():
                self.assertTrue(spec['url'].startswith('https://github.com/'))
                self.assertRegex(spec['sha256'], r'^[0-9a-f]{64}$')


class InstallerAndExposureTests(unittest.TestCase):
    def test_historical_exceptions_are_only_four_verified_placeholder_fingerprints(self):
        entries = [line for line in (ROOT/'.gitleaksignore').read_text().splitlines()
                   if line and not line.startswith('#')]
        expected_commit = '388758e711371bad961799df71eb66d7e3228206'
        self.assertEqual(set(entries), {
            expected_commit+':docs/BUILD-MANUAL.md:curl-auth-user:'+str(line)
            for line in (331, 366, 371, 376)})
        self.assertEqual(len(entries), 4)
        historic = subprocess.run(['git', 'show', expected_commit+':docs/BUILD-MANUAL.md'],
                                  cwd=ROOT, capture_output=True, text=True, check=True).stdout.splitlines()
        for number in (331, 366, 371, 376):
            # Do not print source content if a regression introduces sensitive text.
            self.assertTrue(historic[number-1].split('-u ', 1)[1].split()[0]
                            == 'elastic:'+'YOUR_PASSWORD', 'Historical placeholder changed')
        self.assertNotIn('YOUR_PASSWORD', (ROOT/'docs/BUILD-MANUAL.md').read_text())

    def test_history_exceptions_cannot_apply_to_current_content(self):
        for mode in ('git', 'dir'):
            def invoke(args, **_):
                ignore = Path(args[args.index('--gitleaks-ignore-path')+1])
                if mode == 'git':
                    self.assertEqual(ignore, ROOT/'.gitleaksignore')
                else:
                    self.assertNotEqual(ignore, ROOT/'.gitleaksignore')
                    self.assertEqual(ignore.read_text(), '')
                return Mock(returncode=0)

            with patch.object(scanner.subprocess, 'run', side_effect=invoke), \
                 patch.object(scanner, 'publishable_tree'), redirect_stdout(io.StringIO()):
                self.assertEqual(scanner.scan('/tmp/fake-scanner', mode), 0)

    def test_checksum_failure_cannot_produce_executable_payload(self):
        with self.assertRaises(ValueError):
            installer.verified_payload(b'wrong bytes', {'sha256': '0'*64, 'member': None})

    def test_archive_only_reads_expected_regular_member(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
            member = tarfile.TarInfo('tool');member.size = 2
            archive.addfile(member, io.BytesIO(b'ok'))
            link = tarfile.TarInfo('link');link.type = tarfile.SYMTYPE;link.linkname = '/etc/passwd'
            archive.addfile(link)
        data = buffer.getvalue();spec = {'sha256': hashlib.sha256(data).hexdigest(), 'member': 'tool'}
        self.assertEqual(installer.verified_payload(data, spec), b'ok')
        for name in ('link', '../tool', '/tool'):
            with self.assertRaises(ValueError):
                installer.verified_payload(data, {**spec, 'member': name})

    def test_install_destination_cannot_be_inside_checkout(self):
        with patch('urllib.request.urlopen', side_effect=AssertionError('network forbidden')):
            with self.assertRaises(ValueError):
                installer.install(['ruff'], ROOT/'tools')

    def test_compose_does_not_inherit_credentials_read_dotenv_or_start_services(self):
        with patch.dict(os.environ, {'ELASTIC_PASSWORD': 'must-not-propagate'}), \
             patch.object(ci.subprocess, 'run', return_value=Mock(returncode=0)) as run, \
             redirect_stdout(io.StringIO()):
            ci.compose_config('/tmp/compose')
        args, kwargs = run.call_args
        self.assertEqual(args[0][-3:], ['config', '--no-env-resolution', '--quiet'])
        self.assertIn(os.devnull, args[0])
        self.assertNotEqual(kwargs['env']['ELASTIC_PASSWORD'], 'must-not-propagate')
        self.assertNotIn('up', args[0])
        self.assertNotIn('pull', args[0])

    def test_publishable_secret_path_is_rejected_without_reading_it(self):
        with patch.object(ci, 'files', return_value=[ROOT/'infra/.env']):
            with self.assertRaises(ValueError):
                ci.artifacts()

    def test_secret_reports_print_metadata_only_even_if_tool_returns_sensitive_fields(self):
        sentinel = 'sensitive-sentinel-not-for-output'

        def invoke(args, **_):
            report = Path(args[args.index('--report-path')+1])
            report.write_text(json.dumps([{'File': 'example.txt', 'StartLine': 2, 'RuleID': 'test-rule',
                                          'Secret': sentinel, 'Match': sentinel}]))
            return Mock(returncode=1, stdout=sentinel, stderr=sentinel)

        with patch.object(scanner.subprocess, 'run', side_effect=invoke), \
             redirect_stdout(io.StringIO()) as output:
            self.assertEqual(scanner.scan('/tmp/fake-scanner', 'git'), 1)
        self.assertNotIn(sentinel, output.getvalue())
        self.assertIn('example.txt', output.getvalue())
