"""Offline safety/policy tests. No credentials, Docker or live API access."""
from contextlib import redirect_stdout, redirect_stderr
from copy import deepcopy
from datetime import datetime, timezone
import io
import importlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

PROCESSING = Path(__file__).resolve().parents[1] / 'processing'
sys.path.insert(0, str(PROCESSING))
client = importlib.import_module('runtime_client')
fixtures = importlib.import_module('runtime_fixtures')
runtime = importlib.import_module('runtime_validation')


class FixtureBuilderTests(unittest.TestCase):
    def test_exact_manifest_unique_ids_and_pid_realism(self):
        bundle = fixtures.build_fixtures('offline-test-001', '2026-11-17T12:00:00Z')
        self.assertEqual(len(bundle['prepared_events']), 29)
        self.assertEqual(len(bundle['expected']), 14)
        self.assertEqual(len(bundle['excluded']), 15)
        self.assertEqual(len(set(bundle['source_ids'])), 29)
        for e in bundle['prepared_events']:
            self.assertNotEqual(e['process']['pid'], e['process']['parent']['pid'])
        self.assertEqual(bundle, fixtures.build_fixtures('offline-test-001', '2026-11-17T12:00:00Z'))
        other = fixtures.build_fixtures('offline-test-002', '2026-11-17T12:00:00Z')
        self.assertFalse(set(bundle['source_ids']) & set(other['source_ids']))

    def test_builder_is_offline_and_does_not_execute_scripts(self):
        with patch('socket.socket', side_effect=AssertionError('network forbidden')), \
             patch('subprocess.Popen', side_effect=AssertionError('execution forbidden')):
            self.assertEqual(len(fixtures.build_fixtures('offline-test-001',
                                                       '2026-11-17T12:00:00Z')['prepared_events']), 29)

    def test_invalid_run_or_naive_timestamp_rejected(self):
        for run_id, stamp in [('../escape', '2026-11-17T12:00:00Z'),
                              ('offline-test', '2026-11-17T12:00:00')]:
            with self.assertRaises(ValueError):
                fixtures.build_fixtures(run_id, stamp)


class MutationPolicyTests(unittest.TestCase):
    def setUp(self):
        self.bundle = fixtures.build_fixtures('offline-test-001', '2026-11-17T12:00:00Z')
        self.bulk = fixtures.create_bulk(self.bundle)

    def test_default_client_denies_before_loading_secrets(self):
        read_only = client.Client()
        with patch.object(Path, 'read_text', side_effect=AssertionError('must not load credentials')):
            with self.assertRaises(client.Stop):
                read_only.call('kb', '/api/detection_engine/rules',
                               {'rule_id': client.RULE, 'enabled': True}, method='PATCH')

    def test_live_modes_require_explicit_guard_before_client_construction(self):
        for argv in (['warmup'], ['ingest'], ['warmup', '--allow-live-writes'],
                     ['ingest', '--allow-live-writes', '--confirm-rule', 'OTHER']):
            with patch.object(runtime, 'Client', side_effect=AssertionError('no live client')), \
                 redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                runtime.main(argv)

    def test_offline_fixtures_cli_never_constructs_client(self):
        with patch.object(runtime, 'Client', side_effect=AssertionError('no live client')), \
             redirect_stdout(io.StringIO()) as output:
            runtime.main(['fixtures', '--run-id', 'offline-test-001', '--anchor', '2026-11-17T12:00:00Z'])
        self.assertEqual(len(json.loads(output.getvalue())['prepared_events']), 29)

    def test_only_exact_operator_enable_disable_patch_allowed(self):
        allowed = {'rule_id': client.RULE, 'enabled': False}
        client.authorize('kb', '/api/detection_engine/rules', 'PATCH', allowed, False, {'disable'})
        for body, admin in [({**allowed, 'query': 'changed'}, False),
                            ({**allowed, 'rule_id': 'other'}, False), (allowed, True)]:
            with self.assertRaises(client.Stop):
                client.authorize('kb', '/api/detection_engine/rules', 'PATCH', body, admin, {'disable'})

    def test_exact_admin_create_only_batch_allowed(self):
        client.authorize('es', '/' + client.INDEX + '/_bulk', 'POST', self.bulk, True, {'ingest'})
        for path, admin, writes in [('/other/_bulk', True, {'ingest'}),
                                    ('/'+client.INDEX+'/_bulk?refresh=wait_for', True, {'ingest'}),
                                    ('/'+client.INDEX+'/_bulk', False, {'ingest'}),
                                    ('/'+client.INDEX+'/_bulk', True, set())]:
            with self.assertRaises(client.Stop):
                client.authorize('es', path, 'POST', self.bulk, admin, writes)

    def test_index_update_delete_override_duplicate_and_partial_bulk_rejected(self):
        original = [json.loads(line) for line in self.bulk.splitlines()]
        variants = []
        for op in ('index', 'update', 'delete'):
            lines = deepcopy(original); lines[0] = {op: lines[0]['create']}; variants.append(lines)
        lines = deepcopy(original); lines[0]['create']['_index'] = 'other'; variants.append(lines)
        lines = deepcopy(original); lines[2] = lines[0]; variants.append(lines)
        lines = deepcopy(original); lines[1] = '@timestamp'; variants.append(lines)
        variants.append(original[:-2])
        for lines in variants:
            with self.assertRaises(client.Stop):
                client.authorize('es', '/'+client.INDEX+'/_bulk', 'POST',
                                 '\n'.join(json.dumps(v) for v in lines)+'\n', True, {'ingest'})

    def test_security_config_refresh_and_key_mutations_have_no_allowlist(self):
        for service, path, method in [('es', '/_security/api_key', 'POST'),
                ('es', '/_security/api_key', 'DELETE'), ('es', '/_security/role/operator', 'PUT'),
                ('es', '/_index_template/p1-powershell-synthetic', 'PUT'),
                ('es', '/'+client.INDEX+'/_refresh', 'POST'),
                ('es', '/_data_stream/'+client.INDEX, 'DELETE')]:
            with self.assertRaises(client.Stop):
                client.authorize(service, path, method, {}, True, {'enable', 'disable', 'ingest'})

    def test_redirects_are_refused(self):
        with self.assertRaises(client.Stop):
            client.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://other.invalid')


class RuntimeEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.bundle = fixtures.build_fixtures('offline-test-001', '2026-11-17T12:00:00Z')
        self.hits = [{'_id': 'alert-'+str(n), '_source': {'event': {'id': eid}, 'kibana': {'alert': {
            'severity': want['severity'], 'risk_score': want['risk_score']}}}}
            for n, (eid, want) in enumerate(self.bundle['expected'].items())]

    def test_actual_alert_fields_and_expected_false_positives(self):
        rows = runtime.verify_alerts(self.hits, self.bundle)
        self.assertEqual(sum(r['severity'] == 'medium' for r in rows), 6)
        self.assertEqual(sum(r['severity'] == 'high' for r in rows), 8)
        self.assertEqual(sum(r['category'] == 'false_positive' for r in rows), 2)

    def test_wrong_override_duplicate_and_excluded_alert_fail(self):
        wrong = deepcopy(self.hits);wrong[0]['_source']['kibana']['alert']['risk_score'] = 999
        duplicate = deepcopy(self.hits);duplicate.append(deepcopy(duplicate[0]))
        excluded = deepcopy(self.hits);excluded[0]['_source']['event']['id'] = self.bundle['excluded'][0]
        for hits in (wrong, duplicate, excluded, self.hits[:-1]):
            with self.assertRaises(client.Stop):
                runtime.verify_alerts(hits, self.bundle)

    def test_preexisting_alerts_are_preserved(self):
        previous = {'_id': 'previous', '_source': {}}
        self.assertEqual(len(runtime.verify_alerts([previous]+self.hits, self.bundle, ['previous'])), 14)
        with self.assertRaises(client.Stop):
            runtime.verify_alerts(self.hits, self.bundle, ['previous'])

    def test_actual_timestamp_overlap_required(self):
        runs = [{'start': '2026-11-17T12:00:30Z', 'status': 'succeeded'},
                {'start': '2026-11-17T12:05:30Z', 'status': 'succeeded'}]
        versions = {'doc': {'timestamp': '2026-11-17T12:00:00Z'}}
        runtime.verify_overlap(runs, versions, '2026-11-17T12:00:01Z')
        runs[1]['start'] = '2026-11-17T12:08:00Z'
        with self.assertRaises(client.Stop):
            runtime.verify_overlap(runs, versions, '2026-11-17T12:00:01Z')

    @staticmethod
    def execution_events(start, status, message):
        uid = start
        def obj(action, **extra):
            return {'event': {'action': action, **extra}, 'kibana': {'alert': {'rule': {
                'execution': {'uuid': uid, 'status': status}}}, 'alerting': {'status': 'ok'}},
                'message': message}
        return [obj('status-change'), obj('execute', provider='alerting', outcome='success',
                                         start=start, end=start)]

    def test_only_one_explicit_first_historical_gap_can_be_allowed(self):
        message = ('4 minutes (210410ms) were not queried between this rule execution and the last execution, '
                   'so signals may have been missed. Consider increasing your look behind time or adding more Kibana instances')
        first = self.execution_events('2026-11-17T12:00:30Z', 'failed', message)
        second = self.execution_events('2026-11-17T12:05:30Z', 'succeeded', 'Rule execution completed successfully')
        fake = Mock()
        fake.call.return_value = {'hits': {'total': {'value': 4}, 'hits': [{'_source': e} for e in first+second]}}
        runs = runtime.execution_runs(fake, 'rule', '2026-11-17T12:00:00Z', allow_first_gap=True)
        self.assertTrue(runs[0]['historical_gap']);self.assertEqual(runs[1]['status'], 'succeeded')
        with self.assertRaises(client.Stop):
            runtime.execution_runs(fake, 'rule', '2026-11-17T12:00:00Z')
        second = self.execution_events('2026-11-17T12:05:30Z', 'failed', message)
        fake.call.return_value['hits']['hits'] = [{'_source': e} for e in first+second]
        with self.assertRaises(client.Stop):
            runtime.execution_runs(fake, 'rule', '2026-11-17T12:00:00Z', allow_first_gap=True)

    def test_other_error_never_gets_warmup_exception(self):
        for message in ('security_exception: forbidden', 'Query parsing failed'):
            events = self.execution_events('2026-11-17T12:00:30Z', 'failed', message)
            fake = Mock();fake.call.return_value = {'hits': {'total': {'value': 2},
                                                          'hits': [{'_source': e} for e in events]}}
            with self.assertRaises(client.Stop):
                runtime.execution_runs(fake, 'rule', '2026-11-17T12:00:00Z', allow_first_gap=True)

    def test_audit_mode_cannot_mutate(self):
        with patch.object(runtime, 'Client') as cls, patch.object(runtime, 'audit', return_value={'disabled': True}), \
             redirect_stdout(io.StringIO()):
            runtime.main(['audit', '--evidence', 'saved.json'])
        cls.assert_called_once_with(writes=())

    def test_ingestion_failure_always_attempts_targeted_disable(self):
        fake = Mock()
        with patch.object(runtime, 'preflight', side_effect=client.Stop('preflight stopped')), \
             patch.object(runtime, 'disable') as disable, patch.object(runtime, 'write_evidence'):
            with self.assertRaises(client.Stop):
                runtime.ingest(fake)
        disable.assert_called_once()

    def test_warmup_second_failure_disables_and_does_not_pass(self):
        fake = Mock();fake.call.return_value = {'enabled': True,
            'updated_by': 'p1_detection_operator', 'updated_at': '2026-11-17T12:00:00Z'}
        first = {'start': '2026-11-17T12:00:10Z', 'end': '2026-11-17T12:00:11Z',
                 'status': 'failed', 'historical_gap': True}
        with patch.object(runtime, 'preflight', return_value=({'id': 'rule'}, {})), \
             patch.object(runtime, 'identity', return_value={}), patch.object(runtime, 'alerts', return_value=[]), \
             patch.object(runtime, 'rule', return_value={'enabled': True}), \
             patch.object(runtime, 'execution_runs', side_effect=[[first], client.Stop('second run failed')]), \
             patch.object(runtime, 'disable') as disable, patch.object(runtime, 'write_evidence'), \
             patch.object(runtime, 'now', return_value=datetime(2026, 11, 17, 12, 0, 45, tzinfo=timezone.utc)), \
             patch.object(runtime.time, 'sleep'), redirect_stdout(io.StringIO()):
            with self.assertRaises(client.Stop):
                runtime.warmup(fake, allow_gap=True)
        disable.assert_called_once()

    def test_clean_second_warmup_run_pauses_enabled_without_ingestion(self):
        fake = Mock();fake.call.return_value = {'enabled': True,
            'updated_by': 'p1_detection_operator', 'updated_at': '2026-11-17T12:00:00Z'}
        first = {'start': '2026-11-17T12:00:10Z', 'end': '2026-11-17T12:00:11Z',
                 'status': 'failed', 'historical_gap': True}
        second = {'start': '2026-11-17T12:05:10Z', 'end': '2026-11-17T12:05:11Z',
                  'status': 'succeeded', 'historical_gap': False,
                  'message': 'Rule execution completed successfully'}
        with patch.object(runtime, 'preflight', return_value=({'id': 'rule'}, {})), \
             patch.object(runtime, 'identity', return_value={}), patch.object(runtime, 'alerts', return_value=[]), \
             patch.object(runtime, 'rule', return_value={'enabled': True}), \
             patch.object(runtime, 'execution_runs', side_effect=[[first], [first, second]]), \
             patch.object(runtime, 'disable') as disable, patch.object(runtime, 'write_evidence'), \
             patch.object(runtime, 'now', side_effect=[datetime(2026, 11, 17, 12, 0, 45, tzinfo=timezone.utc),
                 datetime(2026, 11, 17, 12, 5, 12, tzinfo=timezone.utc)]), \
             patch.object(runtime.time, 'sleep'), redirect_stdout(io.StringIO()):
            result = runtime.warmup(fake, allow_gap=True)
        self.assertTrue(result['passed']);self.assertTrue(result['paused_before_ingestion'])
        self.assertFalse(result['historical_coverage_recovered'])
        disable.assert_not_called()
        self.assertEqual(fake.call.call_args_list[0].args[:2], ('kb', '/api/detection_engine/rules'))
        self.assertEqual(len(fake.call.call_args_list), 1)  # enable only, no ingestion

    def test_partial_bulk_failure_disables_without_retry(self):
        fixed = datetime(2026, 11, 17, 12, 0, tzinfo=timezone.utc)
        ticks = [0]

        def clock():
            ticks[0] += 1
            return fixed if ticks[0] <= 2 else fixed.replace(second=20)
        mapping = json.loads((PROCESSING.parent/'mappings'/f'{client.INDEX}.json').read_text())
        fake = Mock()
        bulk_calls = []

        def respond(service, path, body=None, **kwargs):
            if path.endswith('/_count'):
                return {'count': 58}
            if path.endswith('/_mapping'):
                return {'backing': {'mappings': {**mapping['mappings'],
                                                '_data_stream_timestamp': {'enabled': True}}}}
            if '/_settings' in path:
                return {'backing': {'settings': {'index.number_of_shards': '1', 'index.number_of_replicas': '0'}}}
            if path.startswith('/api/alerting/rule/'):
                return {'next_run': '2026-11-17T12:00:45Z'}
            if path.endswith('/_bulk'):
                bulk_calls.append((body, kwargs))
                return {'errors': True, 'items': [{'create': {'status': 409}}] +
                        [{'create': {'status': 201}} for _ in range(28)]}
            self.fail('Unexpected mocked operation')

        fake.call.side_effect = respond
        r = {'id': 'rule', 'execution_summary': {'last_execution': {'status': 'succeeded'}}}
        with patch.object(runtime, 'preflight', return_value=(r, {})), \
             patch.object(runtime, 'alerts', return_value=[]), \
             patch.object(runtime, 'source_versions', return_value={}), \
             patch.object(runtime, 'now', side_effect=clock), \
             patch.object(runtime.time, 'sleep', side_effect=AssertionError('test must not sleep')), \
             patch.object(runtime, 'disable') as disable, patch.object(runtime, 'write_evidence'):
            with self.assertRaises(client.Stop):
                runtime.ingest(fake)
        self.assertEqual(len(bulk_calls), 1)
        self.assertTrue(bulk_calls[0][1]['admin'])
        self.assertEqual(len(bulk_calls[0][0].splitlines()), 58)
        disable.assert_called_once()


if __name__ == '__main__':
    unittest.main()
