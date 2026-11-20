"""Exercise committed canary artifacts and the HTTPS boundary with mocked I/O."""

import base64
from copy import deepcopy
from email.message import Message
import json
from pathlib import Path
import ssl
import subprocess
from tempfile import TemporaryDirectory
from threading import Lock
import unittest
from unittest.mock import Mock, patch

from detections.processing import connected_plan, deployment_plan, deployment_state
from detections.processing.canary_profile import CANARY_ARTIFACTS, CANARY_RULE_ID, CANARY_SPACE, CANARY_WRITER
from detections.processing.canary_transport import _CanaryHTTPS
from detections.processing.deployment_engine import CanaryDeploymentEngine


class SimulatedCrash(BaseException):
    pass


class CanaryDeploymentTests(unittest.TestCase):
    COMMIT = 'a' * 40
    UUID = '72ab56fa-f3a1-4c84-8466-a0b23b2254ea'
    OTHER_UUID = '82ab56fa-f3a1-4c84-8466-a0b23b2254ea'
    ORIGIN = 'https://127.0.0.1:5601'
    PATCH = '/s/p1-day4-canary/api/detection_engine/rules'
    GET = PATCH + '?rule_id=P1-D4-CANARY-001'
    MOCK_SECRET = 'mock-only fixture'

    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.commit_files = {
            path: (deployment_plan.ROOT / path).read_bytes() for path in CANARY_ARTIFACTS
        }
        real_run = subprocess.run

        def run(args, **kwargs):
            if args[:3] != ['git', '--no-replace-objects', 'cat-file']:
                return real_run(args, **kwargs)
            if args[3:] == ['-t', self.COMMIT]:
                return subprocess.CompletedProcess(args, 0, b'commit\n')
            if args[3] == 'blob' and args[4].startswith(self.COMMIT + ':'):
                path = args[4].partition(':')[2]
                if path in self.commit_files:
                    return subprocess.CompletedProcess(args, 0, self.commit_files[path])
            return subprocess.CompletedProcess(args, 1, b'')

        self.start_patch(deployment_plan.subprocess, 'run', side_effect=run)
        self.start_patch(ssl.SSLContext, 'load_verify_locations')
        self.https = self.start_patch(connected_plan, 'HTTPSConnection', side_effect=self.connection)
        self.requests = []
        self.crash = False
        self.get_status = 200
        self.baseline = deployment_plan.build_canary_plan(self.COMMIT, baseline=True)
        self.candidate = deployment_plan.build_canary_plan(self.COMMIT)
        self.remote = {
            **deepcopy(self.baseline['payload']), 'id': self.UUID, 'revision': 2,
            'immutable': False, 'output_index': '',
        }
        self.engine = self.restart()

    def start_patch(self, obj, name, **kwargs):
        patcher = patch.object(obj, name, **kwargs)
        self.addCleanup(patcher.stop)
        return patcher.start()

    def restart(self):
        return CanaryDeploymentEngine(self.ORIGIN, 'mock-ca.pem', self.UUID, self.MOCK_SECRET, Lock(),
                                      journal_directory=self.directory)

    def connection(self, host, port, *, context, timeout):
        self.assertEqual((host, port, timeout), ('127.0.0.1', 5601, 10))
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        conn = Mock()

        def request(method, path, *, headers, body=None):
            expected = base64.b64encode(f'{CANARY_WRITER}:{self.MOCK_SECRET}'.encode()).decode()
            self.assertEqual(headers['Authorization'], 'Basic ' + expected)
            decoded = json.loads(body) if body is not None else None
            self.requests.append((method, path, decoded))
            if method == 'GET':
                self.assertEqual((path, body), (self.GET, None))
            else:
                self.assertEqual((method, path, headers['kbn-xsrf']), ('PATCH', self.PATCH, 'day4-canary'))
                self.assertEqual(decoded.keys(), {'id', 'enabled', 'interval'})
                self.assertIs(decoded['enabled'], False)
                self.assertEqual(decoded.pop('id'), self.UUID)
                self.remote.update(decoded)
                self.remote['revision'] += 1
                if self.crash:
                    raise SimulatedCrash
            mime = Message()
            mime['Content-Type'] = 'application/json'
            conn.getresponse.return_value = Mock(
                status=self.get_status if method == 'GET' else 200,
                headers=mime, read=Mock(return_value=json.dumps(self.remote).encode()),
            )

        conn.request.side_effect = request
        return conn

    def approve(self):
        return deployment_state.digest(self.engine.plan(self.COMMIT))

    def apply(self, approval):
        return self.engine.apply(self.COMMIT, approval, authorize_write=True)

    def patches(self):
        return [request for request in self.requests if request[0] == 'PATCH']

    def test_apply_noop_and_separately_approved_rollback(self):
        plan = self.engine.plan(self.COMMIT)
        self.assertEqual(plan['before']['payload']['rule_id'], CANARY_RULE_ID)
        self.assertEqual(plan['target'], (self.ORIGIN, CANARY_SPACE))
        receipt = self.apply(deployment_state.digest(plan))
        receipt_digest = deployment_state.digest(receipt)
        self.assertEqual(self.engine.verify(receipt, receipt_digest)['payload'], self.candidate['payload'])
        fresh = self.engine.plan(self.COMMIT)
        self.assertEqual(fresh['action'], 'noop')
        self.apply(deployment_state.digest(fresh))
        self.assertEqual(len(self.patches()), 1)
        with self.assertRaisesRegex(ValueError, 'authorization'):
            self.engine.rollback(receipt, receipt_digest)
        self.assertEqual(self.engine.rollback(receipt, receipt_digest, authorize_write=True)['payload'],
                         self.baseline['payload'])
        self.assertEqual([body['interval'] for _, _, body in self.patches()], ['6m', '5m'])
        self.assertIs(self.remote['enabled'], False)
        journal = json.loads((self.directory / 'deployment-journal.json').read_text())['data']
        self.assertEqual(journal['binding']['rule_id'], CANARY_RULE_ID)
        self.assertEqual([r['states'][-1] for r in journal['records']], ['VERIFIED', 'VERIFIED'])
        self.assertEqual(journal['records'][0]['artifact_sha256'], self.candidate['artifact_sha256'])
        self.assertNotIn(self.MOCK_SECRET, repr(journal))

    def test_wrong_uuid_disabled_drift_stale_plan_and_missing_approval_block(self):
        approved = self.approve()
        with self.assertRaisesRegex(ValueError, 'authorization'):
            self.engine.apply(self.COMMIT, approved)
        with self.assertRaisesRegex(ValueError, 'Plan changed'):
            self.apply('0' * 64)
        original = deepcopy(self.remote)
        for changed, diagnostic in (
            ({'id': self.OTHER_UUID}, 'Unexpected rule UUID'),
            ({'rule_id': 'P1-PS-001'}, 'Unexpected rule identity'),
            ({'enabled': True}, 'disabled'),
            ({'description': 'unapproved description'}, 'drifted'),
            ({'timestamp_override': '@timestamp'}, 'Unknown Kibana'),
            ({'revision': 3}, 'Plan changed'),
        ):
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, diagnostic):
                self.remote = {**original, **changed}
                self.apply(approved)
        self.assertEqual(self.patches(), [])
        self.assertEqual(self.engine.status()['state'], 'EMPTY')

    def test_wire_denies_cross_space_wrong_identity_activation_or_extra_fields(self):
        transport = _CanaryHTTPS(self.ORIGIN, 'mock-ca.pem', self.UUID, self.MOCK_SECRET)
        safe = {'id': self.UUID, 'enabled': False, 'interval': '6m'}
        for method, path, body in (
            ('GET', self.GET.replace(CANARY_RULE_ID, 'P1-PS-001'), None),
            ('GET', '/api/detection_engine/rules?rule_id=P1-D4-CANARY-001', None),
            ('PATCH', '/api/detection_engine/rules', safe),
            ('PATCH', self.PATCH, {**safe, 'rule_id': 'P1-PS-001'}),
            ('PATCH', self.PATCH, {**safe, 'id': self.OTHER_UUID}),
            ('PATCH', self.PATCH, {**safe, 'enabled': True}),
            ('PATCH', self.PATCH, {**safe, 'interval': '10m'}),
            ('PATCH', self.PATCH, {**safe, 'actions': []}),
            ('POST', self.PATCH, safe),
            ('DELETE', self.PATCH, safe),
        ):
            with self.subTest(method=method, path=path, body=body), self.assertRaises(ValueError):
                transport._exchange(method, path, body, authorize_write=True)
        with self.assertRaisesRegex(ValueError, 'approved journaled'):
            transport._exchange('PATCH', self.PATCH, safe)
        self.https.assert_not_called()

    def test_read_only_p1_transport_cannot_dispatch_canary_or_patch(self):
        reader = connected_plan.KibanaHTTPS(self.ORIGIN, 'default', 'mock-ca.pem')
        with self.assertRaisesRegex(ValueError, 'Unsupported Kibana read path'):
            reader.read(self.GET, 'fixture-user', self.MOCK_SECRET)
        self.assertFalse(hasattr(reader, 'patch'))
        self.https.assert_not_called()

    def test_git_pair_rejects_additional_changes_and_missing_commit(self):
        self.assertEqual(
            {k for k in self.baseline['payload'] if self.baseline['payload'][k] != self.candidate['payload'][k]},
            {'interval'},
        )
        candidate = CANARY_ARTIFACTS[1]
        self.commit_files[candidate] = self.commit_files[candidate].replace(
            b'disabled deployment canary', b'changed deployment canary')
        with self.assertRaisesRegex(ValueError, 'differ only'):
            self.engine.plan(self.COMMIT)
        with self.assertRaisesRegex(ValueError, 'unavailable locally'):
            self.engine.plan('b' * 40)
        self.https.assert_not_called()

    def test_patch_crash_leaves_durable_reconciliation_and_no_retry(self):
        approved = self.approve()
        self.crash = True
        with self.assertRaises(SimulatedCrash):
            self.apply(approved)
        restarted = self.restart()
        self.assertEqual(restarted.status(reconcile=True)['observation'], 'MATCHES_DESIRED')
        self.assertEqual(restarted.status()['state'], 'APPLYING')
        with self.assertRaisesRegex(ValueError, 'Unresolved deployment'):
            restarted.apply(self.COMMIT, approved, authorize_write=True)
        self.assertEqual(len(self.patches()), 1)

    def test_committed_source_and_query_are_pinned(self):
        query = CANARY_ARTIFACTS[2]
        self.commit_files[query] = self.commit_files[query].replace(b'canary-synthetic', b'other-synthetic')
        with self.assertRaisesRegex(ValueError, 'Unexpected canary query or source'):
            self.engine.plan(self.COMMIT)
        self.https.assert_not_called()

    def test_404_blocks_and_never_creates_canary(self):
        self.get_status = 404
        with self.assertRaisesRegex(ValueError, 'HTTP 404'):
            self.engine.plan(self.COMMIT)
        self.assertEqual(self.requests, [('GET', self.GET, None)])
