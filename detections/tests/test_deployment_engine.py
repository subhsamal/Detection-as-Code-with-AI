"""Controlled deployment against a fake Kibana 8.13 single-rule exchange."""

from copy import deepcopy
import json
import os
from pathlib import Path
import stat
import subprocess
from tempfile import TemporaryDirectory
from threading import Lock
import unittest
from unittest.mock import patch

from detections.processing import deployment_engine, deployment_plan, deployment_state


class SimulatedCrash(BaseException):
    pass


class DeploymentEngineTests(unittest.TestCase):
    UUID = '72ab56fa-f3a1-4c84-8466-a0b23b2254ea'
    PATCH = '/s/canary/api/detection_engine/rules'
    GET = PATCH + '?rule_id=P1-PS-001'

    @classmethod
    def setUpClass(cls):
        cls.commit = subprocess.check_output(
            ['git', 'rev-parse', 'HEAD'], cwd=deployment_plan.ROOT, text=True,
        ).strip()
        cls.artifact = deployment_plan.build_plan(cls.commit)

    def setUp(self):
        self.before = deepcopy(self.artifact['payload'])
        self.changed = {**self.before, 'description': 'Mocked approved revision'}
        self.remote = {
            **self.before, 'id': self.UUID, 'revision': 3,
            'immutable': False, 'output_index': '',
        }
        self.calls = []
        self.lock = Lock()
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.journal_file = self.directory / 'deployment-journal.json'
        self.engine = self.restart()
        self.read_status = 200
        self.patch_status = 200
        self.lose_ack = False
        self.readback_drift = False
        self.crash_after_patch = False

    def restart(self):
        return self.engine_for_target('mock')

    def engine_for_target(self, target):
        store = deployment_engine._KibanaStore(target, 'canary', self.UUID, self.exchange, self.lock)
        return deployment_engine._DeploymentEngine(store, self.directory)

    def exchange(self, method, path, body):
        self.calls.append((method, path, deepcopy(body)))
        if method == 'GET':
            self.assertEqual((path, body), (self.GET, None))
            return self.read_status, json.dumps(self.remote)
        self.assertEqual((method, path), ('PATCH', self.PATCH))
        self.assertTrue(self.lock.locked())
        self.assertEqual(self.records()[-1]['states'], ['PREPARED', 'APPLYING'])
        self.assertEqual(body['id'], self.UUID)
        self.assertIs(body['enabled'], False)
        if self.patch_status != 200:
            return self.patch_status, 'untrusted error body'
        self.remote.update(body)
        self.remote['revision'] += 1
        if self.crash_after_patch:
            raise SimulatedCrash
        acknowledgement = json.dumps(self.remote)
        if self.lose_ack:
            raise TimeoutError('untrusted transport error')
        if self.readback_drift:
            self.remote['description'] = 'Concurrent remote update'
        return 200, acknowledgement

    def simulated_commit(self):
        approved = 'b' * 40
        changed = {**self.artifact, 'commit': approved, 'payload': self.changed}
        del changed['plan_sha256']
        changed['payload_sha256'] = deployment_state.digest(self.changed)
        changed['plan_sha256'] = deployment_state.digest(changed)

        def load(commit):
            if commit == approved:
                return deepcopy(changed)
            self.assertEqual(commit, self.commit)
            return deepcopy(self.artifact)

        patcher = patch.object(deployment_engine, 'build_plan', side_effect=load)
        patcher.start()
        self.addCleanup(patcher.stop)
        return approved

    def patch_requests(self):
        return [body for method, _, body in self.calls if method == 'PATCH']

    def records(self):
        return json.loads(self.journal_file.read_text())['data']['records']

    def test_real_commit_noop_and_receipt_verification_send_only_gets(self):
        plan = self.engine.plan(self.commit)
        self.assertEqual(plan['action'], 'noop')
        self.assertEqual(plan['artifact_plan_sha256'], self.artifact['plan_sha256'])
        receipt = self.engine.apply(self.commit, deployment_state.digest(plan), authorize_write=True)
        self.assertEqual(self.engine.verify(receipt, deployment_state.digest(receipt)), receipt['after'])
        self.assertEqual(self.patch_requests(), [])

    def test_apply_then_rollback_use_exact_fields_and_same_uuid(self):
        commit = self.simulated_commit()
        plan = self.engine.plan(commit, self.commit)
        receipt = self.engine.apply(commit, deployment_state.digest(plan), self.commit, authorize_write=True)
        self.assertEqual(receipt['plan']['before']['payload'], self.before)
        self.assertEqual(receipt['after']['payload'], self.changed)
        self.assertEqual(receipt['after']['revision'], 4)
        self.assertEqual(self.engine.verify(receipt, deployment_state.digest(receipt)), receipt['after'])
        with self.assertRaisesRegex(ValueError, 'authorization'):
            self.engine.rollback(receipt, deployment_state.digest(receipt))
        restored = self.engine.rollback(receipt, deployment_state.digest(receipt), authorize_write=True)
        self.assertEqual(restored['payload'], self.before)
        self.assertEqual((restored['id'], restored['revision']), (self.UUID, 5))
        self.assertEqual(self.patch_requests(), [
            {'id': self.UUID, 'enabled': False, 'description': self.changed['description']},
            {'id': self.UUID, 'enabled': False, 'description': self.before['description']},
        ])
        self.assertNotIn(self.before['query'], repr(self.engine.audit))
        self.assertNotIn(self.changed['description'], repr(self.engine.audit))
        applied, rolled_back = self.records()
        self.assertEqual(applied['states'], ['PREPARED', 'APPLYING', 'VERIFIED'])
        self.assertEqual(applied['commit'], commit)
        self.assertEqual(applied['artifact_sha256'], self.artifact['artifact_sha256'])
        self.assertEqual(applied['before'], receipt['plan']['before'])
        self.assertEqual(applied['result_sha256'], deployment_state.digest(receipt))
        self.assertEqual(rolled_back['commit'], self.commit)
        self.assertEqual(rolled_back['before'], receipt['after'])
        self.assertEqual(stat.S_IMODE(self.journal_file.stat().st_mode), 0o600)

    def test_write_authorization_plan_and_artifact_hash_are_required(self):
        commit = self.simulated_commit()
        plan = self.engine.plan(commit, self.commit)
        approved = deployment_state.digest(plan)
        with self.assertRaisesRegex(ValueError, 'authorization'):
            self.engine.apply(commit, approved, self.commit)
        plan['artifact_plan_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'Plan changed'):
            self.engine.apply(commit, deployment_state.digest(plan), self.commit, authorize_write=True)
        self.assertEqual(self.patch_requests(), [])

    def test_stale_revision_and_other_uuid_refuse_patch(self):
        commit = self.simulated_commit()
        approval = deployment_state.digest(self.engine.plan(commit, self.commit))
        self.remote['revision'] += 1
        with self.assertRaisesRegex(ValueError, 'Plan changed'):
            self.engine.apply(commit, approval, self.commit, authorize_write=True)
        self.remote['id'] = '82ab56fa-f3a1-4c84-8466-a0b23b2254ea'
        with self.assertRaisesRegex(ValueError, 'Unexpected rule UUID'):
            self.engine.plan(commit, self.commit)
        self.assertEqual(self.patch_requests(), [])

    def test_enabled_unsafe_drift_and_404_block_existing_rule_plan(self):
        commit = self.simulated_commit()
        self.remote['enabled'] = True
        with self.assertRaisesRegex(ValueError, 'disabled'):
            self.engine.plan(commit, self.commit)
        self.remote['enabled'] = False
        self.remote['timestamp_override'] = 'unexpected'
        with self.assertRaisesRegex(ValueError, 'Unknown Kibana'):
            self.engine.plan(commit, self.commit)
        del self.remote['timestamp_override']
        self.remote['description'] = 'unreviewed drift'
        with self.assertRaisesRegex(ValueError, 'drifted'):
            self.engine.plan(commit, self.commit)
        self.read_status = 404
        with self.assertRaisesRegex(ValueError, 'HTTP 200'):
            self.engine.plan(commit, self.commit)
        self.assertEqual(self.patch_requests(), [])

    def test_applied_plan_cannot_replay_and_fresh_plan_is_noop(self):
        commit = self.simulated_commit()
        approval = deployment_state.digest(self.engine.plan(commit, self.commit))
        self.engine.apply(commit, approval, self.commit, authorize_write=True)
        with self.assertRaisesRegex(ValueError, 'Plan changed'):
            self.engine.apply(commit, approval, self.commit, authorize_write=True)
        fresh = self.engine.plan(commit, self.commit)
        self.assertEqual(fresh['action'], 'noop')
        self.engine.apply(commit, deployment_state.digest(fresh), self.commit, authorize_write=True)
        self.assertEqual(len(self.patch_requests()), 1)

    def test_rollback_checks_receipt_provenance_and_current_state(self):
        commit = self.simulated_commit()
        approval = deployment_state.digest(self.engine.plan(commit, self.commit))
        receipt = self.engine.apply(commit, approval, self.commit, authorize_write=True)
        changed = deepcopy(receipt)
        changed['plan']['artifact_plan_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'committed artifacts'):
            self.engine.rollback(changed, deployment_state.digest(changed), authorize_write=True)
        self.remote['revision'] += 1
        with self.assertRaisesRegex(ValueError, 'drifted'):
            self.engine.rollback(receipt, deployment_state.digest(receipt), authorize_write=True)
        self.assertEqual(len(self.patch_requests()), 1)

    def test_patch_error_lost_ack_and_mismatched_readback_latch_without_retry(self):
        commit = self.simulated_commit()
        for failure in ('patch_status', 'lose_ack', 'readback_drift'):
            with self.subTest(failure=failure):
                self.setUp()
                approval = deployment_state.digest(self.engine.plan(commit, self.commit))
                setattr(self, failure, 409 if failure == 'patch_status' else True)
                with self.assertRaisesRegex(deployment_state.WriteOutcomeUnknown, 'Reconcile'):
                    self.engine.apply(commit, approval, self.commit, authorize_write=True)
                self.assertEqual(self.engine.audit[-1]['result'], 'UNCERTAIN')
                self.assertEqual(self.calls[-1][:2], ('GET', self.GET))
                with self.assertRaisesRegex(ValueError, 'Unresolved deployment journal'):
                    self.restart().apply(commit, approval, self.commit, authorize_write=True)
                self.assertEqual(len(self.patch_requests()), 1)

    def test_restart_after_patch_crash_only_reconciles_and_keeps_journal_unchanged(self):
        commit = self.simulated_commit()
        approved = deployment_state.digest(self.engine.plan(commit, self.commit))
        self.crash_after_patch = True
        with self.assertRaises(SimulatedCrash):
            self.engine.apply(commit, approved, self.commit, authorize_write=True)
        raw = self.journal_file.read_bytes()
        restarted = self.restart()
        self.assertEqual(restarted.status()['state'], 'APPLYING')
        for expected in ('MATCHES_DESIRED', 'DIVERGED', 'UNAVAILABLE_OR_UNSUPPORTED'):
            with self.subTest(expected=expected):
                if expected == 'DIVERGED':
                    self.remote['description'] = 'Mocked external edit'
                if expected == 'UNAVAILABLE_OR_UNSUPPORTED':
                    self.read_status = 403
                self.assertEqual(restarted.status(reconcile=True)['observation'], expected)
                self.assertEqual(self.journal_file.read_bytes(), raw)
        with self.assertRaisesRegex(ValueError, 'Unresolved deployment'):
            restarted.apply(commit, approved, self.commit, authorize_write=True)
        with self.assertRaisesRegex(ValueError, 'Only a PREPARED'):
            restarted.close_prepared(restarted.status()['record_sha256'], authorize_recovery=True)
        self.assertEqual(len(self.patch_requests()), 1)

    def test_restart_before_applying_requires_separately_approved_failed_transition(self):
        commit = self.simulated_commit()
        approved = deployment_state.digest(self.engine.plan(commit, self.commit))
        with patch.object(self.engine._journal, 'advance', side_effect=SimulatedCrash):
            with self.assertRaises(SimulatedCrash):
                self.engine.apply(commit, approved, self.commit, authorize_write=True)
        restarted = self.restart()
        report = restarted.status(reconcile=True)
        self.assertEqual((report['state'], report['observation']), ('PREPARED', 'MATCHES_BEFORE'))
        with self.assertRaisesRegex(ValueError, 'Unresolved deployment'):
            restarted.apply(commit, approved, self.commit, authorize_write=True)
        with self.assertRaisesRegex(ValueError, 'approval'):
            restarted.close_prepared(report['record_sha256'])
        with self.assertRaisesRegex(ValueError, 'digest'):
            restarted.close_prepared('0' * 64, authorize_recovery=True)
        calls = self.calls[:]
        restarted.close_prepared(report['record_sha256'], authorize_recovery=True)
        self.assertEqual(self.calls, calls)
        self.assertEqual(restarted.status()['state'], 'FAILED')
        self.assertFalse(restarted.status()['write_blocked'])
        self.assertEqual(self.patch_requests(), [])

    def test_failure_persisting_verified_state_is_uncertain_after_restart(self):
        commit = self.simulated_commit()
        approved = deployment_state.digest(self.engine.plan(commit, self.commit))
        save = self.engine._journal.save

        def fail_terminal(fd, binding, records):
            if records[-1]['states'][-1] == 'VERIFIED':
                raise OSError('mock persistence failure')
            return save(fd, binding, records)

        with patch.object(self.engine._journal, 'save', side_effect=fail_terminal):
            with self.assertRaisesRegex(deployment_state.WriteOutcomeUnknown, 'persist verified'):
                self.engine.apply(commit, approved, self.commit, authorize_write=True)
        report = self.restart().status(reconcile=True)
        self.assertEqual((report['state'], report['observation']), ('APPLYING', 'MATCHES_DESIRED'))
        self.assertEqual(len(self.patch_requests()), 1)

    def test_failed_atomic_applying_replace_preserves_prepared_file_and_sends_no_patch(self):
        commit = self.simulated_commit()
        approved = deployment_state.digest(self.engine.plan(commit, self.commit))
        replace = os.replace
        replacements = 0

        def fail_second_replace(*args, **kwargs):
            nonlocal replacements
            replacements += 1
            if replacements == 2:
                raise OSError('mock atomic replace failure')
            return replace(*args, **kwargs)

        with patch.object(os, 'replace', side_effect=fail_second_replace):
            with self.assertRaises(OSError):
                self.engine.apply(commit, approved, self.commit, authorize_write=True)
        self.assertEqual(self.restart().status()['state'], 'PREPARED')
        self.assertEqual(list(self.directory.iterdir()), [self.journal_file])
        self.assertEqual(self.patch_requests(), [])

    def test_corrupt_malformed_insecure_and_foreign_journals_fail_before_any_request(self):
        commit = self.simulated_commit()
        approved = deployment_state.digest(self.engine.plan(commit, self.commit))
        self.engine.apply(commit, approved, self.commit, authorize_write=True)
        raw = self.journal_file.read_bytes()
        corrupt = json.loads(raw)
        corrupt['data']['records'][0]['before']['revision'] += 1
        self.calls.clear()
        for invalid, diagnostic in ((b'{', 'Malformed'), (json.dumps(corrupt).encode(), 'checksum')):
            self.journal_file.write_bytes(invalid)
            with self.assertRaisesRegex(ValueError, diagnostic):
                self.restart().apply(commit, approved, self.commit, authorize_write=True)
        self.journal_file.write_bytes(raw)
        self.journal_file.chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'mode-0600'):
            self.restart().status(reconcile=True)
        self.journal_file.chmod(0o600)
        foreign = self.engine_for_target('other')
        with self.assertRaisesRegex(ValueError, 'binding mismatch'):
            foreign.status(reconcile=True)
        self.assertEqual(self.calls, [])
