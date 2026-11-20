"""Exercise deployment transitions with an in-memory store and no credentials."""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from threading import Barrier, Lock
import unittest

from detections.processing.deployment_plan import RULE_ID
from detections.processing import deployment_state as deploy


class FakeRuleStore:
    rule_id = RULE_ID

    def __init__(self):
        self.target = 'fake-lab/default'
        self.state = None
        self.writes = []
        self.mutex = Lock()
        self.lose_response = False
        self.wrong_acknowledgement = False
        self.unexpected_settings = False

    def lock(self):
        return self.mutex

    def read(self, rule_id):
        assert rule_id == RULE_ID
        if self.unexpected_settings:
            raise ValueError('Unexpected rule settings')
        return deepcopy(self.state)

    def create(self, rule_id, payload):
        assert self.state is None
        return self._write('create', rule_id, 'rule-uuid', 0, payload)

    def update(self, rule_id, uuid, payload, before):
        assert self.state['id'] == uuid and self.state['payload'] == before
        return self._write('update', rule_id, uuid, self.state['revision'] + 1, payload)

    def _write(self, operation, rule_id, uuid, revision, payload):
        assert rule_id == RULE_ID and self.mutex.locked()
        assert payload['enabled'] is False and payload['actions'] == []
        self.writes.append(operation)
        self.state = {'id': uuid, 'revision': revision, 'payload': deepcopy(payload)}
        if self.lose_response:
            raise TimeoutError()
        return uuid, revision + int(self.wrong_acknowledgement)


class DeploymentStateTests(unittest.TestCase):
    def setUp(self):
        self.store = FakeRuleStore()
        self.old = {'rule_id': RULE_ID, 'enabled': False, 'actions': [], 'version': 1}
        self.new = {**self.old, 'version': 2}

        def artifact(commit, *, baseline=False):
            payload = {'old': self.old, 'new': self.new}[commit]
            return {'payload': deepcopy(payload), 'plan_sha256': deploy.digest(payload)}

        self.store.artifact = artifact

    def approval(self, commit, previous=None):
        return deploy.digest(deploy.plan(self.store, commit, previous))

    def install_baseline(self):
        return deploy.apply(self.store, 'old', self.approval('old'))

    def test_create_then_fresh_plan_is_noop_and_rollback_retains_create(self):
        receipt = self.install_baseline()
        self.assertEqual(deploy.verify(self.store, receipt)['revision'], 0)
        repeated = deploy.apply(self.store, 'old', self.approval('old'))
        self.assertEqual(repeated['plan']['action'], 'noop')
        self.assertEqual(deploy.rollback(self.store, receipt, deploy.digest(receipt)), receipt['after'])
        self.assertEqual(self.store.writes, ['create'])

    def test_update_and_rollback_preserve_identity_and_advance_revision(self):
        original = self.install_baseline()
        receipt = deploy.apply(self.store, 'new', self.approval('new', 'old'), 'old')
        self.assertEqual(receipt['after']['payload'], self.new)
        self.assertEqual(receipt['after']['id'], original['after']['id'])
        restored = deploy.rollback(self.store, receipt, deploy.digest(receipt))
        self.assertEqual(restored['payload'], self.old)
        self.assertEqual(restored['id'], original['after']['id'])
        self.assertEqual(restored['revision'], 2)
        self.assertEqual(self.store.writes, ['create', 'update', 'update'])

    def test_update_requires_approved_matching_baseline(self):
        self.install_baseline()
        with self.assertRaisesRegex(ValueError, 'no approved baseline'):
            deploy.plan(self.store, 'new')
        self.store.state['payload']['version'] = 3
        with self.assertRaisesRegex(ValueError, 'drifted'):
            deploy.plan(self.store, 'new', 'old')
        self.assertEqual(self.store.writes, ['create'])

    def test_stale_uuid_revision_or_target_blocks_apply(self):
        self.install_baseline()
        original = deepcopy(self.store.state)
        approved = self.approval('new', 'old')
        for change in ({'revision': 5}, {'id': 'replacement'}, {}):
            with self.subTest(change=change):
                self.store.state = {**deepcopy(original), **change}
                if not change:
                    self.store.target = 'other-lab/default'
                with self.assertRaisesRegex(ValueError, 'Plan changed'):
                    deploy.apply(self.store, 'new', approved, 'old')
        self.assertEqual(self.store.writes, ['create'])

    def test_stale_rollback_and_unapproved_rollback_refuse_to_write(self):
        self.install_baseline()
        receipt = deploy.apply(self.store, 'new', self.approval('new', 'old'), 'old')
        with self.assertRaisesRegex(ValueError, 'approval'):
            deploy.rollback(self.store, receipt, 'unapproved')
        self.store.state['revision'] += 1
        with self.assertRaisesRegex(ValueError, 'drifted'):
            deploy.rollback(self.store, receipt, deploy.digest(receipt))
        self.assertEqual(self.store.writes, ['create', 'update'])

    def test_enabled_rule_or_unexpected_settings_block_operation(self):
        self.install_baseline()
        self.store.state['payload']['enabled'] = True
        with self.assertRaisesRegex(ValueError, 'disabled'):
            deploy.plan(self.store, 'old')
        self.store.unexpected_settings = True
        with self.assertRaisesRegex(ValueError, 'Unexpected rule settings'):
            deploy.plan(self.store, 'old')
        self.assertEqual(self.store.writes, ['create'])

    def test_ambiguous_write_has_no_receipt_or_retry(self):
        artifact = self.store.artifact
        for mode in ('lose_response', 'wrong_acknowledgement'):
            with self.subTest(mode=mode):
                self.store = FakeRuleStore()
                self.store.artifact = artifact
                setattr(self.store, mode, True)
                with self.assertRaisesRegex(deploy.WriteOutcomeUnknown, 'Reconcile'):
                    self.install_baseline()
                self.assertEqual(self.store.writes, ['create'])
                self.assertEqual(self.store.state['payload'], self.old)

    def test_second_writer_with_same_create_approval_cannot_write(self):
        approved = self.approval('old')
        start = Barrier(2)

        def apply_same_plan():
            start.wait(timeout=5)
            try:
                return deploy.apply(self.store, 'old', approved)['plan']['action']
            except ValueError as error:
                return str(error)

        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(apply_same_plan)
            second = pool.submit(apply_same_plan)
            self.assertCountEqual(
                [first.result(timeout=5), second.result(timeout=5)],
                ['create', 'Plan changed or approval does not match'],
            )
        self.assertEqual(self.store.writes, ['create'])
