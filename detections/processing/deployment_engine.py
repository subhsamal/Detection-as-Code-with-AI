"""Approval-bound deployment transitions and the fixed canary engine."""

from re import fullmatch
from uuid import UUID

from detections.processing import deployment_state as state
from detections.processing.canary_profile import CANARY_PATCH_FIELDS, CANARY_SPACE
from detections.processing.canary_transport import _CanaryHTTPS
from detections.processing.deployment_journal import DeploymentJournal, UNRESOLVED
from detections.processing.deployment_plan import FIELDS, build_canary_plan, build_plan, canonical
from detections.processing.kibana_rule_reader import KibanaRuleReader, project_rule, rule_path
from scripts.ci.validate import require

PATCH_FIELDS = FIELDS - {'rule_id', 'type', 'language', 'enabled', 'actions'}


class _KibanaStore:
    def __init__(self, target, space, expected_uuid, exchange, lock, *, canary=False):
        self.reader = KibanaRuleReader(target, space, lambda path: exchange('GET', path, None), canary=canary)
        self.rule_id = self.reader.rule_id
        self._canary = canary
        self.target = self.reader.target
        self.expected_uuid = expected_uuid
        self.exchange = exchange
        self._lock = lock
        self._canary_patch = None
        self.patch_path = rule_path(space, canary=canary).partition('?')[0]

    def artifact(self, commit, *, baseline=False):
        if self._canary:
            return build_canary_plan(commit, baseline=baseline)
        return build_plan(commit)

    def lock(self):
        return self._lock

    def read(self, rule_id):
        observed = self.reader.read(rule_id)
        require(observed['id'] == self.expected_uuid, 'Unexpected rule UUID')
        return observed

    def update(self, rule_id, uuid, payload, before):
        require(rule_id == self.rule_id and uuid == self.expected_uuid, 'Unexpected patch identity')
        require(payload.keys() == before.keys(), 'Patch would change the managed field set')
        changes = {key: value for key, value in payload.items()
                   if canonical(value) != canonical(before[key])}
        allowed = CANARY_PATCH_FIELDS if self._canary else PATCH_FIELDS
        require(changes and changes.keys() <= allowed, 'Unsupported managed patch fields')
        require(payload['enabled'] is False and payload['actions'] == [],
                'Expected a disabled rule without actions')
        patch = {'id': uuid, 'enabled': False, **changes}
        if self._canary:
            require(patch == self._canary_patch, 'Canary PATCH differs from the journaled operation')
            self._canary_patch = None
            status, body = self.exchange('PATCH', self.patch_path, patch, authorize_write=True)
        else:
            status, body = self.exchange('PATCH', self.patch_path, patch)
        require(status == 200, 'Kibana patch did not return HTTP 200')
        acknowledged = project_rule(body, rule_id)
        require(canonical(acknowledged['payload']) == canonical(payload),
                'Kibana acknowledgement differs from approved payload')
        return acknowledged['id'], acknowledged['revision']


class _DeploymentEngine:
    def __init__(self, store, journal_directory):
        expected_uuid = store.expected_uuid
        require(isinstance(expected_uuid, str) and str(UUID(expected_uuid)) == expected_uuid,
                'Expected a canonical rule UUID')
        self._store = store
        self._journal = DeploymentJournal(journal_directory)
        self._binding = {'target': store.target, 'uuid': expected_uuid, 'rule_id': store.rule_id}
        self._audit = []

    @property
    def audit(self):
        return tuple(entry.copy() for entry in self._audit)

    def plan(self, commit, previous_commit=None):
        return state.plan(self._store, commit, previous_commit)

    def apply(self, commit, approved_plan_digest, previous_commit=None, *, authorize_write=False):
        return self._write('apply', approved_plan_digest, authorize_write,
                           lambda prepare: state.apply(self._store, commit, approved_plan_digest,
                                                       previous_commit, before_write=prepare))

    def verify(self, receipt, expected_receipt_digest):
        def inspect():
            self._check_receipt(receipt, expected_receipt_digest)
            return state.verify(self._store, receipt)

        return self._record('verify', expected_receipt_digest, inspect)

    def rollback(self, receipt, approved_receipt_digest, *, authorize_write=False):
        def restore(prepare):
            self._check_receipt(receipt, approved_receipt_digest)
            return state.rollback(self._store, receipt, approved_receipt_digest, before_write=prepare)

        return self._write('rollback', approved_receipt_digest, authorize_write, restore)

    def status(self, *, reconcile=False):
        """Read local status and optionally compare an unresolved record with one GET."""
        with self._journal.locked(shared=True) as fd:
            records = self._journal.load(fd, self._binding)
            if not records:
                return {'state': 'EMPTY', 'write_blocked': False}
            record = records[-1]
            latest = record['states'][-1]
            report = {
                'state': latest, 'write_blocked': latest in UNRESOLVED,
                'record_sha256': state.digest(record), 'operation': record['operation'],
            }
            if reconcile and latest in UNRESOLVED:
                report['observation'] = self._reconcile(record)
            return report

    def close_prepared(self, expected_record_digest, *, authorize_recovery=False):
        """Close a crash before APPLYING, through an explicitly approved local transition."""
        require(authorize_recovery is True, 'Explicit journal recovery approval required')
        with self._journal.locked() as fd:
            records = self._journal.load(fd, self._binding)
            require(records and records[-1]['states'][-1] == 'PREPARED',
                    'Only a PREPARED record can be closed without a write investigation')
            require(state.digest(records[-1]) == expected_record_digest, 'Recovery record digest differs')
            self._journal.advance(fd, self._binding, records, 'FAILED')

    def _reconcile(self, record):
        try:
            current = state.read_rule(self._store)
        except Exception:
            return 'UNAVAILABLE_OR_UNSUPPORTED'
        if canonical(current) == canonical(record['before']):
            return 'MATCHES_BEFORE'
        if (current['revision'] > record['before']['revision'] and
                canonical(current['payload']) == canonical(record['desired'])):
            return 'MATCHES_DESIRED'
        return 'DIVERGED'

    def _check_receipt(self, receipt, expected_digest):
        require(state.digest(receipt) == expected_digest, 'Receipt digest differs')
        plan = receipt['plan']
        artifact = self._store.artifact(plan['commit'])
        require(plan['artifact_plan_sha256'] == artifact['plan_sha256'] and
                canonical(plan['desired']) == canonical(artifact['payload']) and
                canonical(receipt['after']['payload']) == canonical(artifact['payload']),
                'Receipt differs from committed artifacts')
        require(plan['before']['id'] == receipt['after']['id'] == self._store.expected_uuid,
                'Receipt rule UUID differs')

    def _write(self, operation, approved_digest, authorize_write, action):
        def authorized():
            require(authorize_write is True, 'Explicit write authorization required')
            with self._journal.locked() as fd:
                records = self._journal.load(fd, self._binding)
                require(not records or records[-1]['states'][-1] not in UNRESOLVED,
                        'Unresolved deployment journal blocks writes')
                baseline = len(records)

                def prepare(plan, before, desired):
                    commit = plan['commit'] if operation == 'apply' else plan['previous_commit']
                    artifact = self._store.artifact(commit, baseline=operation == 'rollback')
                    require(canonical(artifact['payload']) == canonical(desired),
                            'Journal artifact differs from planned payload')
                    record = {
                        'operation': operation, 'approval_sha256': approved_digest,
                        'commit': commit, 'artifact_sha256': artifact['artifact_sha256'],
                        'artifact_plan_sha256': artifact['plan_sha256'],
                        'payload_sha256': artifact['payload_sha256'],
                        'plan_sha256': state.digest(plan), 'plan': plan,
                        'before': before, 'desired': desired, 'states': ['PREPARED'],
                    }
                    self._journal.save(fd, self._binding, [*records, record])
                    records.append(record)
                    self._journal.advance(fd, self._binding, records, 'APPLYING')
                    if self._store._canary:
                        self._store._canary_patch = {
                            'id': before['id'], 'enabled': False, 'interval': desired['interval'],
                        }

                try:
                    result = action(prepare)
                except state.WriteOutcomeUnknown:
                    try:
                        self._journal.advance(fd, self._binding, records, 'UNCERTAIN')
                    except (OSError, ValueError):
                        raise state.WriteOutcomeUnknown(
                            'Could not persist uncertain outcome. Reconcile the journal before retrying.'
                        ) from None
                    raise
                finally:
                    self._store._canary_patch = None
                if len(records) > baseline:
                    try:
                        self._journal.advance(fd, self._binding, records, 'VERIFIED',
                                              result_sha256=state.digest(result))
                    except (OSError, ValueError):
                        raise state.WriteOutcomeUnknown(
                            'Could not persist verified outcome. Reconcile the journal before retrying.'
                        ) from None
                return result

        return self._record(operation, approved_digest, authorized)

    def _record(self, operation, approved_digest, action):
        audit = {'operation': operation, 'result': 'BLOCKED'}
        if isinstance(approved_digest, str) and fullmatch(r'[a-f0-9]{64}', approved_digest):
            audit['approval_sha256'] = approved_digest
        try:
            result = action()
            audit['result'] = 'VERIFIED'
            audit['result_sha256'] = state.digest(result)
            return result
        except state.WriteOutcomeUnknown:
            audit['result'] = 'UNCERTAIN'
            raise
        finally:
            self._audit.append(audit)


class CanaryDeploymentEngine(_DeploymentEngine):
    """Fixed live-capable transport; tests replace the HTTPS connection with a mock."""

    def __init__(self, origin, ca_file, expected_uuid, password, lock, *, journal_directory):
        transport = _CanaryHTTPS(origin, ca_file, expected_uuid, password)
        store = _KibanaStore(transport.origin, CANARY_SPACE, expected_uuid,
                             transport._exchange, lock, canary=True)
        super().__init__(store, journal_directory)

    def plan(self, commit):
        return super().plan(commit, previous_commit=commit)

    def apply(self, commit, approved_plan_digest, *, authorize_write=False):
        return super().apply(commit, approved_plan_digest, previous_commit=commit,
                             authorize_write=authorize_write)
