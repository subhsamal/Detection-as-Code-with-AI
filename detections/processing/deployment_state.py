"""Deployment transitions for a normalized rule store. No Kibana transport."""

from copy import deepcopy

from detections.processing.deployment_plan import canonical, sha256
from scripts.ci.validate import require


class WriteOutcomeUnknown(RuntimeError):
    """A write was attempted. Stop and reconcile before planning another write."""


def digest(value):
    return sha256(canonical(value))


def read_rule(store):
    # The store supplies a complete managed projection and rejects unexpected
    # behavior settings before returning it. Absence must be an authoritative read.
    state = deepcopy(store.read(store.rule_id))
    if state is not None:
        require(isinstance(state['id'], str) and state['id'], 'Missing rule UUID')
        require(type(state['revision']) is int and state['revision'] >= 0, 'Invalid revision')
        payload = state['payload']
        require(payload['rule_id'] == store.rule_id, 'Unexpected rule identity')
        require(payload['enabled'] is False and payload['actions'] == [],
                'Rule must be disabled without actions')
    return state


def plan(store, commit, previous_commit=None):
    artifact = store.artifact(commit)
    desired = artifact['payload']
    before = read_rule(store)
    if before is None:
        require(previous_commit is None, 'Expected baseline rule is missing')
        action = 'create'
    elif canonical(before['payload']) == canonical(desired):
        action = 'noop'
    else:
        require(previous_commit is not None, 'Existing rule differs and has no approved baseline')
        previous = store.artifact(previous_commit, baseline=True)['payload']
        require(canonical(before['payload']) == canonical(previous), 'Existing rule drifted')
        require(previous.keys() == desired.keys(), 'Update would change the managed field set')
        action = 'update'
    return {
        'schema_version': 1, 'target': store.target, 'commit': commit,
        'artifact_plan_sha256': artifact['plan_sha256'], 'previous_commit': previous_commit,
        'action': action, 'before': before, 'desired': desired,
    }


def write_and_verify(store, before, payload):
    try:
        if before is None:
            acknowledgement = store.create(store.rule_id, deepcopy(payload))
        else:
            acknowledgement = store.update(store.rule_id, before['id'], deepcopy(payload), before['payload'])
        after = read_rule(store)
        require(after is not None and canonical(after['payload']) == canonical(payload),
                'Persisted configuration differs')
        require((after['id'], after['revision']) == acknowledgement,
                'Write acknowledgement and readback disagree')
        if before is not None:
            require(after['id'] == before['id'] and after['revision'] > before['revision'],
                    'Rule identity or revision did not advance as expected')
    except Exception:
        # Even a matching read cannot attribute a write after a lost acknowledgement.
        try:
            read_rule(store)
        except Exception:
            pass
        raise WriteOutcomeUnknown('Write outcome unverified. Reconcile rule state before retrying.') from None
    return after


def apply(store, commit, approved_plan_digest, previous_commit=None, *, before_write=None):
    with store.lock():
        current = plan(store, commit, previous_commit)
        require(digest(current) == approved_plan_digest, 'Plan changed or approval does not match')
        before = current['before']
        after = before
        if current['action'] != 'noop':
            if before_write is not None:
                before_write(current, before, current['desired'])
            after = write_and_verify(store, before, current['desired'])
        return {'plan': current, 'after': after}


def verify(store, receipt):
    require(store.target == receipt['plan']['target'], 'Receipt target differs')
    current = read_rule(store)
    require(current is not None and canonical(current) == canonical(receipt['after']),
            'Persisted rule has drifted')
    return current


def rollback(store, receipt, approved_receipt_digest, *, before_write=None):
    require(digest(receipt) == approved_receipt_digest, 'Rollback receipt approval does not match')
    with store.lock():
        current = verify(store, receipt)
        applied = receipt['plan']
        if applied['action'] == 'update':
            previous = store.artifact(applied['previous_commit'], baseline=True)['payload']
            require(canonical(previous) == canonical(applied['before']['payload']),
                    'Receipt baseline differs from committed artifacts')
            if before_write is not None:
                before_write(applied, current, previous)
            return write_and_verify(store, current, previous)
        require(applied['action'] in {'create', 'noop'}, 'Unknown receipt action')
        return current
