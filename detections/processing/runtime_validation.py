"""Reviewed local runtime tools. Default modes cannot modify live resources.

No resource setup, configuration patch, permission change or key-management API
is implemented. Live warm-up/ingestion require separate approval AND CLI opt-in.
"""
import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import subprocess
import time
import uuid

from execution_verifier import assess_runtime
from runtime_client import ALERTS, INDEX, ROOT, RULE, Client, Stop
from runtime_fixtures import build_fixtures, create_bulk, timestamp

STORE = ROOT / 'infra/certs/validation'
FIELDS = ('query', 'type', 'language', 'version', 'interval', 'from', 'to',
          'severity', 'risk_score', 'severity_mapping', 'risk_score_mapping', 'actions', 'max_signals')
GAP = re.compile(r'^(?:an?|\d+) (?:millisecond|second|minute|hour|day)s? \(\d+ms\) were not queried '
                 r'between this rule execution and the last execution, so signals may have been missed\. '
                 r'Consider increasing your look behind time or adding more Kibana instances$')


def now():
    return datetime.now(timezone.utc)


def ensure(condition, reason):
    if not condition:
        raise Stop(reason)


def field(doc, dotted):
    if dotted in doc:
        return doc[dotted]
    value = doc
    for part in dotted.split('.'):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def scalar(value):
    return value[0] if isinstance(value, list) and len(value) == 1 else value


def normalize(value):
    if isinstance(value, dict):
        return {k: normalize(v) for k, v in value.items()
                if not (k == 'allow_restricted_indices' and v is False)
                and not (k == 'run_as' and v == [])}
    if isinstance(value, list):
        return sorted((normalize(v) for v in value), key=lambda v: json.dumps(v, sort_keys=True))
    return value


def write_evidence(name, value):
    """Create new ignored evidence or atomically replace this run's checkpoint."""
    ensure(re.fullmatch(r'[A-Za-z0-9_.-]+\.json', name) is not None, 'Invalid evidence filename')
    STORE.mkdir(parents=True, exist_ok=True, mode=0o700)
    # No arbitrary output path; callers use a UUID per invocation, never old run names.
    path = STORE / name
    import os
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, 'w') as output:
            json.dump(value, output, indent=2)
            output.write('\n')
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()
    return path


def rule(client):
    return client.call('kb', '/api/detection_engine/rules?rule_id=' + RULE)


def identity(client, rule_id, *, require_owner):
    reviewed = json.loads((ROOT / 'infra/security/p1_detection_operator.role.json').read_text())
    actual = client.call('kb', '/api/security/role/p1_detection_operator', admin=True)
    ensure(all(normalize(actual.get(k)) == normalize(reviewed[k]) for k in ('elasticsearch', 'kibana')),
           'Role no longer matches reviewed scope')
    roles = client.call('es', '/_security/role/p1_detection_operator', admin=True)
    keys = client.call('es', '/_security/api_key?username=p1_detection_operator&with_limited_by=true&active_only=true', admin=True)
    candidates = keys.get('api_keys', [])
    ensure(all(k.get('username') == 'p1_detection_operator' and not k.get('invalidated')
               and not k.get('role_descriptors') and normalize(k.get('limited_by')) == normalize([roles])
               for k in candidates), 'API-key privilege snapshot differs from reviewed role')
    alerting = client.call('kb', '/api/alerting/rule/' + rule_id)
    owner = alerting.get('api_key_owner')
    if require_owner:
        ensure(owner == 'p1_detection_operator' and bool(candidates), 'Execution owner/scope unconfirmed')
    return {'owner': owner, 'role_matches_reviewed': True,
            'candidate_key_count': len(candidates), 'exact_current_key_id_confirmed': False}


def preflight(client, *, enabled):
    r = rule(client)
    ensure(r['enabled'] is enabled, 'Unexpected enabled state')
    reviewed = json.loads(subprocess.check_output(
        ['ruby', str(ROOT/'detections/processing/export_rule.rb'),
         str(ROOT/'detections/rules/P1-PS-001_Office_Encoded_PowerShell.yml')]))
    ensure(all(r.get(k) == reviewed[k] for k in FIELDS), 'Rule configuration differs from local artifact')
    health = client.call('es', '/_cluster/health', admin=True)
    shards = client.call('es', '/_cat/shards?format=json&h=index,prirep,state', admin=True)
    unassigned = [s for s in shards if s['state'] == 'UNASSIGNED']
    known = {'.ds-.lists-default-2026.11.13-000001', '.ds-.items-default-2026.11.13-000001'}
    ensure(health['status'] in ('green', 'yellow') and
           all(s['state'] == 'STARTED' for s in shards if s['prirep'] == 'p') and
           (not unassigned or len(unassigned) == 2 and {s['index'] for s in unassigned} == known
            and all(s['prirep'] == 'r' for s in unassigned)), 'Unexpected cluster/shard health')
    kb = client.call('kb', '/api/status')
    ensure(kb['status']['overall']['level'] == 'available', 'Kibana unavailable')
    return r, identity(client, r['id'], require_owner=enabled)


def alerts(client):
    response = client.call('es', '/' + ALERTS + '/_search', {
        'size': 100, 'track_total_hits': True, 'query': {'term': {'kibana.alert.rule.rule_id': RULE}},
        '_source': ['event.id', 'kibana.alert.severity', 'kibana.alert.risk_score', 'kibana.alert.ancestors']})
    ensure(response['hits']['total']['value'] <= 100, 'Alert result truncated')
    return response['hits']['hits']


def source_versions(client, ids):
    response = client.call('es', '/' + INDEX + '/_search', {
        'size': 50, 'version': True, 'query': {'ids': {'values': list(ids)}},
        '_source': ['@timestamp', 'event.id']})
    return {h['_id']: {'index': h['_index'], 'version': h['_version'],
                       'timestamp': h['_source']['@timestamp']} for h in response['hits']['hits']}


def verify_alerts(hits, bundle, baseline=()):
    """Check actual fields/source references; never substitute Python priority."""
    expected, ids = bundle['expected'], bundle['source_ids']
    actual, rows = {}, []
    baseline = set(baseline)
    ensure(baseline <= {h['_id'] for h in hits}, 'Existing alert disappeared')
    for hit in hits:
        if hit['_id'] in baseline:
            continue
        doc = hit['_source']
        event_id = scalar(field(doc, 'event.id'))
        if event_id not in expected:
            matches = {ids[a['id']] for a in field(doc, 'kibana.alert.ancestors') or [] if a.get('id') in ids}
            ensure(len(matches) == 1, 'Unexpected or untraceable alert source')
            event_id = next(iter(matches))
        ensure(event_id in expected and event_id not in actual, 'Excluded source or duplicate alert')
        severity, risk = field(doc, 'kibana.alert.severity'), field(doc, 'kibana.alert.risk_score')
        ensure((severity, risk) == (expected[event_id]['severity'], expected[event_id]['risk_score']),
               'Actual alert severity/risk override mismatch')
        actual[event_id] = hit['_id']
        rows.append({'event_id': event_id, 'alert_id': hit['_id'], 'severity': severity,
                     'risk_score': risk, 'category': expected[event_id]['category']})
    ensure(set(actual) == set(expected), 'Missing expected alerts')
    return rows


def execution_runs(client, rule_id, since, *, allow_first_gap=False, until=None):
    bounds = {'gte': since}
    if until is not None:
        bounds['lte'] = until
    response = client.call('es', '/.kibana-event-log-*/_search', {
        'size': 100, 'track_total_hits': True, 'sort': [{'@timestamp': 'asc'}],
        'query': {'bool': {'filter': [
            {'nested': {'path': 'kibana.saved_objects', 'query': {'term': {'kibana.saved_objects.id': rule_id}}}},
            {'range': {'@timestamp': bounds}}]}},
        '_source': ['@timestamp', 'event', 'message', 'error.message',
                    'kibana.alert.rule.execution', 'kibana.alerting', 'kibana.task']}, admin=True)
    ensure(response['hits']['total']['value'] <= 100, 'Execution history truncated')
    groups = {}
    for hit in response['hits']['hits']:
        e = hit['_source']
        ensure(not field(e, 'error.message'), 'Task recorded an error')
        uid = field(e, 'kibana.alert.rule.execution.uuid')
        if uid:
            groups.setdefault(uid, []).append(e)
    runs = []
    for events in groups.values():
        statuses = [e for e in events if e.get('event', {}).get('action') == 'status-change']
        for e in statuses:
            status = field(e, 'kibana.alert.rule.execution.status')
            if status in ('failed', 'partial failure'):
                ensure(allow_first_gap and not runs and status == 'failed'
                       and GAP.fullmatch(e.get('message', '')), 'Repeated gap or other execution error')
        completed = [e for e in events if e.get('event', {}).get('provider') == 'alerting'
                     and e['event'].get('action') == 'execute']
        if not completed:
            continue
        task = completed[-1]
        ensure(task['event'].get('outcome') == 'success'
               and field(task, 'kibana.alerting.status') == 'ok', 'Scheduled task failed')
        ensure(bool(statuses), 'Missing detection outcome')
        final = statuses[-1]
        status, message = field(final, 'kibana.alert.rule.execution.status'), final.get('message', '')
        gap = bool(status == 'failed' and GAP.fullmatch(message))
        ensure(status == 'succeeded' and message in ('', 'Rule execution completed successfully')
               or allow_first_gap and not runs and gap, 'Unrecognized detection outcome')
        runs.append({'start': task['event']['start'], 'end': task['event']['end'],
                     'status': status, 'historical_gap': gap, 'task_outcome': 'success',
                     'message': message})
    return runs


def verify_overlap(runs, versions, visible_at):
    ensure(bool(versions), 'Source snapshot is empty')
    ensure(len(runs) == 2 and all(r['status'] == 'succeeded' for r in runs), 'Two clean runs required')
    ensure(timestamp(runs[1]['start']) > timestamp(runs[0]['start']), 'Distinct ordered runs required')
    for run in runs:
        end = timestamp(run['start'])
        ensure(timestamp(visible_at) < end, 'Source visibility before search not established')
        ensure(all(end - timedelta(minutes=7) < timestamp(v['timestamp']) <= end for v in versions.values()),
               'Same sources not inside both actual-start-derived windows; overlap inconclusive')


def disable(client, ledger):
    client.call('kb', '/api/detection_engine/rules', {'rule_id': RULE, 'enabled': False}, method='PATCH')
    r = rule(client)
    ensure(r['enabled'] is False, 'Final disable not confirmed')
    ledger['disabled'] = True
    ledger['disable_at'] = r['updated_at']


def warmup(client, *, allow_gap=False):
    ledger = {'mode': 'warmup', 'runs': [], 'passed': False, 'historical_coverage_recovered': False}
    name = 'warmup-' + uuid.uuid4().hex + '.json'
    ledger['evidence_file'] = 'infra/certs/validation/' + name
    activated = False
    try:
        r, _ = preflight(client, enabled=False)
        baseline = {h['_id'] for h in alerts(client)}
        activated = True  # also attempt disable after an ambiguous enable response
        enabled = client.call('kb', '/api/detection_engine/rules', {'rule_id': RULE, 'enabled': True}, method='PATCH')
        ensure(enabled['enabled'] is True and enabled['updated_by'] == 'p1_detection_operator', 'Activation not confirmed')
        ledger['activation_at'] = enabled['updated_at']
        write_evidence(name, ledger)
        while True:
            ensure(rule(client)['enabled'] is True, 'Rule unexpectedly disabled')
            ledger['identity'] = identity(client, r['id'], require_owner=True)
            runs = execution_runs(client, r['id'], ledger['activation_at'], allow_first_gap=allow_gap)
            ledger['runs'] = runs
            for run in runs:
                ensure(timestamp(run['start']) > timestamp(ledger['activation_at']), 'Stale execution')
            checkpoint = runs[0]['start'] if runs else ledger['activation_at']
            # The first execution must also be within its activation bound.
            if runs:
                ensure(timestamp(runs[0]['end']) <= timestamp(ledger['activation_at']) + timedelta(seconds=420),
                       'First execution outside activation bound')
            if len(runs) >= 2:
                ensure(len(runs) == 2 and not runs[1]['historical_gap'], 'Unexpected extra execution or repeated gap')
                assessment = assess_runtime({'last_execution': {'date': runs[1]['end'],
                    'status': runs[1]['status'], 'message': runs[1]['message']}},
                    activation_at=checkpoint, observed_at=now().isoformat(), timeout_seconds=420)
                ensure(assessment[0] == 'passed', 'Subsequent execution did not pass within seven minutes')
                ensure({h['_id'] for h in alerts(client)} == baseline, 'Unexpected alerts during warm-up')
                preflight(client, enabled=True)
                ledger['passed'] = True
                ledger['paused_before_ingestion'] = True
                break
            if (now() - timestamp(checkpoint)).total_seconds() >= 420:
                ledger['outcome'] = 'inconclusive'
                raise Stop('No qualifying execution within bounded wait')
            write_evidence(name, ledger)
            print('PENDING | Waiting for next scheduled execution; no ingestion', flush=True)
            time.sleep(10)
    except Stop as error:
        ledger.setdefault('outcome', 'failed')
        ledger['stop_reason'] = str(error)
        raise
    finally:
        try:
            if activated and not ledger['passed']:
                disable(client, ledger)
        finally:
            write_evidence(name, ledger)
    return ledger


def ingest(client):
    """Existing stream only; exactly one new batch, no setup/refresh/retry paths."""
    name = 'runtime-' + uuid.uuid4().hex + '.json'
    ledger = {'mode': 'ingest', 'passed': False, 'runs': [], 'snapshots': [],
              'evidence_file': 'infra/certs/validation/' + name}
    try:
        r, ledger['identity'] = preflight(client, enabled=True)
        ensure((r.get('execution_summary') or {}).get('last_execution', {}).get('status') == 'succeeded',
               'A clean execution gate is required before ingestion')
        baseline = alerts(client)
        ledger['baseline_alert_ids'] = [h['_id'] for h in baseline]
        baseline_count = client.call('es', '/' + INDEX + '/_count')['count']
        mappings = client.call('es', '/' + INDEX + '/_mapping')
        reviewed = json.loads((ROOT/'detections/mappings'/f'{INDEX}.json').read_text())
        ensure(all(v['mappings']['properties'] == reviewed['mappings']['properties']
                   and v['mappings'].get('_data_stream_timestamp', {}).get('enabled') for v in mappings.values()),
               'Source mapping differs from reviewed mapping')
        settings = client.call('es', '/' + INDEX + '/_settings?flat_settings=true')
        ensure(all(v['settings']['index.number_of_shards'] == '1'
                   and v['settings']['index.number_of_replicas'] == '0' for v in settings.values()),
               'Source shard settings changed')
        alerting = client.call('kb', '/api/alerting/rule/' + r['id'])
        target = timestamp(alerting['next_run']) - timedelta(seconds=30)
        if target < now() + timedelta(seconds=10):
            target += timedelta(minutes=5)
        ensure((target-now()).total_seconds() <= 330, 'Unexpected alignment wait')
        while now() < target:
            preflight(client, enabled=True)
            time.sleep(min(10, max(0.1, (target-now()).total_seconds())))
        preflight(client, enabled=True)
        bundle = build_fixtures('runtime-' + uuid.uuid4().hex, (now()-timedelta(seconds=1)).isoformat())
        ledger['bundle'] = bundle
        ensure(not source_versions(client, bundle['source_ids']), 'New fixture IDs collide')
        ensure(all(now()-timedelta(minutes=7) < timestamp(e['@timestamp']) <= now()
                   for e in bundle['prepared_events']), 'Fixtures outside active window')
        ledger['ingested_at'] = now().isoformat()
        write_evidence(name, ledger)
        bulk = client.call('es', '/' + INDEX + '/_bulk', create_bulk(bundle), admin=True)
        ledger['bulk_statuses'] = [item['create']['status'] for item in bulk['items']]
        write_evidence(name, ledger)
        ensure(not bulk.get('errors') and ledger['bulk_statuses'] == [201]*29, 'Bulk failed; no retry permitted')
        visibility_deadline = time.monotonic()+45
        while True:
            versions = source_versions(client, bundle['source_ids'])
            if len(versions) == 29:
                break
            ensure(time.monotonic() < visibility_deadline, 'Ordinary refresh visibility timed out')
            time.sleep(1)
        ledger['source_versions'] = versions
        ledger['visible_at'] = now().isoformat()
        ensure(client.call('es', '/' + INDEX + '/_count')['count'] == baseline_count+29,
               'Unexpected source count change')
        while now() <= timestamp(ledger['ingested_at']) + timedelta(seconds=720):
            preflight(client, enabled=True)
            runs = execution_runs(client, r['id'], ledger['ingested_at'])
            ledger['runs'] = runs
            if len(runs) > len(ledger['snapshots']):
                run = runs[len(ledger['snapshots'])]
                # An observed run after the bound must not yield a successful test.
                ensure(timestamp(run['end']) <= timestamp(ledger['ingested_at']) + timedelta(seconds=720),
                       'Scheduled execution outside fixture test bound')
                visibility_deadline = time.monotonic()+45
                while True:
                    hits = alerts(client)
                    if len(hits) >= len(baseline)+14:
                        break
                    ensure(time.monotonic() < visibility_deadline, 'Expected alerts not visible')
                    ensure(now() <= timestamp(ledger['ingested_at']) + timedelta(seconds=720), 'Fixture bound expired')
                    time.sleep(2)
                rows = verify_alerts(hits, bundle, ledger['baseline_alert_ids'])
                ledger['snapshots'].append(rows)
                write_evidence(name, ledger)
                print('PASS | Scheduled snapshot: 6 Medium/47, 8 High/73, 15 exclusions; 2 known FPs', flush=True)
            if len(ledger['snapshots']) == 2:
                ensure(now() <= timestamp(ledger['ingested_at']) + timedelta(seconds=720), 'Fixture bound expired')
                verify_overlap(runs[:2], versions, ledger['visible_at'])
                ensure({row['alert_id'] for row in ledger['snapshots'][0]} ==
                       {row['alert_id'] for row in ledger['snapshots'][1]}, 'Alert IDs changed between overlapping runs')
                ensure(source_versions(client, bundle['source_ids']) == versions, 'Source versions changed')
                ledger['passed'] = True
                break
            time.sleep(10)
        ensure(ledger['passed'], 'No two qualifying overlapping executions within bound')
    except Stop as error:
        ledger['outcome'] = 'failed'
        ledger['stop_reason'] = str(error)
        raise
    finally:
        try:
            disable(client, ledger)
        finally:
            write_evidence(name, ledger)
    return ledger


def load_result(path):
    """Accept new ledgers and the original sanitized Day 2 retained evidence."""
    result = json.loads(Path(path).read_text())
    if 'bundle' in result:
        return result
    run_id = result['run_id']
    ensure(re.fullmatch(r'[A-Za-z0-9_-]{8,80}', run_id) is not None, 'Invalid retained run ID')
    prepared = json.loads((Path(path).parent / (run_id+'-prepared.json')).read_text())
    result['bundle'] = {'expected': result['expected_matches'], 'excluded': result['excluded_event_ids'],
                        'source_ids': {e['p1'].get('document_id') or 'unknown-'+e['event']['id']: e['event']['id']
                                       for e in prepared}}
    # These are expected historical run references; audit() rechecks actual event statuses.
    result['runs'] = result['executions']
    result['snapshots'] = [[{'alert_id': value} for value in r['alert_ids']] for r in result['executions']]
    result['visible_at'] = result['ordinary_refresh_visible_at']
    result['ingested_at'] = result['ingestion_started_at']
    result['baseline_alert_ids'] = []
    return result


def audit(client, path):
    result = load_result(path)
    r = rule(client)
    ensure(r['enabled'] is False, 'Recording audit expects disabled rule')
    rows = verify_alerts(alerts(client), result['bundle'], result.get('baseline_alert_ids', ()))
    ensure(source_versions(client, result['bundle']['source_ids']) == result['source_versions'],
           'Source identities/versions differ from retained snapshot')
    runs = execution_runs(client, r['id'], result['ingested_at'], until=result.get('disable_at'))
    selected = [next((run for run in runs if run['start'] == recorded['start']), None)
                for recorded in result['runs'][:2]]
    ensure(all(selected), 'Historical execution not found')
    verify_overlap(selected, result['source_versions'], result['visible_at'])
    ids = {row['alert_id'] for row in rows}
    ensure(len(result['snapshots']) == 2 and all({row['alert_id'] for row in snap} == ids
           for snap in result['snapshots']), 'Per-run snapshots disagree with live alerts')
    ensure(rule(client)['enabled'] is False, 'Rule state changed during audit')
    return {'disabled': True, 'medium_47': 6, 'high_73': 8, 'excluded': 15,
            'false_positives': [row for row in rows if row['category'] == 'false_positive'],
            'same_14_alert_ids': sorted(ids), 'runs': selected,
            'window_evidence': 'Derived from actual execution starts, not individual request traces',
            'snapshot_evidence': 'Retained per-run snapshots corroborated by current live reads'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('fixtures', 'status', 'audit', 'warmup', 'ingest'))
    parser.add_argument('--run-id')
    parser.add_argument('--anchor')
    parser.add_argument('--evidence', type=Path)
    parser.add_argument('--allow-live-writes', action='store_true')
    parser.add_argument('--confirm-rule')
    parser.add_argument('--allow-first-historical-gap', action='store_true')
    args = parser.parse_args(argv)
    if args.mode in ('warmup', 'ingest') and not (args.allow_live_writes and args.confirm_rule == RULE):
        parser.error('Live mode requires separate approval, --allow-live-writes and --confirm-rule P1-PS-001')
    if args.allow_first_historical_gap and args.mode != 'warmup':
        parser.error('Historical-gap exception is only available for warmup')
    try:
        if args.mode == 'fixtures':
            ensure(args.run_id is not None and args.anchor is not None, 'Offline fixtures require run ID and anchor')
            print(json.dumps(build_fixtures(args.run_id, args.anchor), indent=2))
            return
        if args.mode == 'audit':
            ensure(args.evidence is not None, 'Audit requires retained evidence')
        writes = ('enable', 'disable') if args.mode == 'warmup' else ('ingest', 'disable') if args.mode == 'ingest' else ()
        client = Client(writes=writes)
        if args.mode == 'status':
            r, ident = preflight(client, enabled=False)
            result = {'disabled': not r['enabled'], 'identity': ident,
                      'schedule': [r['interval'], r['from'], r['to']], 'alert_count': len(alerts(client))}
        elif args.mode == 'audit':
            result = audit(client, args.evidence)
        elif args.mode == 'warmup':
            result = warmup(client, allow_gap=args.allow_first_historical_gap)
        else:
            result = ingest(client)
        # Never print bundles, raw HTTP responses, key metadata or exception strings.
        if args.mode in ('warmup', 'ingest'):
            result = {k: result[k] for k in ('mode', 'passed', 'disabled', 'paused_before_ingestion',
                                             'evidence_file') if k in result}
        print(json.dumps(result, indent=2))
    except Stop as error:
        print('STOP | ' + str(error))
        raise SystemExit(1) from None
    except Exception:
        print('STOP | Validation could not complete; sensitive error details suppressed')
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
