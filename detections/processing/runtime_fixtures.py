"""Build the reviewed 29 inert cases offline; never execute PowerShell or HTTP."""
import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re

from powershell import prepare_events

ROOT = Path(__file__).resolve().parents[2]


def timestamp(value):
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.utcoffset() is None:
        raise ValueError('Timezone-aware timestamp required')
    return parsed.astimezone(timezone.utc)


def build_fixtures(run_id, anchor):
    """Return new raw/prepared events and explicit expectation/source-ID manifests."""
    if not re.fullmatch(r'[A-Za-z0-9_-]{8,80}', run_id):
        raise ValueError('Invalid synthetic run ID')
    anchor = timestamp(anchor)
    cases = json.loads((ROOT / 'detections/tests/fixtures/powershell_scripts.json').read_text())
    template = json.loads((ROOT / 'detections/tests/fixtures/office_cmd_high.json').read_text())
    raw, prepared, expected, excluded = [], [], {}, []

    def events_for(case, indirect):
        events = deepcopy(template if indirect else [template[0], template[2]])
        tag = f'{run_id}-{case["id"]}-' + ('cmd' if indirect else 'direct')
        for n, event in enumerate(events):
            process = event['process']
            original = process['entity_id']
            event['host']['id'] = 'synthetic-' + tag
            event['event']['id'] = f'{tag}-{n}'
            event['@timestamp'] = (anchor - timedelta(seconds=len(events)-1-n)).isoformat()
            process['entity_id'] = f'{tag}-{original}'
            if n:
                parent = events[n-1]['process']
                process['parent'] = {k: parent[k] for k in ('entity_id', 'name', 'pid')}
        process = events[-1]['process']
        process['args'] = ['powershell.exe', '-EncodedCommand',
                           base64.b64encode(case['script'].encode('utf-16-le')).decode()]
        process['command_line'] = ' '.join(process['args'])
        return events

    for case in cases:
        for indirect in (False, True):
            events = events_for(case, indirect)
            out = prepare_events(events)
            if len(out) != 1 or out[0]['p1']['powershell']['script_evidence']['status'] != case['expected']:
                raise ValueError('Fixture classification differs from reviewed manifest')
            raw.extend(events)
            prepared.extend(out)
            eid = events[-1]['event']['id']
            if case['expected'] in ('download_only', 'download_and_execute'):
                high = case['expected'] == 'download_and_execute'
                expected[eid] = {'severity': 'high' if high else 'medium',
                                 'risk_score': 73 if high else 47, 'category': case['category']}
            else:
                excluded.append(eid)
    missing = events_for(cases[0], False)[-1:]
    missing[0]['event']['id'] += '-missing-ancestor'
    missing[0]['process']['entity_id'] += '-missing-ancestor'
    unknown = prepare_events(missing)[0]
    if unknown['p1']['powershell']['script_evidence']['status'] != 'unknown':
        raise ValueError('Missing ancestry was not unknown')
    raw.extend(missing)
    prepared.append(unknown)
    excluded.append(missing[0]['event']['id'])
    source_ids = {e['p1'].get('document_id') or 'unknown-' + e['event']['id']: e['event']['id']
                  for e in prepared}
    bundle = {'run_id': run_id, 'anchor': anchor.isoformat(), 'original_events': raw,
              'prepared_events': prepared, 'expected': expected, 'excluded': excluded,
              'source_ids': source_ids}
    validate_bundle(bundle)
    return bundle


def validate_bundle(bundle):
    events, expected = bundle['prepared_events'], bundle['expected']
    if (len(events) != 29 or len(bundle['source_ids']) != 29 or len(expected) != 14
            or len(bundle['excluded']) != 15 or len(set(bundle['excluded'])) != 15
            or set(expected) & set(bundle['excluded'])
            or set(bundle['source_ids'].values()) != set(expected) | set(bundle['excluded'])
            or sum(v['severity'] == 'medium' and v['risk_score'] == 47 for v in expected.values()) != 6
            or sum(v['severity'] == 'high' and v['risk_score'] == 73 for v in expected.values()) != 8
            or sum(v['category'] == 'false_positive' for v in expected.values()) != 2):
        raise ValueError('Fixture cardinality or expectation mismatch')
    actual_ids = {e['p1'].get('document_id') or 'unknown-' + e['event']['id']: e['event']['id']
                  for e in events}
    if len(actual_ids) != 29 or actual_ids != bundle['source_ids']:
        raise ValueError('Prepared event IDs differ from manifest')


def create_bulk(bundle):
    validate_bundle(bundle)
    lines = []
    for event in bundle['prepared_events']:
        doc_id = event['p1'].get('document_id') or 'unknown-' + event['event']['id']
        lines.extend((json.dumps({'create': {'_id': doc_id}}), json.dumps(event)))
    return '\n'.join(lines) + '\n'
