"""Build and verify a credential-free, offline P1-PS-001 deployment plan."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from detections.processing.canary_profile import (
    CANARY_ARTIFACTS, CANARY_INTERVALS, CANARY_QUERY, CANARY_RULE_ID, CANARY_SOURCE,
)
from scripts.ci.validate import detection_contract, require, strict_json, yaml

ROOT = Path(__file__).resolve().parents[2]
RULE_ID = 'P1-PS-001'
RULE = 'detections/rules/P1-PS-001_Office_Encoded_PowerShell'
SOURCE = 'logs-p1-powershell-synthetic'
ARTIFACTS = (f'{RULE}.yml', f'{RULE}.esql', f'detections/mappings/{SOURCE}.json')
FIELDS = {
    'rule_id', 'name', 'description', 'type', 'language', 'version', 'enabled',
    'severity', 'risk_score', 'interval', 'from', 'to', 'max_signals', 'actions',
    'author', 'tags', 'false_positives', 'references', 'note', 'threat',
    'severity_mapping', 'risk_score_mapping', 'query',
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def committed_artifacts(commit):
    return _committed_blobs(commit, ARTIFACTS)


def _committed_blobs(commit, paths):
    require(re.fullmatch(r'[0-9a-f]{40}', commit), 'Expected a full lowercase Git commit SHA')
    env = {key: os.environ[key] for key in ('PATH', 'SYSTEMROOT') if key in os.environ}
    env.update(GIT_NO_LAZY_FETCH='1', GIT_ALLOW_PROTOCOL='', GIT_TERMINAL_PROMPT='0')

    def git(*args):
        result = subprocess.run(
            ['git', '--no-replace-objects', *args], cwd=ROOT, env=env,
            capture_output=True, timeout=15,
        )
        require(result.returncode == 0, 'Commit or required artifact is unavailable locally')
        return result.stdout

    require(git('cat-file', '-t', commit) == b'commit\n', 'SHA must identify a commit')
    return {path: git('cat-file', 'blob', f'{commit}:{path}') for path in paths}


def build_plan(commit):
    artifacts = committed_artifacts(commit)
    rule_path, query_path, mapping_path = ARTIFACTS
    payload = _validated_payload(artifacts[rule_path], artifacts[query_path], artifacts[mapping_path], RULE_ID, SOURCE)
    return _plan(commit, artifacts, payload)


def build_canary_plan(commit, *, baseline=False):
    artifacts = _committed_blobs(commit, CANARY_ARTIFACTS)
    original, candidate, query, mapping = CANARY_ARTIFACTS
    require(artifacts[query].decode('utf-8').rstrip() == CANARY_QUERY, 'Unexpected canary query or source')
    previous, desired = (
        _validated_payload(artifacts[path], artifacts[query], artifacts[mapping], CANARY_RULE_ID, CANARY_SOURCE)
        for path in (original, candidate)
    )
    require(set(previous) == set(desired) == FIELDS, 'Unexpected canary managed field set')
    require((previous['interval'], desired['interval']) == CANARY_INTERVALS and
            canonical({**previous, 'interval': desired['interval']}) == canonical(desired),
            'Canary revisions must differ only by the approved schedule interval')
    return _plan(commit, artifacts, previous if baseline else desired,
                 profile=CANARY_RULE_ID, variant='baseline' if baseline else 'candidate')


def _validated_payload(rule, query, mapping, rule_id, source):
    with tempfile.TemporaryDirectory() as directory:
        local_rule = Path(directory) / 'rule.yml'
        local_rule.write_bytes(rule)
        payload = yaml(local_rule)
        exported = subprocess.run(
            ['ruby', str(ROOT / 'detections/processing/export_rule.rb'), str(local_rule)],
            capture_output=True, text=True, timeout=15,
        )
        require(exported.returncode == 0, 'Disabled rule export failed')
        require(canonical(strict_json(exported.stdout)) == canonical(payload),
                'Strict YAML parser and rule exporter disagree')

    require(isinstance(payload, dict) and set(payload) <= FIELDS, 'Unexpected rule field')
    require(payload.get('rule_id') == rule_id, 'Unexpected rule identifier')
    require(detection_contract(payload, query.decode('utf-8'), strict_json(mapping.decode('utf-8'))) == source,
            'Unexpected source stream')
    return payload


def _plan(commit, artifacts, payload, **metadata):
    plan = {
        **metadata,
        'schema_version': 1,
        'mode': 'offline',
        'commit': commit,
        'artifact_sha256': {path: sha256(data) for path, data in artifacts.items()},
        'payload_sha256': sha256(canonical(payload)),
        'payload': payload,
    }
    return {**plan, 'plan_sha256': sha256(canonical(plan))}


def verify_plan(commit, supplied):
    expected = build_plan(commit)
    require(canonical(supplied) == canonical(expected),
            'Plan differs from the committed artifacts or approved commit')
    return expected['plan_sha256']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('plan', help='print a plan built from committed artifacts')
    verify = commands.add_parser('verify-plan', help='verify a saved plan against an explicit commit')
    verify.add_argument('--file', required=True, type=Path)
    for command in commands.choices.values():
        command.add_argument('--commit', required=True)
    args = parser.parse_args()

    try:
        if args.command == 'plan':
            print(json.dumps(build_plan(args.commit), sort_keys=True, indent=2, allow_nan=False))
        else:
            supplied = strict_json(args.file.read_text(encoding='utf-8'))
            print(f'Verified offline plan {verify_plan(args.commit, supplied)}')
    except (OSError, ValueError, subprocess.SubprocessError, KeyError, TypeError, AttributeError,
            IndexError):
        print('Offline plan failed policy or integrity checks. Check the commit, artifacts, and plan.',
              file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
