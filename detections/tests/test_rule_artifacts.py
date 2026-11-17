"""Offline artifact checks. These do not parse or execute ES|QL in Elasticsearch."""
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('processor', ROOT / 'detections/processing/powershell.py')
processor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(processor)


class RuleArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rule = ROOT / 'detections/rules/P1-PS-001_Office_Encoded_PowerShell.yml'
        exported = subprocess.run(['ruby', str(ROOT / 'detections/processing/export_rule.rb'), str(rule)],
                                  capture_output=True, text=True, check=True)
        cls.rule = json.loads(exported.stdout)
        cls.query = (ROOT / 'detections/rules/P1-PS-001_Office_Encoded_PowerShell.esql').read_text()
        cls.mapping = json.loads((ROOT / 'detections/mappings/logs-p1-powershell-synthetic.json').read_text())

    def field(self, dotted):
        node = self.mapping['mappings']
        for part in dotted.split('.'):
            node = node['properties'][part]
        return node

    def test_export_is_disabled_api_body(self):
        self.assertIs(self.rule['enabled'], False)
        self.assertEqual(self.rule['actions'], [])
        self.assertEqual(self.rule['rule_id'], 'P1-PS-001')
        self.assertEqual((self.rule['interval'], self.rule['from'], self.rule['to']),
                         ('5m', 'now-7m', 'now'))
        self.assertEqual((self.rule['type'], self.rule['language']), ('esql', 'esql'))
        self.assertNotIn('index', self.rule)  # ES|QL uses FROM, not a rule index property.
        self.assertNotIn('engineering', self.rule)
        self.assertEqual(self.rule['query'], self.query.rstrip())
        for key in ['name', 'description', 'risk_score', 'severity', 'query']:
            self.assertIn(key, self.rule)

    def test_priority_mapping_contract(self):
        self.assertEqual(self.rule['risk_score'], 47)
        self.assertEqual(self.rule['severity'], 'medium')
        self.assertEqual({m['value']: m['severity'] for m in self.rule['severity_mapping']},
                         {'medium': 'medium', 'high': 'high'})
        for item in self.rule['severity_mapping']:
            self.assertEqual(item['field'], 'p1.priority.severity')
            self.assertEqual(item['operator'], 'equals')
        risk = self.rule['risk_score_mapping'][0]
        self.assertEqual((risk['field'], risk['value']), ('p1.priority.risk_score', ''))
        self.assertEqual(self.field(risk['field'])['type'], 'integer')

    def test_query_fields_have_explicit_mappings(self):
        # Field-existence consistency only: not an engine syntax/behavior validator.
        for field in set(re.findall(r'\b(?:event|host|process|p1)\.[A-Za-z0-9_.]+', self.query)):
            self.field(field)
        self.assertEqual(self.query.splitlines()[0],
                         'FROM logs-p1-powershell-synthetic [metadata _id, _index, _version]')
        self.assertNotIn('p1.priority.risk_score', self.query)
        self.assertNotIn('p1.priority.severity', self.query)
        self.assertNotIn('| KEEP ', self.query)
        self.assertNotIn('| STATS ', self.query)
        self.assertIn('| LIMIT 100', self.query)
        self.assertEqual(self.rule['max_signals'], 100)

    def test_exact_name_data_stream_template_preserves_reviewed_contract(self):
        import fnmatch
        template = json.loads((ROOT / 'detections/mappings/logs-p1-powershell-synthetic.template.json').read_text())
        name = 'logs-p1-powershell-synthetic'
        self.assertEqual(template['index_patterns'], [name])
        self.assertEqual(template['data_stream'], {})
        self.assertEqual(template['priority'], 501)
        self.assertEqual(template['composed_of'], [])
        self.assertEqual(template['template'], self.mapping)
        self.assertEqual(template['template']['mappings']['properties']['@timestamp']['type'], 'date')
        for control in [name + '-extra', 'logs-p1-other-synthetic', 'logs-p1-powershell-other',
                        'metrics-p1-powershell-synthetic', 'ordinary-p1-index']:
            self.assertFalse(any(fnmatch.fnmatchcase(control, p) for p in template['index_patterns']))

    def test_complete_prepared_documents_fit_strict_mapping(self):
        def validate(document, schema):
            for key, value in document.items():
                self.assertIn(key, schema['properties'], 'Unmapped field: ' + key)
                field = schema['properties'][key]
                if 'properties' in field:
                    self.assertIsInstance(value, dict)
                    validate(value, field)
                else:
                    for item in value if isinstance(value, list) else [value]:
                        if field['type'] == 'boolean':
                            self.assertIs(type(item), bool)
                        elif field['type'] in {'integer', 'long'}:
                            self.assertIs(type(item), int)
                        else:
                            self.assertIsInstance(item, str)
        events = json.loads((ROOT / 'detections/tests/fixtures/office_cmd_high.json').read_text())
        manifest = json.loads((ROOT / 'detections/tests/fixtures/powershell_scripts.json').read_text())
        import base64
        for case in manifest:
            value = base64.b64encode(case['script'].encode('utf-16-le')).decode()
            events[-1]['process']['args'] = ['powershell.exe', '-EncodedCommand', value]
            events[-1]['process']['command_line'] = ' '.join(events[-1]['process']['args'])
            result = processor.prepare_events(events)
            self.assertEqual(len(result), 1)
            validate(result[0], self.mapping['mappings'])
        self.assertEqual(self.mapping['mappings']['dynamic'], 'strict')
        self.assertEqual(self.field('process.args')['ignore_above'], 1024)
        self.assertEqual(self.mapping['settings']['number_of_replicas'], 0)


if __name__ == '__main__':
    unittest.main()
