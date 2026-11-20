"""Kibana detection read contract exercised without network or credentials."""

import json
import subprocess
import unittest
from unittest.mock import Mock

from detections.processing import deployment_plan
from detections.processing.connected_plan import compare
from detections.processing.kibana_rule_reader import KibanaRuleReader


class KibanaRuleReaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.commit = subprocess.check_output(
            ['git', 'rev-parse', 'HEAD'], cwd=deployment_plan.ROOT, text=True,
        ).strip()
        cls.artifact = deployment_plan.build_plan(cls.commit)
        cls.payload = cls.artifact['payload']

    def setUp(self):
        self.response = {
            **self.payload, 'id': '72ab56fa-f3a1-4c84-8466-a0b23b2254ea',
            'revision': 3, 'immutable': False, 'exceptions_list': [], 'updated_by': 'operator',
        }
        self.get = Mock(side_effect=lambda _: (200, json.dumps(self.response)))
        self.reader = KibanaRuleReader('lab', 'default', self.get)

    def test_connected_plan_projects_rule_as_noop(self):
        plan = compare(self.artifact, self.reader, self.response['id'])
        self.assertEqual(plan['result'], 'NOOP')
        self.assertEqual(plan['revision'], 3)
        self.assertEqual(plan['drift_fields'], [])
        self.get.assert_called_once_with('/api/detection_engine/rules?rule_id=P1-PS-001')

    def test_named_space_and_rule_allowlist(self):
        reader = KibanaRuleReader('lab', 'day4-canary', self.get)
        with self.assertRaises(ValueError):
            reader.read('other-rule')
        self.get.assert_not_called()
        reader.read(deployment_plan.RULE_ID)
        self.get.assert_called_once_with('/s/day4-canary/api/detection_engine/rules?rule_id=P1-PS-001')
        with self.assertRaises(ValueError):
            KibanaRuleReader('lab', '../default', self.get)

    def test_errors_are_not_absence(self):
        self.get.side_effect = None
        for status in (302, 401, 403, 404, 500):
            with self.subTest(status=status), self.assertRaisesRegex(ValueError, 'HTTP 200'):
                self.get.return_value = (status, '{}')
                compare(self.artifact, self.reader, self.response['id'])

    def test_rejects_behavior_changes_and_malformed_identity(self):
        for field, value in (
            ('enabled', True), ('actions', [{'id': 'connector'}]),
            ('exceptions_list', [{'id': 'exception'}]), ('timestamp_override', '@other'),
            ('immutable', True), ('setup', 'instructions'), ('rule_id', 'other-rule'),
            ('id', 'wrong'), ('revision', True), ('rule_source', {'type': 'external'}),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                good = self.response
                self.response = {**good, field: value}
                try:
                    self.reader.read(deployment_plan.RULE_ID)
                finally:
                    self.response = good

    def test_rejects_missing_fields_and_duplicate_json(self):
        del self.response['query']
        with self.assertRaisesRegex(ValueError, 'Missing rule fields'):
            self.reader.read(deployment_plan.RULE_ID)
        self.get.side_effect = None
        self.get.return_value = (200, '{"enabled":true,"enabled":false}')
        with self.assertRaisesRegex(ValueError, 'Duplicate JSON'):
            self.reader.read(deployment_plan.RULE_ID)
