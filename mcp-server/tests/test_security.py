"""Offline MCP policy, pagination and audit regressions."""

from datetime import timedelta
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.audit import Audit  # noqa: E402
from tools.security import ALERT_TOOL, RULE_TOOL, FakeBackend, Fault, ReadTools, validate  # noqa: E402

SCOPE = {'space': 'default', 'rule_id': 'P1-PS-001'}
WINDOW = {**SCOPE, 'start': '2026-01-01T11:00:00Z', 'end': '2026-01-01T13:00:00Z'}


def call(tools, name, args):
    return tools.read(name, args, validate(name, args))


class PolicyTests(unittest.TestCase):
    def test_explicit_scope_and_rejects_extra_keys_and_coercion(self):
        for args, code in (
            ({'rule_id': SCOPE['rule_id']}, 'INVALID_INPUT'),
            ({**WINDOW, 'space': 'p1-day4-canary'}, 'DENIED_SCOPE'),
            ({**WINDOW, 'rule_id': '*'}, 'DENIED_SCOPE'),
            ({**WINDOW, 'space': 'default%2f'}, 'DENIED_SCOPE'),
            ({**WINDOW, 'query': 'raw'}, 'INVALID_INPUT'),
            ({**WINDOW, 'limit': True}, 'INVALID_INPUT'),
            ({**WINDOW, 'limit': 1.0}, 'INVALID_INPUT'),
            ({**WINDOW, 'limit': '1'}, 'INVALID_INPUT'),
            ({**WINDOW, 'limit': 51}, 'INVALID_INPUT'),
            ({**WINDOW, 'start': 'now-1h'}, 'INVALID_INPUT'),
            ({**WINDOW, 'start': '2025-12-01T12:00:00Z'}, 'INVALID_INPUT'),
            ({**WINDOW, 'end': WINDOW['start']}, 'INVALID_INPUT'),
        ):
            with self.subTest(args=args), self.assertRaisesRegex(Fault, code):
                validate(ALERT_TOOL, args)

    def test_project_rules_without_free_text_and_accepts_enabled_metadata(self):
        backend = Mock()
        backend.rule.return_value = {**FakeBackend().rule(), 'enabled': True,
                                     'description': 'REDACT_TEST', 'actions': ['REDACT_TEST']}
        result = call(ReadTools(backend), RULE_TOOL, SCOPE)
        self.assertIs(result['enabled'], True)
        self.assertNotIn('REDACT_TEST', repr(result))

    def test_cursor_is_bound_expiring_tamper_checked_and_limited(self):
        clock = Mock(return_value=10)
        tools = ReadTools(FakeBackend(), clock=clock)
        args = {**WINDOW, 'limit': 50}
        cursor, ids = None, []
        for page in range(4):
            result = call(tools, ALERT_TOOL, {**args, **({'cursor': cursor} if cursor else {})})
            ids.extend(row['alert_id'] for row in result['alerts'])
            cursor = result['next_cursor']
            self.assertEqual(result['capped'], page == 3)
            if page == 0:
                first = cursor
                clock.return_value = 200
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(ids), 200)
        self.assertIsNone(cursor)
        for wrong in ({**args, 'limit': 49, 'cursor': first}, {**args, 'cursor': first + 'a'}):
            with self.assertRaisesRegex(Fault, 'INVALID_CURSOR'):
                call(tools, ALERT_TOOL, wrong)
        second = call(tools, ALERT_TOOL, {**args, 'cursor': first})['next_cursor']
        clock.return_value = 310
        with self.assertRaisesRegex(Fault, 'INVALID_CURSOR'):
            call(tools, ALERT_TOOL, {**args, 'cursor': second})
        with self.assertRaisesRegex(Fault, 'INVALID_CURSOR'):
            call(ReadTools(FakeBackend()), ALERT_TOOL, {**args, 'cursor': first})

    def test_valid_empty_window_is_distinct_from_invalid_backend(self):
        args = {**WINDOW, 'start': '2026-01-01T08:00:00Z', 'end': '2026-01-01T09:00:00Z'}
        self.assertEqual(call(ReadTools(FakeBackend()), ALERT_TOOL, args),
                         {'alerts': [], 'capped': False, 'next_cursor': None})
        backend = Mock()
        start, end, limit = validate(ALERT_TOOL, WINDOW)
        rows = FakeBackend().alerts(start, end, None, limit)
        for data in (rows[::-1], [rows[0]] * 2, [dict(rows[0], rule_id='wrong')], rows * 2):
            backend.alerts.return_value = data
            with self.subTest(count=len(data)), self.assertRaisesRegex(Fault, 'INVALID_RESPONSE'):
                call(ReadTools(backend), ALERT_TOOL, WINDOW)


class AuditTests(unittest.TestCase):
    def test_audit_requires_owned_private_storage_and_blocks_at_cap(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'audit.jsonl'
            audit = Audit(directory)
            audit({'outcome': 'OK'})
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(json.loads(path.read_text())['outcome'], 'OK')
            with patch('tools.audit.MAX_BYTES', 1), self.assertRaises(OSError):
                audit({'outcome': 'OK'})
            path.chmod(0o644)
            with self.assertRaises(OSError):
                audit({'outcome': 'OK'})
            path.unlink()
            target = Path(directory) / 'target'
            path.symlink_to(target)
            with self.assertRaises(OSError):
                audit({'outcome': 'OK'})
            self.assertFalse(target.exists())

    def test_exact_utc_time_bounds(self):
        start, end, _ = validate(ALERT_TOOL, WINDOW)
        self.assertEqual(end - start, timedelta(hours=2))
        args = {**WINDOW, 'end': '2026-01-01T13:00:00+00:00'}
        with self.assertRaisesRegex(Fault, 'INVALID_INPUT'):
            validate(ALERT_TOOL, args)
