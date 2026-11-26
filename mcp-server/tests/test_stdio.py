"""Real SDK stdio transport and sanitized tool failure tests."""

import asyncio
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock

from mcp import Client
from mcp.client.stdio import StdioServerParameters

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from server import MAX_FRAME, build_server  # noqa: E402
from tools.security import ALERT_TOOL, RULE_TOOL, FakeBackend  # noqa: E402

SCOPE = {'space': 'default', 'rule_id': 'P1-PS-001'}
WINDOW = {**SCOPE, 'start': '2026-01-01T11:00:00Z', 'end': '2026-01-01T13:00:00Z'}
SENTINEL = 'SYNTHETIC_PRIVATE_MARKER'


class StdioTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_stdio_discovery_invocation_denial_and_pagination(self):
        with tempfile.TemporaryDirectory() as audit_dir:
            launch = StdioServerParameters(command=sys.executable,
                                           args=['-B', str(ROOT/'server.py'), '--audit-directory', audit_dir])
            async with Client(launch) as client:
                listed = await client.list_tools()
                self.assertEqual({t.name for t in listed.tools}, {RULE_TOOL, ALERT_TOOL})
                self.assertTrue(all(not t.input_schema['additionalProperties'] for t in listed.tools))
                self.assertTrue(all(not t.output_schema['additionalProperties'] for t in listed.tools))
                rule = await client.call_tool(RULE_TOOL, SCOPE)
                self.assertFalse(rule.is_error)
                self.assertEqual(rule.structured_content['rule_id'], 'P1-PS-001')
                self.assertIs(rule.structured_content['enabled'], False)
                denied = await client.call_tool(RULE_TOOL, {**SCOPE, 'space': SENTINEL})
                self.assertTrue(denied.is_error)
                self.assertEqual(denied.structured_content['error'], 'DENIED_SCOPE')
                self.assertNotIn(SENTINEL, repr(denied))
                malformed = await client.call_tool(ALERT_TOOL, {**WINDOW, 'limit': True})
                self.assertEqual(malformed.structured_content['error'], 'INVALID_INPUT')
                page = (await client.call_tool(ALERT_TOOL, {**WINDOW, 'limit': 3})).structured_content
                again = (await client.call_tool(ALERT_TOOL, {**WINDOW, 'limit': 3,
                                                           'cursor': page['next_cursor']})).structured_content
                self.assertEqual(len(page['alerts']), 3)
                self.assertNotEqual(page['alerts'], again['alerts'])
            text = (Path(audit_dir)/'audit.jsonl').read_text()
            self.assertNotIn(SENTINEL, text)
            self.assertNotIn(page['next_cursor'], text)
            self.assertNotIn(page['alerts'][0]['alert_id'], text)
            events = [json.loads(line) for line in text.splitlines()]
            self.assertIn('DENIED_SCOPE', [e['outcome'] for e in events])
            self.assertEqual(events[-1]['result_count'], 3)

    async def test_sdk_handler_fails_closed_if_audit_or_backend_fails(self):
        backend = Mock(wraps=FakeBackend())
        audit = Mock(side_effect=OSError(SENTINEL))
        async with Client(build_server(backend, audit)) as client:
            blocked = await client.call_tool(RULE_TOOL, SCOPE)
        self.assertEqual(blocked.structured_content['error'], 'AUDIT_UNAVAILABLE')
        self.assertNotIn(SENTINEL, repr(blocked))
        backend.rule.assert_not_called()

        audit = Mock(side_effect=[None, OSError(SENTINEL)])
        async with Client(build_server(backend, audit)) as client:
            hidden = await client.call_tool(RULE_TOOL, SCOPE)
        self.assertEqual(hidden.structured_content['error'], 'AUDIT_UNAVAILABLE')
        self.assertNotIn('revision', hidden.structured_content)

        backend.rule.side_effect = TimeoutError(SENTINEL)
        async with Client(build_server(backend, Mock())) as client:
            failed = await client.call_tool(RULE_TOOL, SCOPE)
        self.assertEqual(failed.structured_content['error'], 'BACKEND_FAILURE')
        self.assertNotIn(SENTINEL, repr(failed))

    async def test_stdio_rejects_bad_frames_before_tool_validation(self):
        frames = (
            b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":'
            b'{"name":"get_detection_rule","arguments":{"space":"default","space":"duplicate"}}}\n',
            b' ' * MAX_FRAME + SENTINEL.encode() + b'\n',
            b'{"jsonrpc":"2.0","id":1,"method":"' + SENTINEL.encode() + b'"}\n',
        )
        with tempfile.TemporaryDirectory() as audit_dir:
            for frame in frames:
                with self.subTest(length=len(frame)):
                    result = await asyncio.to_thread(
                        subprocess.run, [sys.executable, '-B', str(ROOT/'server.py'), '--audit-directory', audit_dir],
                        input=frame, capture_output=True, timeout=8,
                    )
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual(result.stdout, b'')
                    self.assertTrue(result.stderr.startswith(b'MCP_STOPPED:'))
                    self.assertNotIn(SENTINEL.encode(), result.stderr)
            self.assertFalse((Path(audit_dir)/'audit.jsonl').exists())
