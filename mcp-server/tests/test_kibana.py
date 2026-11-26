"""Exercise the real adapter with a mocked HTTP connection and no network."""

import base64
from contextlib import redirect_stderr, redirect_stdout
from email.message import Message
from io import StringIO
import json
from pathlib import Path
import ssl
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, Mock, patch

from mcp import Client
from mcp.client.stdio import StdioServerParameters

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT.parent)]
from probe_rule import REVIEWED_UUID, authorize_then_read, main, read_once  # noqa: E402
from server import build_server  # noqa: E402
from tools.kibana import ORIGIN, KibanaBackend  # noqa: E402
from tools.security import ALERT_TOOL, RULE_TOOL  # noqa: E402

UUID = '1eaa1a10-79a5-4cf4-89dc-21292bd17401'
SCOPE = {'space': 'default', 'rule_id': 'P1-PS-001'}
ROUTE = '/api/detection_engine/rules?rule_id=P1-PS-001'
MARKER = 'SYNTHETIC_PRIVATE_MARKER'
RESPONSE = {**SCOPE, 'id': UUID, 'enabled': True, 'type': 'esql', 'language': 'esql',
            'interval': '5m', 'revision': 7, 'risk_score': 47, 'severity': 'medium',
            'output_index': '', 'query': MARKER, 'updated_by': MARKER}
del RESPONSE['space']


class KibanaTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.password = Path(directory) / 'password'
        self.password.write_text(MARKER + '\n')
        self.password.chmod(0o600)
        tls = self.enterContext(patch.object(ssl.SSLContext, 'load_verify_locations'))
        self.connection = self.enterContext(patch('detections.processing.connected_plan.HTTPSConnection'))
        self.backend = KibanaBackend('mock-ca.pem', self.password, UUID)
        tls.assert_called_once_with(cafile='mock-ca.pem')
        self.audit = Mock()
        self.response = self.connection.return_value.getresponse.return_value
        self.response.status = 200
        self.response.headers = Message()
        self.response.headers['Content-Type'] = 'application/json'
        self.response.read.return_value = json.dumps(RESPONSE).encode()

    async def call(self, name=RULE_TOOL, arguments=SCOPE):
        async with Client(build_server(self.backend, self.audit)) as client:
            result = await client.call_tool(name, arguments)
        self.assertNotIn(MARKER, repr(result))
        self.assertNotIn(MARKER, repr(self.audit.call_args_list))
        return result

    async def test_one_exact_get_and_project_only_reviewed_fields(self):
        data = (await self.call()).structured_content
        self.assertEqual(data, {**SCOPE, 'uuid': UUID, 'enabled': True, 'type': 'esql',
                                'interval': '5m', 'revision': 7, 'risk_score': 47, 'severity': 'medium'})
        self.assertEqual(ORIGIN, 'https://127.0.0.1:5601')
        context = self.connection.call_args.kwargs['context']
        self.connection.assert_called_once_with('127.0.0.1', 5601, context=context, timeout=10)
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        header = base64.b64encode(f'p1_detection_reader:{MARKER}'.encode()).decode()
        self.connection.return_value.request.assert_called_once_with(
            'GET', ROUTE, headers={'Accept': 'application/json', 'Authorization': f'Basic {header}'})
        self.response.read.assert_called_once_with(256 * 1024 + 1)
        self.connection.return_value.close.assert_called_once()

    async def test_auth_errors_and_redirect_never_read_bodies_or_retry(self):
        for status, error in [(401, 'AUTHENTICATION_FAILED'), (403, 'AUTHORIZATION_FAILED'),
                              (404, 'NOT_FOUND'), (302, 'BACKEND_FAILURE')]:
            with self.subTest(status=status):
                self.connection.reset_mock()
                self.response.status = status
                result = await self.call()
                self.assertEqual(result.structured_content['error'], error)
                self.connection.return_value.request.assert_called_once()
                self.response.read.assert_not_called()

    async def test_timeout_and_tls_failure_are_sanitized(self):
        for exception, code in [(TimeoutError(MARKER), 'BACKEND_TIMEOUT'),
                                (ssl.SSLCertVerificationError(MARKER), 'TLS_FAILURE')]:
            with self.subTest(code=code):
                self.connection.reset_mock()
                self.connection.return_value.request.side_effect = exception
                self.assertEqual((await self.call()).structured_content['error'], code)
                self.connection.return_value.request.assert_called_once()
                self.connection.return_value.close.assert_called_once()

    async def test_malformed_or_unexpected_response_is_rejected(self):
        for body in [b'{', b'{"id": 1, "id": 2}', b'x' * (256 * 1024 + 1), b'\xff',
                     *(json.dumps({**RESPONSE, **changes}).encode() for changes in
                       [{'enabled': 'false'}, {'id': 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'},
                        {'rule_id': 'other'}, {'unexpected': MARKER}, {'output_index': MARKER}])]:
            with self.subTest(size=len(body)):
                self.response.read.return_value = body
                self.assertEqual((await self.call()).structured_content['error'], 'INVALID_RESPONSE')

    async def test_prohibited_operations_never_open_connection(self):
        for name, arguments, code in [
            (RULE_TOOL, {**SCOPE, 'space': 'other'}, 'DENIED_SCOPE'),
            (RULE_TOOL, {**SCOPE, 'rule_id': 'other'}, 'DENIED_SCOPE'),
            (RULE_TOOL, {**SCOPE, 'route': '/'}, 'INVALID_INPUT'),
            ('patch_detection_rule', SCOPE, 'UNKNOWN_TOOL'),
            (ALERT_TOOL, {**SCOPE, 'start': '2026-01-01T11:00:00Z',
                          'end': '2026-01-01T12:00:00Z'}, 'BACKEND_UNAVAILABLE'),
        ]:
            self.assertEqual((await self.call(name, arguments)).structured_content['error'], code)
        self.connection.assert_not_called()

    async def test_insecure_credential_file_blocks_transport(self):
        self.password.chmod(0o644)
        self.assertEqual((await self.call()).structured_content['error'], 'CREDENTIAL_UNAVAILABLE')
        self.connection.assert_not_called()

    async def test_probe_invokes_only_one_fixed_mcp_tool(self):
        client = AsyncMock()
        client.__aenter__.return_value = client
        with patch('probe_rule.Client', return_value=client):
            self.assertIs(await read_once('mock-launch'), client.call_tool.return_value)
        client.call_tool.assert_awaited_once_with(RULE_TOOL, SCOPE)

    async def test_keychain_supplies_reader_password_without_file(self):
        self.backend = KibanaBackend('mock-ca.pem', None, UUID, keychain=True)
        with patch('tools.kibana.read_keychain_password', return_value=MARKER) as keychain, \
                patch('tools.kibana.read_password') as file_source:
            result = await self.call()
        self.assertFalse(result.is_error)
        self.assertEqual(result.structured_content['uuid'], UUID)
        keychain.assert_called_once_with()
        file_source.assert_not_called()
        self.connection.return_value.request.assert_called_once()

    async def test_keychain_failure_suppresses_details_and_blocks_network(self):
        self.backend = KibanaBackend('mock-ca.pem', None, UUID, keychain=True)
        with patch('tools.kibana.read_keychain_password', side_effect=OSError(MARKER)):
            result = await self.call()
        self.assertEqual(result.structured_content['error'], 'CREDENTIAL_UNAVAILABLE')
        self.connection.assert_not_called()


class ProbeTests(unittest.TestCase):
    def test_launch_pins_reviewed_uuid_and_rechecks_returned_identity(self):
        for returned_uuid in (REVIEWED_UUID, UUID):
            with self.subTest(match=returned_uuid == REVIEWED_UUID):
                result = Mock(is_error=False, structured_content={
                    **SCOPE, 'uuid': returned_uuid, 'type': 'esql', 'enabled': False,
                    'interval': '5m', 'revision': 0, 'risk_score': 47, 'severity': 'medium',
                })
                output = StringIO()
                args = ['probe_rule.py', '--execute-approved-get', '--audit-directory', 'mock-audit',
                        '--ca-file', 'mock-ca.pem']
                with patch.object(sys, 'argv', args), patch('probe_rule.anyio.run', return_value=result) as run, \
                        patch('probe_rule.logging.disable'), redirect_stdout(output):
                    rc = main()
                launch = run.call_args.args[1]
                self.assertEqual(launch.args[2:], [
                    '--backend', 'kibana', '--audit-directory', 'mock-audit', '--ca-file',
                    'mock-ca.pem', '--keychain', '--expected-uuid', REVIEWED_UUID,
                ])
                if returned_uuid == REVIEWED_UUID:
                    self.assertEqual(rc, 0)
                    self.assertEqual(json.loads(output.getvalue())['uuid'], REVIEWED_UUID)
                else:
                    self.assertEqual(rc, 1)
                    self.assertEqual(output.getvalue().strip(), 'BLOCKED: MCP_PROBE_FAILED')


class AuthorizedRetryTests(unittest.IsolatedAsyncioTestCase):
    async def test_pre_authorization_gate_over_real_stdio(self):
        # This child simulates Keychain readiness then launches the synthetic
        # stdio server. Neither Keychain nor Kibana is contacted.
        child = (
            "import pathlib, runpy, sys; "
            "pathlib.Path(sys.argv[-1]).touch(); "
            "sys.argv = sys.argv[1:-2]; "
            "runpy.run_path(sys.argv[0], run_name='__main__')"
        )
        for response in ('stop', 'retry'):
            with self.subTest(response=response), tempfile.TemporaryDirectory() as audit:
                launch = StdioServerParameters(
                    command=sys.executable,
                    args=['-B', '-c', child, str(ROOT/'server.py'), '--audit-directory', audit],
                    cwd=str(ROOT),
                    env={'PYTHONPATH': str(ROOT)},
                )
                with patch.object(sys.stdin, 'isatty', return_value=True), \
                        patch('builtins.input', return_value=response), redirect_stderr(StringIO()) as output:
                    if response == 'retry':
                        result = await authorize_then_read(launch)
                        self.assertFalse(result.is_error)
                        self.assertEqual(result.structured_content['rule_id'], 'P1-PS-001')
                    else:
                        with self.assertRaisesRegex(Exception, 'RETRY_NOT_CONFIRMED'):
                            await authorize_then_read(launch)
                        self.assertFalse((Path(audit)/'audit.jsonl').exists())
                self.assertIn('KEYCHAIN_READY | no Kibana request sent', output.getvalue())
