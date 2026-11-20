"""Exercise the connected command with a mocked HTTPS connection."""

import base64
from contextlib import redirect_stderr, redirect_stdout
import getpass
import io
import json
import ssl
import subprocess
import unittest
from unittest.mock import patch
import warnings

from detections.processing import connected_plan, deployment_plan


class ConnectedPlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.commit = subprocess.check_output(
            ['git', 'rev-parse', 'HEAD'], cwd=deployment_plan.ROOT, text=True,
        ).strip()
        cls.payload = deployment_plan.build_plan(cls.commit)['payload']

    def setUp(self):
        self.uuid = '72ab56fa-f3a1-4c84-8466-a0b23b2254ea'
        self.response = {
            **self.payload, 'id': self.uuid, 'revision': 3, 'immutable': False, 'output_index': '',
        }
        self.args = ['--commit', self.commit, '--origin', 'https://127.0.0.1:5601',
                     '--space', 'day4', '--ca-file', 'test-ca.pem', '--expected-uuid', self.uuid]

    def run_command(self, configure=None, prompt=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(ssl.SSLContext, 'load_verify_locations', autospec=True) as load_ca, \
                patch.object(connected_plan, 'HTTPSConnection') as https, \
                patch.object(getpass, 'getpass', side_effect=prompt or ['test-user', 'mock password']) as ask, \
                redirect_stdout(stdout), redirect_stderr(stderr):
            connection = https.return_value
            reply = connection.getresponse.return_value
            reply.status = 200
            reply.headers.get_content_type.return_value = 'application/json'
            reply.read.return_value = json.dumps(self.response).encode()
            if configure:
                configure(connection, reply, load_ca)
            status = connected_plan.main(self.args)
        return status, stdout.getvalue(), stderr.getvalue(), https, ask, load_ca

    def test_noop_uses_ca_hostname_verification_and_single_scoped_get(self):
        result, out, err, https, ask, load_ca = self.run_command()
        self.assertEqual((result, err), (0, ''))
        report = json.loads(out)
        self.assertEqual((report['result'], report['commit'], report['target']),
                         ('NOOP', self.commit, ['https://127.0.0.1:5601', 'day4']))
        self.assertEqual(report['drift_fields'], [])
        host, port = https.call_args.args
        context = https.call_args.kwargs['context']
        self.assertEqual((host, port), ('127.0.0.1', 5601))
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
        load_ca.assert_called_once()
        self.assertEqual(load_ca.call_args.kwargs, {'cafile': 'test-ca.pem'})
        auth = base64.b64encode(b'test-user:mock password').decode()
        https.return_value.request.assert_called_once_with(
            'GET', '/s/day4/api/detection_engine/rules?rule_id=P1-PS-001',
            headers={'Accept': 'application/json', 'Authorization': f'Basic {auth}'},
        )
        https.return_value.close.assert_called_once()
        self.assertEqual(ask.call_count, 2)
        for secret in ('mock password', 'test-user', auth):
            self.assertNotIn(secret, out + err)

    def test_drift_reports_managed_fields_without_copying_remote_values(self):
        self.response['description'] = 'untrusted response value'
        result, out, err, *_ = self.run_command()
        self.assertEqual((result, err), (2, ''))
        self.assertEqual(json.loads(out)['drift_fields'], ['description'])
        self.assertNotIn('untrusted response value', out)

    def test_nondefault_or_malformed_output_index_blocks_without_echoing_value(self):
        for value in ('mock destination', ' ', None, False, 0, [], {}):
            with self.subTest(value=value):
                self.response['output_index'] = value
                result, out, err, *_ = self.run_command()
                self.assertEqual((result, out), (1, ''))
                self.assertEqual(err.strip(), 'BLOCKED: Unsupported output_index')

    def test_auth_missing_and_redirect_responses_block_without_read_or_retry(self):
        for code in (401, 403, 404, 302):
            with self.subTest(code=code):
                result, out, err, https, *_ = self.run_command(
                    lambda _connection, reply, _ca: setattr(reply, 'status', code))
                self.assertEqual((result, out), (1, ''))
                self.assertIn(str(code) if code != 302 else 'Unsupported', err)
                self.assertEqual(https.return_value.request.call_count, 1)
                https.return_value.getresponse.return_value.read.assert_not_called()

    def test_tls_failure_suppresses_exception_and_closes_connection(self):
        def reject_certificate(connection, _reply, _ca):
            connection.request.side_effect = ssl.SSLCertVerificationError('mock password')

        result, out, err, https, *_ = self.run_command(reject_certificate)
        self.assertEqual((result, out), (1, ''))
        self.assertIn('certificate or hostname verification failed', err)
        self.assertNotIn('mock password', err)
        https.return_value.close.assert_called_once()
        https.return_value.getresponse.assert_not_called()

    def test_bad_ca_and_no_secure_prompt_never_open_a_connection(self):
        def bad_ca(_connection, _reply, ca):
            ca.side_effect = OSError('mock password')

        def no_tty(_):
            warnings.warn('mock password', getpass.GetPassWarning)

        for settings in ({'configure': bad_ca}, {'prompt': no_tty}):
            with self.subTest(settings=settings):
                result, out, err, https, *_ = self.run_command(**settings)
                self.assertEqual((result, out), (1, ''))
                self.assertNotIn('mock password', err)
                https.assert_not_called()

    def test_invalid_target_or_space_is_rejected_before_credential_prompt(self):
        original = self.args[:]
        for position, value in ((3, 'http://127.0.0.1:5601'), (3, 'https://remote.test:5601'),
                                (3, 'https://127.0.0.1:5601/admin'), (5, '../default')):
            with self.subTest(value=value):
                self.args = original[:]
                self.args[position] = value
                result, out, _, https, ask, _ = self.run_command()
                self.assertEqual((result, out), (1, ''))
                ask.assert_not_called()
                https.assert_not_called()

    def test_identity_unknown_fields_and_malformed_field_types_block(self):
        original = self.response.copy()
        for field, value, diagnostic in (
            ('id', 'aaab56fa-f3a1-4c84-8466-a0b23b2254ea', 'UUID differs'),
            ('rule_id', 'other', 'Unexpected rule identity'),
            ('enabled', True, 'Rule must be disabled'),
            ('timestamp_override', 'mock password', 'Unknown Kibana rule response fields'),
            ('alias_target_id', 'mock alias', 'Unknown Kibana rule response fields'),
            ('query', [], 'Malformed managed rule field type'),
        ):
            with self.subTest(field=field):
                self.response = {**original, field: value}
                result, out, err, *_ = self.run_command()
                self.assertEqual((result, out), (1, ''))
                self.assertIn(diagnostic, err)
                self.assertNotIn('mock password', err)

    def test_malformed_response_blocks(self):
        for body in (b'not json', b'\xff', b'x' * (connected_plan.MAX_RESPONSE_BYTES + 1)):
            with self.subTest(size=len(body)):
                result, out, err, *_ = self.run_command(
                    lambda _conn, reply, _ca: setattr(reply.read, 'return_value', body))
                self.assertEqual((result, out), (1, ''))
                self.assertTrue(err.startswith('BLOCKED:'))
