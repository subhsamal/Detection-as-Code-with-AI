"""Regression cases for saved Kibana execution responses; no live API calls."""
import importlib.util
from pathlib import Path
import unittest

MODULE = Path(__file__).resolve().parents[1] / 'processing/execution_verifier.py'
spec = importlib.util.spec_from_file_location('execution_verifier', MODULE)
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class ExecutionVerifierTests(unittest.TestCase):
    checkpoint = '2026-11-14T10:28:00Z'

    def assess(self, status='succeeded', message='Rule execution completed successfully',
               date='2026-11-14T10:29:08.151Z'):
        return verifier.assess_execution({'last_execution': {
            'date': date, 'status': status, 'message': message,
        }}, after=self.checkpoint)[0]

    def test_observed_kibana_813_success_message(self):
        self.assertEqual(self.assess(), 'passed')

    def test_success_with_no_message(self):
        self.assertEqual(self.assess(message=None), 'passed')

    def test_genuine_authorization_failure(self):
        self.assertEqual(self.assess('failed',
            'security_exception: action [indices:data/read/search] is unauthorized'), 'failed')

    def test_partial_failure_malformed_index_warning(self):
        self.assertEqual(self.assess('partial failure',
            'This rule may not have the required read privileges to the following '
            'index patterns: ["_index","_version",'
            '"logs-p1-powershell-synthetic METADATA _id"]'), 'failed')

    def test_partial_failure_even_with_success_message(self):
        self.assertEqual(self.assess('partial failure'), 'failed')

    def test_authorization_warning_overrides_success_status(self):
        self.assertEqual(self.assess(message='security_exception: forbidden'), 'failed')

    def test_missing_execution_evidence(self):
        for summary in (None, {}, {'last_execution': None}, {'last_execution': {}}):
            with self.subTest(summary=summary):
                self.assertEqual(verifier.assess_execution(
                    summary, after=self.checkpoint)[0], 'unknown')

    def test_stale_or_equal_execution_is_not_verified(self):
        for date in ('2026-11-14T10:27:00Z', self.checkpoint):
            self.assertEqual(self.assess(date=date), 'unknown')

    def test_invalid_or_naive_timestamp_is_not_verified(self):
        for date in (None, 'invalid', '2026-11-14T10:29:00'):
            self.assertEqual(self.assess(date=date), 'unknown')

    def test_missing_status_or_unrecognized_message_is_not_verified(self):
        self.assertEqual(self.assess(status=None), 'unknown')
        self.assertEqual(self.assess(message='New unexpected warning'), 'unknown')


class RuntimeVerifierTests(unittest.TestCase):
    activation = '2026-11-14T13:00:00Z'

    def assess(self, summary=None, observed='2026-11-14T13:01:00Z', **kwargs):
        return verifier.assess_runtime(summary, activation_at=self.activation,
                                      observed_at=observed, timeout_seconds=420,
                                      **kwargs)[0]

    def summary(self, status='succeeded', date='2026-11-14T13:00:30Z',
                message='Rule execution completed successfully'):
        return {'last_execution': {'date': date, 'status': status, 'message': message}}

    def test_missing_evidence_pending_then_inconclusive(self):
        self.assertEqual(self.assess(), 'pending')
        self.assertEqual(self.assess(observed='2026-11-14T13:07:00Z'), 'inconclusive')

    def test_historical_failure_is_pending_after_new_activation(self):
        self.assertEqual(self.assess(self.summary('failed', '2026-11-14T12:59:00Z')),
                         'pending')

    def test_equal_activation_is_not_fresh(self):
        self.assertEqual(self.assess(self.summary(date=self.activation)), 'pending')

    def test_fresh_success(self):
        self.assertEqual(self.assess(self.summary()), 'passed')

    def test_late_success_cannot_pass_deadline(self):
        self.assertEqual(self.assess(self.summary(date='2026-11-14T13:08:00Z'),
                                    observed='2026-11-14T13:08:01Z'), 'inconclusive')

    def test_late_observation_cannot_retroactively_pass(self):
        self.assertEqual(self.assess(self.summary(),
                                    observed='2026-11-14T13:07:00.001Z'), 'inconclusive')

    def test_success_exactly_at_deadline(self):
        self.assertEqual(self.assess(self.summary(date='2026-11-14T13:07:00Z'),
                                    observed='2026-11-14T13:07:00Z'), 'passed')

    def test_failure_stays_failure_after_deadline(self):
        self.assertEqual(self.assess(self.summary('failed'),
                                    observed='2026-11-14T13:08:00Z'), 'failed')

    def test_fresh_actual_and_partial_failures(self):
        for status in ('failed', 'partial failure'):
            self.assertEqual(self.assess(self.summary(status)), 'failed')

    def test_fresh_gap_is_not_automatically_ignored(self):
        self.assertEqual(self.assess(self.summary('failed',
            message='3 hours were not queried between this rule execution and the last execution')),
            'failed')

    def test_future_or_invalid_execution_is_inconclusive(self):
        for date in ('bad', '2026-11-14T13:02:00Z'):
            self.assertEqual(self.assess(self.summary(date=date)), 'inconclusive')

    def test_offsets_use_actual_time_not_lexical_order(self):
        self.assertEqual(self.assess(self.summary(date='2026-11-14T18:30:30+05:30')),
                         'passed')

    def test_invalid_activation_and_clock_order_are_inconclusive(self):
        self.assertEqual(verifier.assess_runtime(None, activation_at='invalid',
            observed_at=self.activation, timeout_seconds=420)[0], 'inconclusive')
        self.assertEqual(self.assess(observed='2026-11-14T12:59:00Z'), 'inconclusive')

    def test_invalid_deadline_is_inconclusive(self):
        for timeout in (0, -1, True, float('nan'), float('inf')):
            self.assertEqual(verifier.assess_runtime(None, activation_at=self.activation,
                observed_at=self.activation, timeout_seconds=timeout)[0], 'inconclusive')
