"""Offline interpretation of Kibana 8.13 detection execution summaries.

No HTTP requests, credential access or rule mutations. A passed execution check
does not establish execution-key ownership, privilege scope or alert correctness.
"""
from datetime import datetime
import math


def _timestamp(value):
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.utcoffset() is None:
        raise ValueError('Timezone required')
    return parsed


def assess_runtime(summary, *, activation_at, observed_at, timeout_seconds):
    """Assess an execution against an immutable, caller-recorded activation.

    Returns passed, failed, pending or inconclusive. Missing/stale evidence is
    pending until the deadline, then inconclusive, never a confirmed failure.
    No historical-gap exception is enabled: a fresh failed status still fails.
    """
    try:
        activated = _timestamp(activation_at)
        observed = _timestamp(observed_at)
        if (isinstance(timeout_seconds, bool)
                or not math.isfinite(timeout_seconds) or timeout_seconds <= 0
                or observed < activated):
            raise ValueError('Invalid observation bounds')
    except (TypeError, ValueError, AttributeError, OverflowError):
        return 'inconclusive', 'Invalid activation checkpoint or observation bounds'

    last = summary.get('last_execution') if isinstance(summary, dict) else None
    if isinstance(last, dict) and last.get('date') is not None:
        try:
            executed = _timestamp(last['date'])
        except (TypeError, ValueError, AttributeError, OverflowError):
            return 'inconclusive', 'Invalid execution timestamp'
        if executed > observed:
            return 'inconclusive', 'Execution timestamp is after observation'
        if executed > activated:
            outcome, reason = assess_execution(summary, after=activation_at)
            if outcome == 'passed' and (observed - activated).total_seconds() > timeout_seconds:
                return 'inconclusive', 'Success was not verified within the execution deadline'
            return ('inconclusive' if outcome == 'unknown' else outcome), reason

    if (observed - activated).total_seconds() < timeout_seconds:
        return 'pending', 'Awaiting execution after activation'
    return 'inconclusive', 'No fresh execution observed before deadline'


def assess_execution(summary, *, after):
    """Return (passed|failed|unknown, sanitized reason) for a fresh execution.

    ``after`` is the timezone-aware activation/configuration checkpoint. Missing,
    malformed or stale evidence is unknown, never a successful verification.
    """
    last = summary.get('last_execution') if isinstance(summary, dict) else None
    if not isinstance(last, dict):
        return 'unknown', 'Missing execution evidence'
    try:
        checkpoint = datetime.fromisoformat(after.replace('Z', '+00:00'))
        executed = datetime.fromisoformat(last['date'].replace('Z', '+00:00'))
        if checkpoint.utcoffset() is None or executed.utcoffset() is None:
            raise ValueError('Timezone required')
    except (KeyError, TypeError, ValueError, AttributeError):
        return 'unknown', 'Missing or invalid execution timestamp'
    if executed <= checkpoint:
        return 'unknown', 'No execution after the checkpoint'

    status = last.get('status')
    message = last.get('message', '')
    if message is None:
        message = ''
    if not isinstance(message, str):
        return 'unknown', 'Invalid execution message'
    text = message.casefold()
    authorization_markers = (
        'may not have the required read privileges', 'security_exception',
        'unauthorized', 'forbidden', 'authorization_exception',
    )
    if any(marker in text for marker in authorization_markers):
        return 'failed', 'Execution reports an authorization error or warning'
    if status in ('failed', 'partial failure'):
        return 'failed', 'Execution failed or partially failed'
    if status != 'succeeded':
        return 'unknown', 'No confirmed successful execution status'
    # Kibana 8.13 emits a normal nonempty message for successful scheduled runs.
    if message.strip() in ('', 'Rule execution completed successfully'):
        return 'passed', 'Fresh scheduled execution succeeded'
    return 'unknown', 'Unrecognized success-status message requires review'
