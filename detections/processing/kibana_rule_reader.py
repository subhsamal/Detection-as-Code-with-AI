"""Read one reviewed Kibana rule through an injected GET transport."""

import re
from urllib.parse import urlencode
from uuid import UUID

from detections.processing.canary_profile import CANARY_RULE_ID, CANARY_SPACE
from detections.processing.deployment_plan import FIELDS, RULE_ID
from scripts.ci.validate import require, strict_json

METADATA = {
    'id', 'revision', 'created_at', 'created_by', 'updated_at', 'updated_by',
    'execution_summary',
}
EMPTY_BEHAVIOR = {'exceptions_list', 'response_actions', 'related_integrations', 'required_fields'}


def rule_path(space, *, canary=False):
    require(isinstance(space, str) and re.fullmatch(r'[a-z0-9_-]+', space),
            'Invalid Kibana space')
    require(not canary or space == CANARY_SPACE, 'Unexpected canary space')
    prefix = '' if space == 'default' else f'/s/{space}'
    return prefix + '/api/detection_engine/rules?' + urlencode({
        'rule_id': CANARY_RULE_ID if canary else RULE_ID,
    })


class KibanaRuleReader:
    def __init__(self, target, space, get, *, canary=False):
        self._path = rule_path(space, canary=canary)
        self.rule_id = CANARY_RULE_ID if canary else RULE_ID
        require(isinstance(target, str) and target, 'Missing target identity')
        self.target = (target, space)
        self._get = get

    def read(self, rule_id):
        require(rule_id == self.rule_id, 'Unsupported detection rule')
        status, body = self._get(self._path)
        # A 404 can also indicate a missing route or an incorrect space.
        require(status == 200, 'Kibana rule read did not return HTTP 200')
        return project_rule(body, rule_id)


def project_rule(body, rule_id):
    response = strict_json(body)
    require(isinstance(response, dict), 'Expected a rule object')
    allowed = FIELDS | METADATA | EMPTY_BEHAVIOR | {
        'immutable', 'setup', 'rule_source', 'output_index',
    }
    require(not (response.keys() - allowed), 'Unknown Kibana rule response fields')
    # Kibana 8.13 serializes the legacy output index with an empty default.
    # Only the default is compatible with the committed rule projection.
    require(response.get('output_index', '') == '', 'Unsupported output_index')
    require(FIELDS <= response.keys(), 'Missing rule fields in Kibana response')
    require(response['rule_id'] == rule_id, 'Unexpected rule identity')
    require(response['type'] == response['language'] == 'esql', 'Unexpected rule type')
    require(response['enabled'] is False and response['actions'] == [],
            'Rule must be disabled without actions')
    require(response.get('immutable') is False, 'Expected a mutable custom rule')
    require(response.get('rule_source', {'type': 'internal'}) == {'type': 'internal'},
            'Expected an internally sourced rule')
    require(response.get('setup', '') == '' and
            all(response.get(field, []) == [] for field in EMPTY_BEHAVIOR),
            'Unexpected rule behavior settings')
    identifier = response.get('id')
    require(isinstance(identifier, str) and str(UUID(identifier)) == identifier,
            'Expected a canonical rule UUID')
    revision = response.get('revision')
    require(type(revision) is int and revision >= 0, 'Invalid rule revision')
    return {'id': identifier, 'revision': revision,
            'payload': {field: response[field] for field in FIELDS}}
