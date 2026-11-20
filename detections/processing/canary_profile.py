"""Fixed identity and transport allowlist for the Day 4 canary."""

CANARY_RULE_ID = 'P1-D4-CANARY-001'
CANARY_SPACE = 'p1-day4-canary'
CANARY_SOURCE = 'logs-p1-day4-canary-synthetic'
CANARY_QUERY = f'FROM {CANARY_SOURCE} [metadata _id, _index, _version]\n| LIMIT 1'
CANARY_WRITER = 'p1_day4_canary_writer'
CANARY_INTERVALS = ('5m', '6m')
CANARY_PATCH_FIELDS = frozenset({'interval'})
CANARY_ARTIFACTS = (
    'detections/day4-canary/baseline.yml',
    'detections/day4-canary/candidate.yml',
    'detections/day4-canary/rule.esql',
    'detections/day4-canary/mapping.json',
)
