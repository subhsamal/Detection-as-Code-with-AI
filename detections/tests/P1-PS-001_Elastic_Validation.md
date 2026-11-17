# P1-PS-001 — Elastic lab validation plan

**Current status:** Controlled runtime validation completed: 29 additional fresh fixtures, 6 actual Medium/47 alerts, 8 High/73 (including two known false positives), 15 exclusions and stable alert IDs across two overlapping successful scheduled runs. Source total 58; alert total 14; rule disabled afterward. See [runtime evidence](P1-PS-001_Runtime_Validation.md) and Day 2 log Step 39. The disabled-stage account below is historical.

## Completed disabled-stage validation — 14 November 2026

The separate setup administrator installed only the exact template (priority 501) and named stream with one primary/zero replicas. Operator reads verified strict mappings and timestamp metadata. Create-only bulk ingestion without refresh parameters succeeded for 29 fixtures, visible through ordinary refresh. The operator query returned exactly 14 expected records (6 Medium/47, 8 High/73), excluding 15; 2 High matches intentionally represent legitimate-automation false positives.

Rule P1-PS-001 was created by p1_detection_operator with enabled false, reviewed mappings/query/schedule and no actions. Final check found zero alerts and unchanged operator grants. Existing yellow condition remained limited to the two known list/item replicas; all primaries were active and Kibana available. No rule activation had occurred at that checkpoint; source-level scores alone were not alert verification. Later controlled results are summarized at the top.

The original disabled-stage pause was completed under later approval. The successful runtime batch preserved those old fixtures and used fresh IDs/timestamps. Further testing must again preserve all existing evidence and await approval.

## Review artifacts

- [ES|QL query](../rules/P1-PS-001_Office_Encoded_PowerShell.esql)
- [Disabled YAML rule](../rules/P1-PS-001_Office_Encoded_PowerShell.yml)
- [Proposed source-index mapping](../mappings/logs-p1-powershell-synthetic.json)
- [Local processor contract](../processing/README.md)

The query filters trusted Python output. Behavioral matching does not depend on exact severity/risk values; priority fields are validated separately in processing/artifact tests and during live alert checks. Explicit process/start filters use MV_CONCAT and whole-value RLIKE membership to handle scalar or array ECS fields. It does not decode PowerShell, rebuild ancestry, or prove runtime download/execution. Windows process-start validation occurs in Python before `p1.lineage.verified` can be true; the query independently rechecks event category/type, Windows/image/analysis-version/lineage/encoding and qualifying script classification. Never ingest externally supplied classification labels as trusted evidence.

## Completed local checks

24 unittest methods pass: 20 processor tests plus 4 artifact-contract checks. YAML was safely parsed using already-installed Ruby/Psych and exported to JSON. Prepared output fits the proposed explicit field/type contract, including all 14 script fixtures. Query field names and both mapping branches are consistent. This does **not** validate ES|QL syntax, Elasticsearch mapping acceptance, Kibana API acceptance, risk overrides or actual alerts.

To repeat local checks:

```sh
python3 -B -m unittest discover -s detections/tests -p 'test_*.py' -v
ruby detections/processing/export_rule.rb detections/rules/P1-PS-001_Office_Encoded_PowerShell.yml
```

The exporter prints only the local disabled rule body; it does not deploy. No package was installed. Python standard-library tests use existing Ruby/Psych only to parse YAML safely; those artifact tests require Ruby/Psych to be available.

## Read-only engine checks completed on Elasticsearch 8.13.0

Authenticated read-only probes confirmed the running version. Both `FROM ... METADATA ...` and legacy bracket syntax returned HTTP 200 on the existing empty default-space alert index, with `_id`, `_index`, `_version` columns. Subsequent scheduled validation exposed a Kibana 8.13 index-extraction incompatibility with bare METADATA. The final query uses verified `[metadata _id, _index, _version]` syntax, accepted by both the engine and Kibana helper. No alert data was printed.

The actual revised pipeline after FROM ran against constant-only ROW input: **12 cases, all HTTP 200 with expected row counts**. Medium, High, changed risk score, scalar ECS fields and array ECS fields matched; wrong category/type, substring lookalikes, unknown/no-download and typed missing-lineage evidence were excluded. An initial untyped ROW null caused a type-verification error; the final test used `TO_BOOLEAN(null)` to represent the declared Boolean mapping. The first array-membership regex probe also failed to match multivalues; the corrected full-string pattern passed. These observations informed the final query, rather than assuming current-version behavior.

At that historical pre-source checkpoint, the complete FROM query parsed but returned `verification_exception: Unknown index [logs-p1-powershell-synthetic]`. The source index was deliberately not created. These probes validate syntax/functions and constant-input filter behavior, not proposed mapping acceptance, actual indexed events, scheduled alerts, priority overrides or deduplication.

Reference: [Elasticsearch 8.13 metadata directive](https://www.elastic.co/guide/en/elasticsearch/reference/8.13/esql-metadata-fields.html).

## Authorization for future live validation

The data stream, exact template and disabled P1-PS-001 already exist. Future activation/ingestion requires separate approval and recording checkpoints. Existing resources must not be created again or overwritten. This does not authorize role changes, service recreation, connector actions, new raw-event indices, rule overwrites or deletion of shared resources.

## Historical blocker — resolved by approved data-stream setup

The approved source name matches built-in template `logs` (`logs-*-*`, priority 100, data-stream-only). The reviewed regular-index PUT was rejected with HTTP 400. Follow-up reads confirmed no source index/data stream or rule exists. No telemetry was ingested and no execution API key was created.

The [exact-name data-stream review](../designs/P1-PS-001_Data_Stream_Review.md) and [proposed template](../mappings/logs-p1-powershell-synthetic.template.json) now have successful non-persistent simulation evidence. Before retrying, obtain approval for this source-resource design. A possible solution is an exact-name data-stream template containing the reviewed mapping and lab settings, then creating a data stream under the existing approved name. That requires explicit approval for template installation/data-stream creation; it is not an automatic workaround. Do not change the global logs template or the operator's role. The accepted replica-only yellow condition was reconfirmed; all primaries were STARTED and Kibana available before the rejected write.

## Future repeat-validation sequence

Use the [repository tools](../processing/RUNTIME_TOOLS.md) after explicit approval.
Do not execute resource-creation steps from the historical plan against existing
resources. The current source is a data stream, not a regular index.

1. Read-only preflight: verify disabled state, ignored secrets, trusted HTTPS,
   exact template/mappings, 5m/from now-7m/to now settings and operator scope.
2. After RECORD BEFORE and approval, run the gated warm-up. Preserve activation
   time and any first-run historical gap as failed coverage; require the clean
   next run within seven minutes. No other error is exempted.
3. Pause before ingestion for recording and explicit resume. Use exactly 29 new
   IDs/current timestamps; setup authentication creates documents only in the
   existing stream, without refresh parameters, updates or automatic retries.
4. Validate actual alert fields against exact source IDs: 6 Medium/47, 8 High/73,
   15 exclusions and two intentional automation false positives. No extra Medium
   alert for a High source; no script strings executed.
5. Require two actual successful overlapping executions, unchanged source
   identities/versions and the same 14 alert IDs. Derived window evidence and
   retained snapshot provenance must be labeled accurately.
6. Disable on any unexpected condition or after the bounded 12-minute test.
   Preserve source/alerts, role, keys and infrastructure. Record final state.

## Acceptance and rollback

Accept only when the actual engine query matches expected IDs, scheduled executions succeed, both actual severity/risk values are correct, and unchanged sources do not create unexpected duplicates. Record any unperformed check as pending.

On failure, disable only the newly created rule and retain evidence. Stop for review on API/schema/privilege problems; do not silently broaden roles or bypass TLS. Source/alert/rule/key deletion needs a separate exact-scope cleanup approval. Preserve credentials, volumes, n8n and unrelated data.
