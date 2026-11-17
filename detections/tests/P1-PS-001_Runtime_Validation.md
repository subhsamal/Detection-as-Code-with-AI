# P1-PS-001 — Controlled runtime validation

**Status:** Controlled runtime validation completed 14 November 2026. Rule disabled after the test; interval 5m/from now-7m/to now preserved. Exactly 29 fresh create-only records produced 6 Medium/47 and 8 High/73 actual alerts, including two known legitimate-automation false positives. Fifteen sources excluded; same 14 alert IDs across two qualifying overlapping scheduled executions. Bounds: 420-second activation gate and 720-second fixture test.

## Observed runtime results — 14 November 2026

- Fresh run `20261114T155319Z-runtime-b6787c09`; 29 create items returned 201,
  no refresh parameter. Existing 29 source records preserved; total now 58.
- Prepared-event timestamp 15:55:43.840952 UTC, ingestion started
  15:55:44.868705 UTC, ordinary-refresh visibility confirmed 15:55:45.917430 UTC.
  All IDs new; all 29 timestamps verified inside the active seven-minute window.
- Actual scheduled runs started 15:56:14.893 UTC and 16:01:14.933 UTC, completing
  15:56:15.006 and 16:01:14.996 respectively. Both detection statuses succeeded.
  Seven-minute windows derived from those actual starts and the verified rule
  settings are 15:49:14.893–15:56:14.893 and 15:54:14.933–16:01:14.933 UTC.
  Same fresh timestamps lie inside both; source visibility preceded both runs.
  Bounds are code/configuration-derived, not retained individual request traces.
- Both alert snapshots contained precisely the expected 14 source references,
  6 actual kibana.alert.severity=medium/risk_score=47 and 8 high/73. No excluded
  source alerted. Two High alerts correspond to the reviewed authorized-automation
  cases; they remain known false positives, not evidence of malicious execution.
- Alert IDs identical across both runs; source backing indices, document IDs,
  timestamps and versions unchanged. Deduplication passed for this batch and
  these two overlapping runs; updates, rollover and future runs remain outside
  this test. Actual payload execution/native PowerShell behavior was not tested.
- Disabled as operator at 16:01:19.498 UTC; final alert count 14, role unchanged,
  all primaries active, only two accepted replicas unassigned, Kibana available.
  Test finished 16:01:20.573210 UTC, within 12 minutes after ingestion.
- Sanitized evidence and original/prepared fresh events retained in ignored
  infra/certs/validation/ under the run ID. No fixture file replacement, cleanup,
  privilege expansion, commit or push. See Day 2 log Step 39.

## Approved schedule revision — applied while disabled

The approved patch below is applied. Every query predicate, metadata field,
priority mapping and permission is preserved. Current settings are 5m/now-7m/to now.

```diff
-interval: 1m
-from: now-2m
+interval: 5m
+from: now-7m
 to: now
```

The additional look-back is **2 minutes**; the full window is 5 + 2 = **7
minutes**, not now-2m. This reduces scheduled frequency and increases expected
notification latency compared with the current one-minute interval. It does not
fix historical disabled-period gaps or justify ignoring an actual failed run.

### Current local verifier and runtime tools

`assess_runtime` now requires immutable activation_at, observed_at and an explicit
timeout. It compares timezone-aware timestamps rather than mutable updated_at or
lexical strings. Missing/stale execution is pending before the deadline and
inconclusive afterward. A fresh failed/partial-failure response remains failed;
normal fresh Kibana success passes. Invalid evidence remains inconclusive.
The repository runtime tools capture the server activation timestamp and use this
helper. Success observed after the deadline is inconclusive, not passed. Safety
disable on inconclusive evidence is an action, not evidence of rule failure. A
separate explicitly selected warm-up policy can permit one historical first-run
gap, retaining failed coverage and requiring the next clean run within seven
minutes. No other/repeated error is exempted. New tools were tested offline on
17 November; the original dated live results above are not a new rollout.

The approved **420-second activation observation bound**
(five-minute interval plus two minutes tolerance) replaces the prior 105-second
bound. Persist the actual activation-response timestamp before
later rule mutations. A locally recorded fallback observation time must be labeled
as such, not claimed as exact activation. Capture final disable timestamp too.

### Fresh fixtures and overlapping windows

- Preserve the original records/files. After the clean execution/owner/scope gate
  and pre-ingestion recording pause, prepare the approved 29-event batch with new
  IDs and fresh timestamps immediately before create-only ingestion.
- Read the next scheduled run time. Aim to timestamp/ingest 10–30 seconds before
  that run, then confirm actual visibility and execution windows. A fixture must
  be less than approximately two minutes old at the first run to remain eligible
  for the second run five minutes later. Scheduler delay consumes that margin.
- Example: timestamp 12:04:40 UTC, runs 12:05 and 12:10. Their nominal windows are
  11:58–12:05 and 12:03–12:10, so the same unchanged event is inside both. These
  illustrative windows are not evidence of actual execution times.
- Keep 6 Medium/47, 8 High/73 (including two known false positives) and 15 excluded
  IDs as expectations. Verify actual alert IDs/ancestors, source index/ID/version
  and actual execution windows. Stable counts after expiry are not deduplication
  proof. A late refresh/run that loses overlap makes this check inconclusive;
  do not silently ingest another batch or change timestamps/look-back.
- Approved: up to **12 minutes after ingestion** for bounded observation under the
  slower schedule. Stop as soon as two qualifying runs and expected evidence are
  complete; disable on actual error or deadline. This replaces the prior five-minute
  test bound. Recording must not extend active-test bounds.

### Approval, verification and rollback

Schedule-only patch and 420-second gate/12-minute test bounds are approved and
prepared. The completed historical test is preserved. Any future activation/ingestion
requires a new recording checkpoint and explicit resume.
Do not modify the .esql file because it contains no schedule. Verify settings and
unchanged query/mappings while disabled before activation. The warm-up exception is off by default and requires explicit approval and
--allow-first-historical-gap; it permits only the isolated historical first-run
gap, followed by a clean second run within seven minutes. Other live modes do not
ignore failed status.

Rollback while disabled: restore interval 1m/from now-2m in YAML and live settings,
verify unchanged query/priorities/permissions, and restore prior observation bounds.
Preserve all fixtures, alerts, keys and other resources. No deletion or privilege
change is part of rollback.

## Next controlled run — sequence after verifier correction

Preparation only; this document does not authorize activation or ingestion.

1. Reconfirm the disabled rule, bracketed metadata query parity, 5m schedule,
   now-7m window, empty actions and unchanged priority mappings. Recheck trusted
   HTTPS, all primaries active, only the two accepted unassigned replicas,
   Kibana/n8n availability, exact stream settings/mappings and current source/alert
   counts. Stop on an unexpected baseline. Finish the pre-activation recording
   pause before continuing.
2. After approval, the gated warmup tool enables only P1-PS-001 as
   p1_detection_operator and retains the server activation timestamp. A manual
   operator activation must likewise retain that exact checkpoint; never reuse
   an earlier successful run as fresh evidence.
3. Immediately inspect public execution-key owner and candidate privilege
   snapshots. Require operator ownership and reviewed scope. Report the exact
   key-ID association limitation explicitly; never decrypt credentials. Wait up
   to 420 seconds for a fresh scheduled run after the checkpoint. Use
   assess_runtime: normal fresh succeeded message passes within the deadline;
   missing/stale evidence is pending then inconclusive. Failed/partial status
   stops unless it is the one explicitly approved historical warm-up gap; that
   gap still counts as failed coverage, requiring the next clean run within
   seven minutes of the first.
   Require absence of the old malformed-index warning and unexpected alerts.
   Disable immediately on failure or unresolved evidence at the deadline.
4. Pause before ingestion after this gate passes. Capture the successful saved
   execution and sanitized owner/scope results. Obtain the user's resume after
   recording; no fixture timestamps are frozen during this pause.
5. After resume, recheck health and current execution status. Generate exactly
   29 new prepared records from the approved inert cases, using unique run,
   host, process, event and document IDs. Assign fresh UTC timestamps immediately
   before ingestion with valid parent/child ordering. Preserve original fixture
   files and all existing documents. Verify expected source-ID sets locally:
   6 Medium, 8 High (including two known automation false positives), 15 excluded.
6. Time the batch for the next scheduled window. Separate setup administrator
   sends create-only POST /_bulk entries targeting only the approved stream,
   without a refresh parameter. Require every item to succeed; stop on any
   conflict/partial error without retrying or replacing existing records.
   Poll ordinary refresh visibility and verify exactly 29 new IDs. Source count
   should increase by 29 from the measured baseline.
7. Observe at most 12 minutes after ingestion, continuously checking execution
   and health. Verify exact matching source references, 6 actual Medium/47 and
   8 actual High/73 alerts, no alerts for the 15 excluded IDs and no second Medium
   alert for a High source. Require two documented actual scheduled windows
   containing the same unchanged sources and stable alert IDs/counts to pass
   deduplication. If timing prevents that, mark it inconclusive; no extra batch,
   schedule change or privilege expansion is automatic.
8. Disable only this rule on completion or unexpected failure and verify disabled.
   Allow in-flight work to settle, recheck health and final alert counts, and
   retain sanitized evidence plus all resources. Capture final results after
   disabling; no recording pause may extend the bounded active test.

Recording capture details and statuses are maintained only in the ignored local
docs/recordings/P1_Recording_Plan.md. Actual controlled alert results are recorded above; future runs require separate approval.

## Historical pre-schedule-change evidence — 14 November 2026

- Rule owner/editor: `p1_detection_operator`; enabled false; interval 1 minute, `from: now-2m`, `to: now`. The extra minute is the additional look-back, not a second execution schedule.
- Elasticsearch: yellow, 40 active primaries, 2 unassigned shards; Kibana available. Reconfirm that the two shards are only the known lists/items replicas before execution.
- Source contains 29 documents, all at **2026-11-14 00:18:59.371 UTC / 05:48:59.371 IST**. At **05:07:35 UTC / 10:37:35 IST**, the actual now-2m count was **0**. Existing fixtures are outside the runtime window.
- Rule alert count is zero. Operator-owned API-key metadata count is zero; no generated execution key is currently confirmed. Do not claim that disabled-rule creation proved key generation or execution permissions.

## 1. Pre-activation checks

Repeat immediately before execution:

- Trusted HTTPS and hostname validation, Elasticsearch/Kibana availability, all primaries STARTED and exactly the two documented unassigned list/item replicas. Stop on any additional unassigned shard or deterioration; do not alter replicas.
- Verify rule query/settings match reviewed files, actions remain empty, rule is disabled, and rule ID is P1-PS-001. Record the rule UUID privately for exact requests.
- Authenticate as the operator; compare effective source read/metadata, default-space Security and alert privileges with the reviewed role. Verify encryption readiness. No role edits, standalone credentials, API-key rotation or admin rule editing.
- Snapshot source count, rule alert count, current rule execution summary and selected task/event-log metadata if accessible. Do not grant extra access merely to inspect logs.
- Inspect the template/data stream read-only: exact name, priority 501, strict reviewed mappings, timestamp support and one-primary/zero-replica backing index. Check n8n availability as an unaffected service.

## 2. Fresh-fixture proposal — requires execution approval

Do not edit the committed fixture files, existing 29 records, source timestamps or document versions. Generate a **new run** from the same reviewed local fixtures, with a new run ID, host/process/event IDs and document IDs. Keep raw and prepared evidence locally in ignored storage.

Produce the same 29 prepared records: 14 expected matches and 15 exclusions. Set a fresh controlled UTC anchor immediately around activation, with parent-before-child order and the tested cmd delay. Use the separate setup administrator only for create-only bulk ingestion into the approved stream, with **no refresh parameter**. Poll for ordinary refresh visibility; no force refresh, updates, rollover or broad writes. Stream total should become 58 for one new full batch, provided the starting count is still 29.

Use the new run's event IDs and actual execution time bounds for evaluation. An unrestricted query now includes old fixture matches too; do not compare its total directly with the new-run expectation. Record time-bounded source results and exact expected source IDs. Query-filter success remains separate from scheduled-alert success.

Minimize the delay between ingestion/visibility and activation. If a pause makes the new batch stale, do not overwrite it or silently change the look-back. Stop and agree on another create-only batch with new IDs. A stale source outside the execution window is not a rule false negative.

## 3. Operator activation and generated-key execution

Execution-response interpretation is implemented in
`detections/processing/execution_verifier.py` and tested offline. Require a
timezone-aware execution timestamp after the activation/configuration checkpoint
and status `succeeded`. Kibana 8.13's normal message
`Rule execution completed successfully` is accepted; a nonempty message alone
is not a failure. Authorization warnings and `failed`/`partial failure` remain
failures. Missing, stale or unrecognized evidence remains unknown and cannot
pass the gate. This helper performs no API calls or rule changes and does not
replace the separate identity, privilege and alert checks.

### Historical pre-activation approval gate — 14 November 2026

The historical pre-activation read-only check found no operator-owned execution API key; the disabled rule's key-owner metadata is null. Ownership and key privileges therefore cannot be confirmed before activation. Operator privileges are verified separately and do not prove execution-key privileges. That ordering was subsequently approved and the actual warm-up/run results are preserved above; do not treat this historical check as current absence or blanket future activation approval.

If that ordering is approved, use this sequence:

1. Recheck health, disabled configuration, source counts, data-stream settings and unaffected-service availability. Prepare the new 29-event batch locally with unique IDs; assign fresh timestamps immediately before ingestion.
2. Enable only P1-PS-001 as `p1_detection_operator`; initially the old source records remain outside its time window.
3. Inspect only generated-key owner, rule association and privilege descriptors, including effective privilege limits. Require the operator owner and sufficient source-read/alert permissions. Do not retrieve key secrets. If missing, ambiguous or insufficient, disable immediately and stop before ingestion.
4. After that gate passes, create the 29 fresh records through the separate setup identity. Use create-only bulk operations, no refresh parameter, and ordinary visibility checks. Preserve the original 29 records.
5. Observe at most 12 minutes and verify the alert expectations below, including two actual overlapping execution windows. Record any inconclusive timing result rather than adding another batch automatically.
6. Disable the rule as the operator on completion or unexpected failure; verify its final state, health and settled alert evidence. Preserve resources and generated-key metadata.

After explicit resume approval, enable only this rule using `p1_detection_operator`. Existing administrator credentials must not create, edit or enable the rule. Kibana should create/use its encrypted internal execution API key using the operator's privilege snapshot; do not create a separate key or retrieve its secret value.

Record the enable response, operator ownership, and scheduled execution status. Where available, inspect only owner/key metadata for the newly generated rule-associated key; no IDs or secret values need appear in recording output. Manual queries authenticated as the operator do **not** establish that scheduled API-key execution works. Successful background execution and expected alerts are required evidence. If key metadata cannot be associated safely, record that limit even if background execution succeeds.

Stop on privilege/API-key/engine errors, unexpected configuration changes, truncation or health deterioration. Do not broaden grants, regenerate credentials or change the rule to make a failing test pass.

## 4. Actual alert checks

| Fresh-batch sources | Expected actual alerts |
|---|---|
| Understood download-only, direct and cmd paths | 6 Medium, risk 47 |
| Download-to-execution, direct and cmd paths | 8 High, risk 73 |
| Benign, unsupported, malformed or missing ancestry | 15 source IDs produce no alerts |
| Legitimate automation satisfying the complete High pattern | 2 of the 8 High alerts: expected known false positives, not additional alerts |

Read `kibana.alert.severity` and `kibana.alert.risk_score`, **not** the rule's default severity/risk fields. Verify the numeric scores and exact source-event/ancestor references, rule ID and run IDs. Each matching source gets one alert; a High source must not also create Medium. Validate both process paths and zero alerts for each excluded ID.

Use an exact rule filter plus source-event IDs/ancestor references; do not depend on custom p1 fields being mapped in the alert index. Preserve observed fields if custom data is omitted. Legitimate automation may still alert; this test does not establish a production false-positive rate. These are instructions identified in synthetic text, not proof of real payload execution.

## 5. Scheduled overlap and duplicate checks

Aim for at least two successful scheduled executions where the same unchanged fresh source documents fall inside **both actual execution windows**. Plan fresh ingestion shortly before the next scheduled run; do not assume wall-clock sleeps exactly equal scheduler times. If safe timing requires observing an empty first execution, record it as such before introducing the fresh batch.

For each run, capture execution time bounds/status, source document IDs/index/versions and alert IDs/counts. After the first qualifying run expect 14 alerts for the new batch. On a later overlapping run, expect no additional alerts for those same unchanged sources. The count remaining 14 after sources aged out is insufficient evidence of deduplication. If two qualifying windows cannot be demonstrated, mark the overlap test inconclusive; do not claim it passed.

No source mutation/reingestion is needed. Deterministic Python IDs do not replace this test, and updates/rollover may change identity behavior. No automatic Medium-to-High update is included. Observe up to 12 minutes, then stop/disable after the approved test; report scheduling delays or missing evidence instead of changing interval/look-back automatically.

## 6. Stop, rollback and evidence

At the end of the bounded test, or on unexpected failure, disable **only P1-PS-001** as the operator and verify enabled false. Allow any in-flight task to settle; note that disabling is not proof an already running task was cancelled. Recheck final execution/alert counts and health without forcing unrelated task actions.

Preserve all fixture records, alerts, template, data stream and API-key metadata. No key invalidation or credential rotation is part of rollback. A template used by a stream cannot simply be removed; data-stream/backing-index/template/rule/key deletion requires separate exact cleanup approval. Never delete shared alerts, lists/items, global logs configuration or named volumes.

Keep a sanitized evidence manifest in ignored local validation storage: UTC/IST times, rule/query/configuration digest, run ID, input/expected IDs, source count and time bounds, actual severity/risk and source/alert references, execution outcomes, overlapping-window evidence and final disabled state. Record aggregate findings and remaining gaps in the Day 2 log. Do not save raw authorization headers, key values, credentials or unredacted API output. API probes that only inspect state remain distinguished from activation or stored-data writes.

## Actual-window evidence required at the next run

The completed run above supplies post-change evidence; use these requirements
again for future tests rather than assuming future overlap/deduplication.
For two actual completed runs, retain execute-start/end times, actual query time
bounds when available, and the same unchanged source IDs/index/versions. With
normal seven-minute windows ending at actual times T1 and T2, their intersection
is [max(T1-7m, T2-7m), min(T1, T2)]. Use actual submitted query bounds if catch-up
changes them. Require each tested source timestamp inside both actual windows,
ordinary-refresh visibility before both searches, and identical alert IDs/counts
after both executions. If query bounds or source eligibility cannot be established,
report overlap/deduplication inconclusive. Schedule settings and historical runs
from the old one-minute configuration are not proof of post-change overlap.

## Reproducible tools after final code review

Use [repository commands and safety boundaries](../processing/RUNTIME_TOOLS.md),
not /private/tmp scripts. Read-only audit accepts original Day 2 evidence without
rewriting it. Fixtures generated after the PID correction have distinct PIDs;
historical JSON retains the original values. Local tests mock HTTP and mutations.
This document's historical runtime evidence does not imply that the refactored
tools were executed live or that future runs are automatically approved.
