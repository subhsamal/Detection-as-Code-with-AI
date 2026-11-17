# P1-PS-001 runtime tools

These standard-library tools replace the temporary Day 2 scripts. Paths resolve
from the repository, not a particular user's home or `/private/tmp`. No live tool
was executed as part of the 17 November code corrections. The existing rule,
58 source records, 14 alerts, roles and keys are to be preserved.

## Local checks and fixture preparation

From the project root:

```sh
python3 -B -m unittest discover -s detections/tests -p 'test_*.py' -v
python3 -B detections/processing/runtime_validation.py --help
python3 -B detections/processing/runtime_validation.py fixtures \
  --run-id offline-review-001 --anchor 2026-11-17T12:00:00Z
```

The last command uses no credentials/network and prints synthetic JSON only.
It creates 29 prepared records: 6 Medium candidates, 8 High candidates (including
two intentional legitimate-automation false positives), 15 excluded records. Both
direct and cmd-mediated ancestry are covered. Raw events use distinct process
PIDs; entity IDs establish lineage. Separate tests exercise PID reuse.

Fixture generation never executes script text or contacts its `.invalid` URLs.
The JSON includes decoded text; use only reviewed synthetic input. Do not ingest
the example's fixed timestamps as if they were current. An approved live run
builds a fresh batch immediately before its create-only write. Historical Day 2
raw/prepared artifacts are retained unchanged, including their original PIDs.

## Read-only modes

```sh
python3 -B detections/processing/runtime_validation.py status
python3 -B detections/processing/runtime_validation.py audit --evidence \
  infra/certs/validation/20261114T155319Z-runtime-b6787c09-runtime-result.json
```

`status` expects the final disabled state and compares configuration, health and
role/key scope with reviewed artifacts. `audit` reads current alerts, source
versions and recorded execution history, then compares the retained snapshots.
It prints actual priorities, the two intentional false-positive rows, the 14
alert IDs and disabled status. Neither mode enables/disables anything or saves
new evidence. Raw HTTP responses, key IDs/values and credentials are not printed.

Both modes use existing credentials in ignored `infra/.env`, held in memory.
Operator authentication reads rules, source data and alerts; the separate existing
administrator is used only for role/key descriptors, health and execution-history
inspection. These are narrow authorized operations using a broad setup account,
not a claim of narrowly scoped administrator authentication. Ports must be local,
the Elasticsearch CA must verify, redirects/proxies are refused, and `.env` must
be restricted (0600). No key is created/decrypted/revoked by these modes. Public
metadata still does not uniquely link the exact execution key; all active owner
snapshots are compared and that limitation is reported.

The original Day 2 result format and new ledgers are accepted. Missing evidence,
truncated reads, wrong scores, changed source versions or alert IDs stop the audit.
Retained per-run snapshots establish historical comparisons; live reads corroborate
them, rather than recreating past snapshots. Window bounds are derived from actual
execution starts and the verified 5m/now-7m/to now configuration, not request traces.

## Live modes — examples for a separately approved future run only

These commands must NOT be run during code review or used as an implied rollout.
Obtain the user approval and recording checkpoints required by AGENTS.md first.
The CLI and transport require explicit write authorization; flags do not replace
human authorization. No setup/role/user/key/configuration mutation is implemented.

```sh
# After explicit warm-up approval and RECORD BEFORE:
python3 -B detections/processing/runtime_validation.py warmup \
  --allow-live-writes --confirm-rule P1-PS-001 --allow-first-historical-gap

# Only after a passed warm-up, recording pause and explicit ingestion resume:
python3 -B detections/processing/runtime_validation.py ingest \
  --allow-live-writes --confirm-rule P1-PS-001
```

Warm-up requires the rule disabled initially. It enables only P1-PS-001 as
`p1_detection_operator` and retains the server activation timestamp. Missing/stale
execution is pending; a deadline without evidence is inconclusive. A late success
cannot pass the gate. The first execution must complete within seven minutes of
activation; the second must be clean within seven minutes of the first. The
historical-gap exception is off unless explicitly selected: at most one exact
first-run coverage-gap error is allowed, with successful task invocation and no
other recorded errors. Its coverage stays failed, never relabeled successful.
Repeated gap/authorization/query/other errors stop immediately and trigger a
targeted disable. A passed warm-up leaves the rule enabled and pauses WITHOUT
ingesting; capture the clean result before resuming.

Ingestion requires the rule already enabled with a clean execution gate. It
checks mappings, scope, health and the next run time, aligns ingestion about
30 seconds before the next scheduled run, then creates exactly 29 new IDs using
the setup identity. Operator source writes are not granted. No refresh parameter,
force refresh, index/update/delete, resource setup, conflict retry or extra batch
is allowed. Existing source/alert records are preserved; prior alerts are excluded
from the new run's counts and must remain present.

The fixture test is bounded to 12 minutes after ingestion. Verify actual 6
Medium/47 and 8 High/73 alert fields, zero alerts for 15 excluded source IDs, the
two known High false positives, and unchanged IDs/versions across two successful
overlapping executions. A five-minute cadence has only two minutes of overlap;
missed visibility/window timing is not proof of deduplication. Stop as soon as
the two qualifying runs pass; otherwise stop/disable at the bound or first error.
No automatic configuration or privilege expansion makes a test pass.

Warm-up failures and every ingestion completion/failure attempt disable only
P1-PS-001 and confirm the saved state. Network failure may prevent confirmation;
a failed disable must be treated as requiring immediate operator attention.
Disabling cannot cancel a task already in flight. No key revocation or resource
deletion is part of rollback. Record the final disabled state before recording
results; filming must not extend the active test.

New UUID-named evidence goes only under ignored `infra/certs/validation/`, with
0600 files. The tools checkpoint only their own new run and never rewrite the
original Day 2 evidence. Preserve the encryption key, CA, TLS mounts, data stream,
template, source/alert data and volumes. Destructive cleanup requires separate
exact-resource approval. To roll back local tool changes, revert only the reviewed
code; do not alter the installed rule or history automatically.
