# Day 4 — Controlled detection deployment

## Offline planner

Run from the repository root with Git, Python and Ruby. Supply the full SHA of
the reviewed commit. The commit and its blobs must already be available locally.

```sh
# Replace with the approved full commit SHA.
approved_commit='<full-commit-sha>'
umask 077
python3 -B -m detections.processing.deployment_plan plan \
  --commit "$approved_commit" > /private/tmp/p1-day4-plan.json
python3 -B -m detections.processing.deployment_plan verify-plan \
  --commit "$approved_commit" --file /private/tmp/p1-day4-plan.json
```

Review the exact JSON payload, the rule ID, `enabled: false`, empty actions, and
the plan digest. A successful verification rebuilds the plan with the supplied
commit and compares the entire canonical JSON object. A failed command exits
nonzero. Preserve the approved commit and digest separately from the plan.
Keep plan files outside the repository.

The planner reads the committed YAML, ES|QL and source mapping. It applies the
existing strict YAML parser, disabled-rule exporter and detection contract to
the Git blobs and hashes each input plus the canonical payload and plan. SHA-256
checks integrity. The operator approves provenance by selecting a reviewed
commit, and uses CI evidence for that exact SHA when available. This command
uses the planner and validators installed in the current checkout. Run it from
a trusted tool checkout.

Offline verification covers repository contracts. It performs zero live reads
and provides no deployment decision or execution evidence.

## Mocked controlled deployment engine

Run the transition and mocked Kibana tests from the repository root.

```sh
python3 -B -m unittest discover -s detections/tests -p 'test_deployment*.py' -v
python3 -B -m unittest discover -s detections/tests -p 'test_canary_deployment.py' -v
```

The transition core is tested through a fake GET/PATCH exchange.
`CanaryDeploymentEngine` supplies the only HTTPS write transport. It has no
write CLI. The dedicated `p1_detection_reader` and the P1-PS-001 command remain
read-only.

1. **Plan.** Build the desired payload from an explicit full commit and its
   hashed artifacts. Read only the fixed canary in the canary engine. An update
   requires a reviewed baseline whose managed payload matches the disabled rule. The plan
   binds the target, UUID, revision, prior managed configuration and desired
   artifact-plan digest. Retain the approved plan and digest for reconciliation.
2. **Apply.** Require the exact approval digest and the explicit mock write
   flag. Rebuild and compare the plan under the lock. An already-matching
   rule produces a no-op. A change sends one single-rule PATCH by UUID with
   only changed managed fields and explicit disabled state. The PATCH
   response and a fresh GET must agree on UUID, revision and managed payload.
   A previous approval cannot be replayed after the state changes.
3. **Verify.** Check the supplied receipt digest, rebuild its desired artifact
   from Git, then compare it with a fresh read of the expected UUID. Verify
   configuration independently of scheduler or execution-key state.
4. **Rollback.** Require separate approval of the receipt digest and explicit
   mock write authorization. Require the exact verified post-apply state and
   reconstruct the prior reviewed payload from Git. Restore only changed
   managed fields on the same UUID and keep it disabled.

A 404 blocks planning. The mocked Kibana engine updates an existing rule
and offers no create, delete, activation, connector or index operation.
Unknown fields and unsupported behavior settings block. A timeout, failed
PATCH, malformed acknowledgement or discrepant readback produces an uncertain
outcome and no verified receipt. The engine attempts a read-only reconciliation
probe and blocks further writes through the same journal, including after
restart. The in-memory audit records operation, result and hashes only.

### Durable journal and recovery

Use an existing, owned mode-`0700` directory on a local filesystem outside
publishable repository paths. Every cooperating process for the target, space
and UUID must use that same directory. The engine serializes updates with an
advisory directory lock. The mode-`0600` journal retains the approved commit,
artifact and approval digests, target binding, expected UUID, prior revision
and managed snapshots. It flushes a temporary file, atomically replaces the
journal, and flushes the directory. The checksum detects accidental damage.
The journal directory remains a trusted local boundary. Keep its contents
private and preserve the journal across restarts. No-op plans issue no PATCH
and need no recovery entry.

| State | Meaning and recovery |
|---|---|
| `PREPARED` | The plan and baseline were persisted. The engine requires a durable `APPLYING` marker before it can invoke PATCH. Inspect with `status(reconcile=True)`. After reviewing the record, explicitly approve `close_prepared(record_sha256, authorize_recovery=True)` to close it locally as `FAILED`. Obtain a fresh plan and approval before any later write. |
| `APPLYING` | The PATCH may have been attempted. Status can read the current rule once and compare it to the snapshots. Leave the journal intact and stop writes. |
| `VERIFIED` | Acknowledgement and readback agreed and the result digest was persisted. |
| `FAILED` | A prepared attempt was explicitly closed before the PATCH boundary. |
| `UNCERTAIN` | A write or its verification failed with no reliable outcome. Follow the same read-only investigation as for `APPLYING`. |

`status()` reads the journal only. `status(reconcile=True)` reports
`MATCHES_BEFORE`, `MATCHES_DESIRED`, `DIVERGED`, or
`UNAVAILABLE_OR_UNSUPPORTED` for unresolved records. It never alters the
journal or sends PATCH. A match cannot attribute a write or prove that a
request still in flight will fail. The engine provides no automatic release
for `APPLYING` or `UNCERTAIN`. Preserve the record and obtain a separately
reviewed recovery decision. A malformed, foreign or insecure journal blocks
requests from the write and recovery paths. Do not delete it to bypass the
block. The journal has an 8 MiB limit and requires a local filesystem that
honors file locks and file and directory flushes.

### Elastic 8.13 write limits

The single-rule PATCH uses the saved-object UUID and merges supplied fields.
Kibana does not expose a caller-supplied revision precondition on this route.
The internal versioned saved-object update and retry logic are separate from
the engine's approval check. A writer outside the shared lock can still race
the read and PATCH. Future live writes require an exclusive maintenance window
and validation of journal durability on the intended local filesystem.
[8.13 patch route](https://github.com/elastic/kibana/blob/v8.13.0/x-pack/plugins/security_solution/server/lib/detection_engine/rule_management/api/rules/patch_rule/route.ts)
· [8.13 alerting update](https://github.com/elastic/kibana/blob/v8.13.0/x-pack/plugins/alerting/server/rules_client/methods/update.ts)

The 8.13 update path builds execution-key attributes based on the existing
enabled state. An enabled rule can get a replacement key under the editor's
permissions. A disabled update skips creating a new key and can clear existing
key attributes. Restoring the managed payload cannot restore that key.
Activation and execution-key verification require separate review. Future
writes need a dedicated, separately verified writer scoped to the approved
space. Do not expand the reader's privileges.
[8.13 key handling](https://github.com/elastic/kibana/blob/v8.13.0/x-pack/plugins/alerting/server/rules_client/lib/create_new_api_key_set.ts)

## Read-only rule adapter

The adapter requests P1-PS-001 by stable rule ID from the configured space
using an injected GET transport. It projects the rule UUID, revision and
managed fields for comparison. It blocks unknown response fields, unexpected
behavior settings and all non-200 responses. A 404 alone cannot authorize a
create because it may indicate a missing route or an incorrect space.

The Day 2 8.13 runtime client used the same default-space endpoint.
The [Elastic v8 retrieval reference](https://www.elastic.co/docs/api/doc/kibana/v8/operation/operation-readrule)
documents the route and named-space form. Tests use synthetic responses, so
the exact full 8.13 response still needs validation against the approved lab.
The connected command below supplies the GET transport. The adapter still
requires a live response contract check before write support.

## Connected read-only plan

This command is implemented and tested with mocked HTTP. Run it against the lab
only after trusted Kibana HTTPS and the dedicated identity have been approved
and provisioned. The 20 November 2026 cutover verified Kibana HTTPS and the
dedicated reader was provisioned. Its first live planner invocation blocked
on a response field. The compatibility correction passed offline tests. The
corrected default-space planner invocation was not repeated. The separate
fixed-profile canary workflow passed live apply and rollback validation.

```sh
approved_commit='<full-commit-sha>'
expected_rule_uuid='<independently-reviewed-rule-uuid>'
ca_file='<path-to-trusted-kibana-ca.pem>'
python3 -B -m detections.processing.connected_plan \
  --commit "$approved_commit" --origin https://127.0.0.1:5601 \
  --space default --ca-file "$ca_file" --expected-uuid "$expected_rule_uuid"
```

Select the space explicitly, including `default` for the root route. Supply
a reviewed UUID from trusted prior evidence. The HTTPS origin accepts
`127.0.0.1` or `[::1]` and an explicit port. The supplied CA must verify the
server certificate and its IP SAN. The client requires TLS 1.2 or newer and
opens a direct connection without proxies or redirects.

Enter the dedicated username and password at the hidden prompts. The command
requires a secure prompt and loads no credentials from arguments, environment
variables or repository files. It performs one GET for P1-PS-001 and prints
only comparison metadata and managed drift field names. Output and diagnostics
suppress response bodies and credential values.

| Exit | Result |
|---|---|
| 0 | `NOOP`. The observed managed fields match the selected commit. |
| 2 | `DRIFT`. The observed rule differs. Review the named fields before any further action. |
| 1 | `BLOCKED`. The read or its validation failed. Review the diagnostic and obtain a fresh approved baseline if needed. |

Unknown fields, unsupported settings, malformed data and all HTTP errors
block the comparison. A 404 gives no authority to create a rule. The command
does not verify scheduler behavior or grant effective privileges, and the
exact full 8.13 response still needs approved live validation.

## Fixed canary setup proposal

The fixed profile is `P1-D4-CANARY-001` in `p1-day4-canary`. It loads
[baseline](../detections/day4-canary/baseline.yml),
[candidate](../detections/day4-canary/candidate.yml),
[ES|QL](../detections/day4-canary/rule.esql), and
[mapping](../detections/day4-canary/mapping.json) from the same reviewed full
Git commit. The only difference is `interval` from `5m` to `6m`. The lookback
stays `now-7m` and both variants remain disabled, action-free, and restricted
to `logs-p1-day4-canary-synthetic`. The planner refuses missing Git blobs.
The files need an approved commit before live setup can use them.

### Setup to approve before any live attempt

1. Review and commit the profile, both rule configurations, and the tests
   under a separate Git approval. Record the commit and all four artifact
   hashes. Reserve the space ID `p1-day4-canary` and verify it and the canary
   rule ID are unused. Approve the exact space initialization with a separate
   setup principal. Preserve the default space.
2. Approve the exact dedicated native user `p1_day4_canary_writer` and sole
   canary-space role. The initial role proposal uses empty Elasticsearch
   cluster, index and run-as grants, with Kibana
   `{"base":[],"feature":{"siem":["all"]},"spaces":["p1-day4-canary"]}`.
   Check the installed 8.13.0 authorization and any required alert/list grants
   separately. If needed, review only the canary-space resources
   `.alerts-security.alerts-p1-day4-canary`, `.lists-p1-day4-canary` and
   `.items-p1-day4-canary`. A denial blocks the run until the exact additional
   permission is approved. Deny default-space access, P1 source access,
   cluster or security administration, and connector management. The existing
   reader keeps its current role.
3. Approve one setup-only `POST /s/p1-day4-canary/api/detection_engine/rules`
   with the committed baseline payload. Use an empty canary source if the
   installed build requires one. Approve creating only
   `logs-p1-day4-canary-synthetic` with the pinned mapping in that case.
   Ingest zero documents. Record the server-generated UUID using a trusted
   read of the stable rule ID and confirm it is disabled with empty actions.
4. Approve the exact loopback HTTPS origin, public CA, journal directory,
   maintenance window, and expected UUID. The engine uses
   `GET /s/p1-day4-canary/api/detection_engine/rules?rule_id=P1-D4-CANARY-001`
   and one `PATCH /s/p1-day4-canary/api/detection_engine/rules` with only
   `id`, `enabled: false`, and the approved `interval`. It supplies
   `kbn-xsrf` on PATCH and verifies the CA and IP identity. Carry the writer
   password in memory after an approved secure prompt or credential retrieval.
   Keep credentials and raw responses out of plans, receipts, and recordings.

**RECORD BEFORE** capture the sanitized canary baseline and P1-PS-001
preservation evidence. Approve the apply plan digest, verify readback, and
confirm a fresh no-op. Approve rollback separately against the verified receipt
and the `6m` to `5m` diff. **RECORD AFTER** capture journal/receipt digests and
the disabled canary baseline at its new server revision. Use read-only checks
to confirm the P1 rule, 14 alert records, and synthetic telemetry remain intact.
Stopping the writer, deleting the canary, and cleaning up any source or space
require separate exact-resource approval. Preserve journal evidence.

Mocked tests cover both routes, strict TLS context, writer selection, and
the full journaled sequence. On 26 November 2026, independent readback
confirmed the live rollback at revision 2, interval 5m, disabled, with no
actions. The writer completed the canary change with Security All in the
canary space and no Elasticsearch grants. The saved-receipt runner verified
the original digest, converted the JSON target array to a tuple in memory,
and preserved the digest and saved bytes. Use the same check if a future
caller loads a receipt from JSON.
[Day 4 verification evidence](implementation-logs/P1-M1_Day4_Implementation_Log.md#26-november-2026--final-read-only-rollback-and-preservation-verification)

## Future live write workflow

1. **Plan.** Pin the verified HTTPS endpoint and space. Check the installed
   Elastic version, target identity, effective role and rule state. Bind the
   target, UUID, observed revision, managed-state digest and desired payload
   into the plan. Report create, update, no-op, or blocked.
2. **Apply.** Require separate authorization tied to the exact plan. Serialize
   cooperating local writers with a target/space lock and use an exclusive
   maintenance window for UI and other clients. Recheck the live preconditions
   under lock. Send at most one disabled single-rule write. Reconcile ambiguous
   responses by reading back before any further write.
3. **Verify.** Compare persisted rule identity, revision and normalized managed
   fields. Keep configuration verification separate from scheduler evidence.
4. **Rollback.** Require an approved receipt and reject intervening drift.
   Restore prior managed fields on the same UUID and keep the rule disabled.
   A newly created rule remains disabled and retained. Preserve existing
   alerts, telemetry, and execution keys.

Before any live write, separately approve trusted Kibana HTTPS and a dedicated
space-scoped principal with exact synthetic-source access. Establish and verify the
8.13 privilege and API behavior before selecting a live identity. Rule edits
can affect the API key used for scheduling. Keep activation outside the first
release and verify key ownership and scheduled execution separately if approved.

Validate the existing rule by read-only comparison first. Prove writes with an
approved disabled canary in an isolated target. Capture **RECORD BEFORE** with
the sanitized target baseline and reviewed plan, and **RECORD AFTER** with the
sanitized verification and rollback receipts and final disabled state.

[Day 4 implementation log](implementation-logs/P1-M1_Day4_Implementation_Log.md)
· [Day 2 runtime evidence](implementation-logs/P1-M1_Day2_Implementation_Log.md)
· [CI validation scope](github-actions-ci.md)

## Kibana HTTPS cutover and rollback

The local configuration and ignored Kibana server leaf passed the 20 November 2026 cutover. The leaf
has IP SAN `127.0.0.1`, DNS SAN `localhost`, and server authentication usage.
The existing lab CA signs the leaf. The CA signing key stays outside Docker
mounts. Use the separate approval for Kibana recreation before running these
commands. Reader provisioning and the planner GET require their own approvals.

**RECORD BEFORE** capture the existing Kibana browser URL, sanitized service
health, and prior disabled-rule evidence. Keep credential prompts, raw service
responses and certificate key files off screen. Confirm the existing image is
Kibana 8.13.0 and the published host port is 5601, or use the configured port for
the host probe and browser. Compare the proposed changes with the protected
pre-Day-4 backups in `infra/certs/day4-kibana-rollback/` before applying.

First check file readability with the local 8.13.0 image's default user. This
temporary check uses no network or app data volumes. If it fails, stop before
recreation and review host-to-container ownership. Keep the private key
restricted.

```sh
docker run --rm --pull=never --network none --read-only \
  --mount "type=bind,src=$PWD/infra/certs/ca.crt,dst=/usr/share/kibana/config/certs/ca.crt,readonly" \
  --mount "type=bind,src=$PWD/infra/certs/kibana-server.crt,dst=/usr/share/kibana/config/certs/kibana-server.crt,readonly" \
  --mount "type=bind,src=$PWD/infra/certs/kibana-server.key,dst=/usr/share/kibana/config/certs/kibana-server.key,readonly" \
  --entrypoint /bin/sh docker.elastic.co/kibana/kibana:8.13.0 \
  -ec 'test -r /usr/share/kibana/config/certs/ca.crt &&
       test -r /usr/share/kibana/config/certs/kibana-server.crt &&
       test -r /usr/share/kibana/config/certs/kibana-server.key'
```

After the mount check succeeds, apply the prepared configuration from the repo root.

```sh
docker compose --env-file infra/.env -f infra/docker-compose.yml up -d \
  --no-deps --force-recreate --no-build --pull never --wait --wait-timeout 180 kibana
```

In the approved validation window, verify the host handshake and availability.
Use the configured host port in place of `5601` if needed. Trust only the
approved public CA in the browser and open `https://localhost:5601`. The Day 2
runtime client now expects HTTPS to Kibana.

```sh
body=$(curl -fsS --max-time 10 --noproxy '*' --cacert infra/certs/ca.crt \
  https://127.0.0.1:5601/api/status) &&
  printf '%s' "$body" | grep -q '"level":"available"' &&
  printf '%s\n' 'Kibana HTTPS status available'
unset body
```

Confirm the existing Kibana volume remains attached, Elasticsearch and n8n
container identities remain stable, and the original saved objects are visible.
Verify that plain HTTP and untrusted TLS fail without submitting credentials.
Use separate approval to compare current rule state or to run the planner.
**RECORD AFTER** capture the trusted HTTPS address and sanitized health checks.

If the HTTPS rollout fails, inspect only sanitized health errors. Restore
the three protected pre-cutover files after reviewing any subsequent local
changes to those files. Restore the previous Kibana service on the same volume.

```sh
cp infra/certs/day4-kibana-rollback/kibana.yml infra/kibana/kibana.yml
cp infra/certs/day4-kibana-rollback/docker-compose.yml infra/docker-compose.yml
cp infra/certs/day4-kibana-rollback/runtime_client.py detections/processing/runtime_client.py
docker compose --env-file infra/.env -f infra/docker-compose.yml up -d \
  --no-deps --force-recreate --no-build --pull never --wait --wait-timeout 180 kibana
```

Verify the previous loopback HTTP healthcheck and browser state after rollback.
Suspend the connected planner until HTTPS is restored. Keep the leaf material
protected and stop before any rule, alert, telemetry or credential changes.
