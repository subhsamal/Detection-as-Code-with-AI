# P1-M1 — Day 4 Implementation Log

## 19 November 2026 — Assessment and offline planner

- Reviewed the Day 2 rule and runtime evidence, Day 3 offline CI, tracked
  authentication and TLS configuration, and the existing export and validation
  tools. Kibana uses loopback HTTP for its client endpoint and CA-verified HTTPS
  to Elasticsearch. The proposed deployer requires verified HTTPS to Kibana.
- After approval of the offline slice, added a planner and verification command
  on `feature/p1-day4-offline-planner`. The planner selects P1-PS-001 by fixed
  artifact paths and an explicit commit and requires a disabled payload without
  actions. It binds raw artifact, canonical payload, and plan SHA-256 digests.
- Recorded the offline commands and connected design in the
  [deployment runbook](../day4-deployment-runbook.md). Connected planning,
  apply, live verification, and rollback remain pending. Live checks, identity
  provisioning, infrastructure changes and activation require separate approval.
- Offline validation: all 97 unittest methods passed, including six new
  planner tests. Generated and verified a CLI plan against commit
  `909edf7fe96d1a059aeebeae4169fa25cd42bbfa`. Ruff, detection contracts,
  static configuration checks, artifact/ignore policy and diff checks passed.
  No live API or scheduler validation was performed.
- Active effort was not measured. **NO RECORDING NEEDED** for the offline slice.

## 19 November 2026 — Mocked deployment transitions

- Added a deployment state core exercised through an in-memory rule store.
  It binds approval to the target, prior state and committed desired artifact,
  rechecks the plan under the store lock and requires matching write
  acknowledgement and readback before issuing a receipt.
- Tested a fresh-plan no-op, competing create approvals, drift refusal,
  same-UUID update and rollback, disabled-rule retention, and an ambiguous
  write with no automatic retry. An update requires a prior committed baseline
  that matches the observed managed fields. Rollback requires a separately
  approved receipt and an unchanged post-apply state.
- Offline validation passed all 105 unittest methods, including eight new
  state-transition tests. Ruff, offline detection contracts, static configuration
  checks, artifact policy and diff checks passed. The store models rather than
  verifies Elastic write semantics. No live transport, cross-process lock,
  authentication or scheduler validation was added.
- Active effort was not measured. **NO RECORDING NEEDED** for this slice.

## 19 November 2026 — Read-only Kibana adapter

- Cross-checked the Elastic v8 read API with the default-space lookup used by
  the Day 2 Elastic 8.13 runtime client. Added a GET-only adapter with injected
  transport, explicit space routing and strict response projection. It blocks
  malformed responses, unknown behavior settings and all non-200 responses.
- All 110 offline tests passed, including five adapter tests covering a matching
  no-op, named-space routing, unauthorized and missing reads, rule identity
  and settings checks, and malformed responses. Ruff, static configuration,
  artifact policy and diff formatting checks passed.
- The exact 8.13 response shape and authentication remain pending an approved
  live read. No transport, credentials or lab changes were used.
- Active effort was not measured. **NO RECORDING NEEDED** for this slice.

## 20 November 2026 — HTTPS transport and connected read-only planning

- Added `python3 -B -m detections.processing.connected_plan` with an explicit
  committed revision, loopback HTTPS origin, space, trusted CA and expected
  rule UUID. The client issues one scoped GET, requires certificate and IP
  identity checks with TLS 1.2 or newer, and collects Basic credentials through
  hidden terminal prompts.
- The command reports `NOOP` or `DRIFT` for the expected existing rule and lists
  only managed fields that differ. HTTP errors, unknown fields, malformed
  responses, identity mismatches and TLS failures block the comparison. No
  response body or credential is included in diagnostics.
- Local CI-equivalent checks passed on Python 3.9.6 and Ruby 2.6.10. All 118
  unittest methods passed, including eight new mocked-command tests. Offline
  detection contracts, strict config checks, config-only Compose with
  placeholders, Ruff, actionlint, artifact and diff checks, and both Gitleaks
  scans passed. The exact Elastic 8.13 response and certificate
  handshake remain pending approved live validation.
- Active effort was not measured. **NO RECORDING NEEDED** for mocked tests.

## 20 November 2026 — Kibana HTTPS cutover preparation

- Confirmed the Day 2 public CA matches the archived CA certificate and
  protected signing key. Checked CA constraints, signing eligibility when a
  key-usage extension is present, and validity beyond the leaf lifetime.
  Issued a distinct 365-day Kibana server leaf using that CA. Offline chain,
  server-auth usage, key match and SAN checks passed for IP `127.0.0.1` and
  DNS `localhost`. The certificate is mode `0644` and the key is `0600`, under
  ignored `infra/certs/`.
- Prepared inbound TLS, two read-only bind mounts with auto-creation disabled,
  and a CA-verified HTTPS healthcheck. Rendered Compose with placeholders and
  confirmed the Elasticsearch and n8n service definitions, named volumes,
  loopback bindings, and Kibana credential references match the prior config.
  The mocked healthcheck passed for availability and rejected degraded status,
  certificate failures and timeouts. Actual container key readability and the
  served TLS handshake remain cutover gates.
- Updated the Day 2 runtime transport and current documentation references to
  use verified Kibana HTTPS after cutover. Preserved the pre-change Kibana,
  Compose, and runtime-client files in the ignored rollback directory. See the
  [cutover and rollback commands](../day4-deployment-runbook.md#kibana-https-cutover-and-rollback).
- All 118 offline tests passed. Detection contracts, strict configuration,
  config-only Compose, Ruff, actionlint, artifact and formatting policy, local
  links, and both Gitleaks checks passed. No service was recreated, no live
  API request was sent, and no role, user, service credential, rule, alert,
  telemetry or volume was modified.
- **RECORD BEFORE** the separate cutover approval. Capture the loopback HTTP
  browser address and sanitized baseline health while the existing service
  still runs. Active effort was not measured.

## 20 November 2026 — Approved Kibana-only HTTPS cutover

- **RECORD BEFORE:** Captured a sanitized terminal baseline. HTTP
  `127.0.0.1:5601/api/status` returned 200, Kibana and Elasticsearch were
  Docker-healthy, and n8n was running. The existing Kibana 8.13.0 container
  used `infra_kibana_data`. Read-only Elasticsearch queries found 14
  P1-PS-001 alerts and 58 synthetic source records. Cluster health was yellow.
- The isolated Kibana 8.13.0 mount check passed for the CA, server leaf and
  key. All three rollback files matched the pre-change versions. Ran the
  approved Compose command targeting only Kibana, with dependency recreation
  and image pulls disabled. Compose reported Kibana healthy.
- **RECORD AFTER:** The served leaf matched the prepared certificate.
  CA-verified TLS 1.2 handshakes passed for `127.0.0.1` and `localhost`. The
  wrong hostname and untrusted CA were rejected. The old plaintext status
  probe failed. Kibana's authenticated status reported overall availability
  and an available Elasticsearch integration.
- P1-PS-001 remained disabled and its managed fields matched the committed
  artifact. All 14 alert IDs and selected fields matched the pre-cutover
  snapshot. The 58-record source count and yellow cluster health matched
  the baseline. Elasticsearch and n8n container identities were unchanged,
  and Kibana retained `infra_kibana_data`.
- No rollback was needed. No role, credential, detection rule, alert or
  telemetry write was performed. The browser sign-in and the first live
  connected-planner request were outside this verification. Terminal evidence
  was captured; no separate video recording is claimed. Active effort was
  not measured.

## 20 November 2026 — Dedicated detection reader provisioned

- **RECORD BEFORE:** Confirmed trusted Kibana 8.13.0 availability, no existing
  `p1_detection_reader` role or user, and P1-PS-001 disabled in the default space.
- Created the reviewed Kibana role and a native user named
  `p1_detection_reader` with only that role. The role grants only
  `feature_siem.read` in `space:default`, with empty Elasticsearch cluster,
  global, index and run-as grants. Generated a unique password in a restricted,
  Git-ignored local file for the pending validation window.
- **RECORD AFTER:** Native authentication passed. Effective privilege checks
  confirmed default-space Security Read and denied rule management, other-space
  Security Read, source and alert/list index access, cluster management,
  security administration and own API-key management. An authenticated
  single-rule permission probe returned the expected disabled P1-PS-001.
  Denials were checked through privilege introspection. No write was attempted
  as the reader.
- The permission probe was separate from the connected-planner command. The
  first live planner invocation and closing the reader's validation window
  remain pending. No existing operator, rule, alert, telemetry or service
  configuration was changed. Active effort was not measured.

## 20 November 2026 — First live planner blocked and offline compatibility correction

- The separately approved connected-planner command ran once as
  `p1_detection_reader` against the default-space P1-PS-001 route over trusted
  HTTPS. It returned `BLOCKED` with exit 1 and the sanitized diagnostic
  `Unknown Kibana rule response fields`. The schema check stopped processing
  before UUID, disabled-state and drift comparison. The earlier permission
  probe had independently confirmed the expected UUID and disabled state.
- Offline inspection of the tagged
  [Kibana 8.13.0 serializer](https://github.com/elastic/kibana/blob/v8.13.0/x-pack/plugins/security_solution/server/lib/detection_engine/rule_management/normalization/rule_converters.ts#L486)
  identified the legacy `output_index` default. Adding this field alone to a
  synthetic response reproduced the live diagnostic. The suppressed live body
  provides no evidence about additional response fields.
- The adapter now accepts `output_index` only when it is absent or exactly the
  serializer's empty-string default. The field is excluded from the managed
  projection. Other unknown and unsupported behavior fields still block.
  Mocked fixtures verified `NOOP`, field-name-only `DRIFT`, malformed and
  non-default `output_index`, unknown fields, wrong UUID and enabled rules.
- All 119 offline tests passed. Local CI-equivalent checks passed for
  detection contracts, static configuration, config-only Compose, Ruff,
  actionlint, artifact policy, diff formatting and both Gitleaks scans.
  No follow-up live request or live change was made. Exact lab compatibility
  remains pending a separately approved rerun. Active effort was not measured.

## 20 November 2026 — Controlled deployment engine with mocked Kibana responses

- Connected the Git planner, transition core, and strict 8.13 response projection
  through an injected fake Kibana exchange. The engine supports update of the
  expected existing disabled P1-PS-001 UUID. Apply rebuilds the approved plan
  under the shared lock, requires explicit write authorization, and sends a
  single PATCH containing only changed managed fields and disabled state.
- No-op applies issue zero PATCH requests. Verified receipts retain the prior
  managed configuration and bind the target, revision, UUID and artifact-plan
  digest. Rollback requires separately approved receipt provenance and an
  unchanged post-apply state. Failures after PATCH initiation yield an
  uncertain outcome, a read-only reconciliation probe and no automatic retry.
  The sanitized in-memory audit records operation, result and digests.
- Reviewed the tagged 8.13.0 patch route and alerting update/key code. The
  route has no caller revision precondition. Updates can change execution-key
  attributes, and restoring configuration cannot restore execution credentials.
  The runbook records the shared-lock boundary and the requirements for a
  durable journal, exclusive maintenance window and separately verified writer.
- All 127 offline tests passed, including eight new mocked Kibana tests. The
  detection contracts, static configuration, config-only Compose, Ruff,
  actionlint, artifact policy, formatting and both Gitleaks scans passed.
  No live Kibana request, deployment credential, service change, commit
  or push occurred. Active effort was not measured.

## 20 November 2026 — Durable deployment journal and recovery

- Added a mode-`0600` journal in an owned mode-`0700` local directory. It binds
  the target, space and expected UUID to the approved commit, approval and
  artifact hashes, prior revision and managed snapshots. Under the shared
  directory lock, each transition flushes an atomic replacement and the
  directory before the engine proceeds.
- A mutation persists `PREPARED` and `APPLYING` before PATCH. Verified
  acknowledgement and readback persist `VERIFIED`. An ambiguous attempt is
  `UNCERTAIN`, or remains `APPLYING` if interrupted before a terminal record
  can be persisted. Unresolved or corrupt journals block later writes using
  that directory. The read-only status comparison leaves journal bytes
  unchanged. Explicit approval can close a never-started `PREPARED` record
  as `FAILED`. An attempted or uncertain write stays blocked for operator
  investigation.
- All 132 offline tests passed, including five new recovery regressions for
  interrupted transitions, restart, failed atomic replacement, failed
  terminal persistence, and malformed, corrupt, insecure or foreign
  journals. Local detection contracts, config-only Compose, strict
  configuration, Ruff, actionlint, artifact and formatting policy, and both
  Gitleaks scans passed.
- Recovery assumes a protected local filesystem and cooperating processes
  using one journal directory per target. The tests simulate interruption and
  I/O faults. They do not exercise a host power loss or an actual Kibana write.
  No live requests, credentials, infrastructure changes, commit or push.
  Active effort was not measured. **NO RECORDING NEEDED** for mocked checks.

## 20 November 2026 — Fixed-profile canary deployment implementation

- Added the fixed `P1-D4-CANARY-001` profile for space `p1-day4-canary`.
  The Git planner binds both committed YAML configurations, the shared ES|QL,
  and the mapping. The exact query is pinned to the canary-only synthetic
  source, and the configurations differ only by `interval` from 5m to 6m.
  The canary artifacts are present in the working tree and need separate
  commit approval before the planner can load them from Git.
- Added a canary-only HTTPS exchange with CA and IP verification. The
  write path requires the expected UUID, explicit approval, a matching
  plan, a durable APPLYING record, and a one-use authorization for the
  exact PATCH body. The transport permits only canary GET and PATCH,
  with disabled state and the approved interval as the only configuration
  change. The P1-PS-001 connected entry point remains read-only.
- All 140 offline tests passed, including eight canary cases exercising
  mocked HTTPS, apply, no-op, rollback, denials, pinned Git artifacts and
  crash reconciliation without PATCH retry. Strict config, offline
  detection contracts, config-only Compose, Ruff, actionlint, artifact
  policy, formatting, and both Gitleaks scans passed.
- The [exact setup proposal](../day4-deployment-runbook.md#fixed-canary-setup-proposal)
  describes the separate space, disabled seed, writer and grant checks,
  journal, maintenance window, approvals and recording checkpoints. Live
  writer privilege requirements and the actual Kibana response contract
  remain unverified. No live request, space, rule, source, identity,
  credential, infrastructure action, commit or push. Active effort was
  not measured. **NO RECORDING NEEDED** for the mocked validation.

## 20 November 2026 — Approved canary space reservation

- **RECORD BEFORE:** Verified the existing setup identity and trusted Kibana
  8.13.0 over loopback HTTPS. The default space and disabled P1-PS-001 were
  readable. `GET /api/spaces/space/p1-day4-canary` returned HTTP 404. The
  proposed canary writer and planned canary source and space-specific
  alert/list indices were absent in read-only preflight checks.
- Rechecked the preconditions and submitted one create-only
  `POST /api/spaces/space` for ID `p1-day4-canary`, display name
  `P1 Day 4 Canary`, and no disabled features. Kibana returned HTTP 200.
  No overwrite, update, or retry was used.
- **RECORD AFTER:** The space GET returned HTTP 200 with the expected ID.
  Its space-scoped rule inventory was empty. The same P1-PS-001 lookup
  returned HTTP 404 in the canary space and HTTP 200 in `default`. The
  default rule remained disabled with unchanged UUID, revision and update
  timestamp. These are sanitized terminal observations.
- Space reservation only. No rule, writer, role, source index or credential
  was created. No rule, alert or telemetry writes occurred. Detection
  initialization and canary seeding were outside this approval.
  Active effort was not measured.
- **Repeat verification, 20 November 2026:** Trusted setup access returned
  HTTP 200 for the existing matching canary space. The create request was
  skipped. The rule inventory remained empty and P1-PS-001 returned HTTP
  404 in the canary space. Its default-space UUID, revision, update timestamp,
  and disabled state stayed unchanged during the check. No canary writer or
  planned canary indices were found. The repeat used read-only requests.

## 20 November 2026 — Approved canary writer provisioning

- **RECORD BEFORE:** Trusted Kibana 8.13.0 was available. Verified the existing
  setup identity, the matching empty `p1-day4-canary` space, and absence of the
  proposed writer role, user and local credential file. P1-PS-001 was disabled
  in the default space.
- Provisioned the role `p1_day4_canary_writer` with Security All for only
  `p1-day4-canary` and no Elasticsearch cluster, index or run-as grants.
  Kibana returned HTTP 204. Created the native user with the same name and
  that sole role. Stored only its new credential in a Git-ignored mode-`0600`
  file under the owned, restricted local certificate directory.
- **RECORD AFTER:** Native authentication and privilege introspection confirmed
  exactly `feature_siem.all` in `space:p1-day4-canary` and no global, cluster,
  index or run-as grants. Checks denied default-space Security, P1 and
  unrelated index access, security administration and own API-key management.
  The scoped rule inventory returned HTTP 200 and was empty. The writer's
  lookup of default-space P1-PS-001 returned HTTP 403. The setup identity
  verified the default rule's UUID, revision, update timestamp and disabled
  state remained unchanged.
- No additional grants were added. Write-specific Kibana 8.13 privilege
  requirements remain unverified because no PATCH was attempted. No rule,
  index, or telemetry was created, and no existing credential or
  infrastructure configuration changed. Active effort was not measured.
- **Repeat verification, 20 November 2026:** The existing writer credential
  remained Git-ignored and owner-only at mode `0600`. Effective privileges
  still showed only canary-space Security All. The empty canary inventory
  returned HTTP 200 and default-space P1-PS-001 returned HTTP 403 for the
  writer. Privilege introspection again denied default-space rule management,
  unrelated index writes and security administration. The default rule's
  identity, revision, update timestamp and disabled state were unchanged.
  No role, user or credential was recreated, and no PATCH was sent.

## 21 November 2026 — Approved one-time canary baseline seed

- **RECORD BEFORE:** Loaded the baseline from commit
  `8eb6d7584e80a7f29f1425e727063a8f0acbf7f9` and verified artifact-plan
  SHA-256 `cbfaeea450b423d579cb034a971d405bdabdbd456519d12bcd0b5ed08fd87ebc`.
  Trusted Kibana 8.13.0 showed an empty `p1-day4-canary` rule inventory and
  the stable canary ID returned HTTP 404. The canary source and space-specific
  alert/list indices were absent. The shared Endpoint exception list already
  existed, so the 8.13 create route could use it without adding another
  resource.
- Using the existing setup identity, sent one
  `POST /s/p1-day4-canary/api/detection_engine/rules`. The committed
  payload referenced only `logs-p1-day4-canary-synthetic`, with
  `enabled: false`, empty actions and a `5m` interval. Kibana returned
  HTTP 200 without a source index or privilege change.
- **RECORD AFTER:** The create response and independent GET agreed on
  `P1-D4-CANARY-001`, UUID `6c1adcbc-dade-43c3-b838-938048ca6738`,
  revision `0`, and the exact committed managed configuration. It remained
  disabled with empty actions and a `5m` interval. The shared Endpoint list
  metadata and canary index absence were unchanged. Default-space
  P1-PS-001 remained disabled with unchanged UUID, revision and update time.
- No data ingestion, rule activation, PATCH, credential or privilege change
  occurred. The writer has yet to be used for a canary PATCH. Active effort
  was not measured.

## 22 November 2026 — Day 4 canary deployment plan prepared

- Built the baseline and candidate from commit
  `8eb6d7584e80a7f29f1425e727063a8f0acbf7f9`. Independently hashed all four
  committed blobs and matched the planner's manifest. The baseline
  artifact-plan SHA-256 matched the seed record. Candidate artifact-plan
  SHA-256 is `132f6661db36853a161b02e012f70475ab4db6a7dba7708f2264068ace2ae5e8`.
- Native writer authentication and effective grants were verified read-only.
  The sole grant is Security All in `p1-day4-canary`, with no Elasticsearch
  cluster, global, index or run-as grants. The fixed-profile GET over CA-verified
  HTTPS confirmed UUID `6c1adcbc-dade-43c3-b838-938048ca6738`, revision `0`,
  and the exact disabled, action-free, committed `5m` baseline.
- The sole planned change is `interval` from `5m` to `6m`. The owned,
  Git-ignored journal directory passed the permission and lock checks. Journal
  status was `EMPTY` before and after planning. Saved the proposed plan under
  that directory with mode `0600`. Its SHA-256 is
  `d86c7e5f508631ff736d7d94f1d4fe3ff49edfc5a581104fb648e9ccac79170d`.
- Apply awaits separate approval of that exact digest and an exclusive
  maintenance window. No journal write transition, PATCH, or live modification
  occurred. Any additional PATCH-specific privilege requirement is unverified.
  Active effort was not measured.

## 22 November 2026 — Approved one-time live canary apply

- **RECORD BEFORE:** User confirmed the exclusive maintenance window with
  other canary editors and automation paused. The writer still had only
  Security All in the canary space and no Elasticsearch privileges. The
  journal was `EMPTY`. The disabled, action-free canary matched the
  retained revision-0 `5m` baseline and approved plan SHA-256
  `d86c7e5f508631ff736d7d94f1d4fe3ff49edfc5a581104fb648e9ccac79170d`.
- The journal persisted `PREPARED` and `APPLYING`. The writer sent exactly
  one `PATCH /s/p1-day4-canary/api/detection_engine/rules`, scoped to UUID
  `6c1adcbc-dade-43c3-b838-938048ca6738`, with interval `6m` and
  `enabled: false`. Kibana returned HTTP 200. No additional privileges
  were needed for this PATCH.
- **RECORD AFTER:** Independent GET returned HTTP 200 with the same UUID,
  revision `1`, interval `6m`, disabled state and empty actions. The journal
  reached `VERIFIED`, and the mode-`0600` ignored receipt was verified
  against SHA-256
  `88326cb3bd439605bcdd7d709dbdf3172e9e7e9f5f8e15a4baa884be1f3ac586`.
  A fresh read-only plan returned `NOOP` with SHA-256
  `3d4e5e08241ff67e6f523f4e230e2f386902889bea263a18e9ccbe3549eb4a76`.
- No retry, rollback, default-space request or other live write occurred.
  macOS denied VS Code terminal automation. A sanitized transcript was
  retained for manual display. Active effort was not measured.

## 22 November 2026 — Read-only canary rollback plan

- Verified the stored apply receipt against the prior approved plan and the
  latest `VERIFIED` apply journal record. Rebuilt both disabled variants from
  commit `8eb6d7584e80a7f29f1425e727063a8f0acbf7f9`. The journal has no
  unresolved operation. Writer grant checks still showed Security All in
  `p1-day4-canary` only and no Elasticsearch privileges.
- The fixed-profile HTTPS GET matched the receipt exactly. UUID
  `6c1adcbc-dade-43c3-b838-938048ca6738` is at revision `1`, interval `6m`,
  disabled, with no actions. The sole rollback diff restores `interval`
  to the committed `5m` baseline.
- Rollback approval binds the verified apply receipt SHA-256
  `88326cb3bd439605bcdd7d709dbdf3172e9e7e9f5f8e15a4baa884be1f3ac586`.
  The saved JSON target is an array and the engine compares an in-memory
  tuple. The read-only runner normalized the already-validated target
  in memory and confirmed the same receipt digest. The saved receipt,
  journal, and engine code were unchanged.
- The rollback PATCH requires separate approval and a confirmed exclusive
  maintenance window. No PATCH or live modification occurred during
  planning. Active effort was not measured.

## 26 November 2026 — Final read-only rollback and preservation verification

- An independent, CA-verified GET as the canary writer matched the persisted
  rollback receipt and the committed disabled baseline. The canary
  `P1-D4-CANARY-001` in `p1-day4-canary` retained UUID
  `6c1adcbc-dade-43c3-b838-938048ca6738`. It was at revision `2`, interval
  `5m`, disabled, with no actions.
- Verified the protected rollback receipt SHA-256
  `97146e081358ff9cef6e2528b988c9e1cf9e9377fbcfdb75391dcd087e3668b5`.
  The receipt bound to the approved apply receipt and the rollback result
  digest in the journal. Both the apply and rollback records reached
  `PREPARED` → `APPLYING` → `VERIFIED`. No unresolved record remained.
- Default-space P1-PS-001 remained disabled and its managed configuration
  matched Git. All 14 original alert IDs, source event IDs, severity and risk
  scores matched Day 2 evidence. All 58 synthetic source payloads matched
  the two retained fixture batches. The 29 recorded runtime source IDs,
  backing indices, versions and timestamps also matched.
- **RECORD AFTER:** Sanitized verification reported revision `2`, restored
  `5m` interval, disabled state, receipt digest and preservation counts.
  This verification issued only read-only requests. No live resource,
  credential, journal or receipt was modified. Active effort was not measured.

### Day 4 closeout from existing evidence

- Revalidated the persisted receipt and journal offline against the original
  apply approval and committed baseline. The 26 November independent
  readback above is the live evidence. Closeout repeated no live test.
- The 14 alert identity, source and priority tuples matched the retained Day 2
  runtime result and independent audit. The live comparison covered all 58
  stored source payloads. Document version metadata was compared for the 29
  runtime records with retained version evidence.
- This milestone verifies disabled-rule configuration apply, no-op and
  rollback. It does not verify canary activation, scheduled execution or
  execution-key restoration. The corrected default-space connected planner
  was not rerun after its first blocked attempt. Default rule preservation
  was independently verified with the Day 2 read-only validation client.
- Recorded the local Video 4 transcript without altering prior video
  sections or media. New footage is unconfirmed. Writer and canary cleanup
  remain separate approval items. No live resources were changed for closeout.
