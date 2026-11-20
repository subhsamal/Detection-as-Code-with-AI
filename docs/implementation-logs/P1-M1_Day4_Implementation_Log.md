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
