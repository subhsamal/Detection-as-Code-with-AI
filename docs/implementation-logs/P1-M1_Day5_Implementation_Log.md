# P1-M1 — Day 5 Implementation Log

## 26 November 2026 — Read-only MCP design reviewed

- Verified GitHub `main` at `6b6dd424f9b934e5d31c74018d9e4b4d5ea0a132`.
  PR #4 is merged and the MCP directory still contains only a placeholder.
  Reviewed the existing HTTPS transport, deployment projection, detection
  roles, Day 2 and Day 4 evidence, architecture and CI configuration.
- Prepared the [Day 5 design](../day5-mcp-design.md) with two fixed-profile
  read tools, separate rule and alert permissions, bounded pagination and
  output, local audit handling, and mock/live approval boundaries.
- Proposed official `mcp==2.3.0` with its stdio API and Python 3.11.14 to
  match CI. The local default Python is 3.9.6. Package resolution and
  host compatibility smoke tests remain pending separate approval.
- Appended a local recording plan for the mocked and separately authorized
  live checkpoints. **NO RECORDING NEEDED** for design review.
- No application code, dependencies, credentials or infrastructure were
  changed. No Elastic lab requests were made. Active effort was not measured.

## 26 November 2026 — Phase 1 offline foundation implemented

- Started `feature/p1-day5-mcp-foundation` from the reviewed main revision.
  Verified official `mcp==2.3.0` and `mcp-types==2.3.0` in an isolated
  Python 3.11.14 environment. Installed 28 distributions from the
  hash-locked dependencies in a separate clean environment using the new
  CI step. The initial interpreter download timed out. A verified copy
  of the same standalone release provided the interpreter.
- Implemented the fixed `default` / `P1-PS-001` tool contracts over
  local stdio using the official SDK's low-level `Server` API. This
  lets the server advertise exact schemas, validate bounded frames
  before SDK parsing, and return sanitized errors. The backend uses
  deterministic synthetic fixtures. Alert pages use signed, expiring
  continuation cursors, a 50-item page limit, and a 200-item traversal
  cap. Tool calls require a writable private, bounded local audit file.
- Added the fake-backend suite to the existing detection-tests job in
  a separate virtual environment. Local validation passed 9 MCP tests
  including actual subprocess discovery and invocation, pagination,
  denials and failure handling, plus all 140 existing detection tests.
  Offline detection contracts, strict configuration, artifact policy,
  Ruff, documentation links and Git diff checks passed. Hosted GitHub Actions was not run.
- **RECORD AFTER.** Capture synthetic tool discovery, an allowed call,
  a denied space and the corresponding sanitized audit record in a local
  terminal. See the [offline run instructions](../../mcp-server/README.md).
- Third-party MCP host compatibility and both live read adapters remain
  pending. No Elastic lab requests, credentials, privilege changes,
  infrastructure changes, commits or pushes. Active effort was not measured.

## 26 November 2026 — Phase 3A Kibana rule backend implemented offline

- Added explicit `kibana` mode to the MCP stdio server. Synthetic remains
  the default, including in CI. The two tool schemas are unchanged.
  Kibana mode limits HTTPS to one fixed GET per accepted rule call for
  `P1-PS-001` in `default`. It requires an independently reviewed UUID,
  an explicitly trusted lab CA, and the existing reader's protected password
  file. Alert calls are denied before any network access.
- Reused the Day 4 TLS transport and scoped reader with a dedicated metadata
  projection. Deployment callers retain their existing stricter deployment
  projection. MCP returns actual enabled state and omits upstream queries,
  action payloads, usernames and execution metadata. Unsupported responses
  and transport or auth failures return fixed codes.
- Verified least-privilege requirements against the Elastic 8.13 permissions
  guide and the Day 4 permission evidence. Day 4 established default-space
  Security Read and no cluster, index, global, or run-as grants for the
  existing reader. Current effective privileges and credential availability
  were not checked against the lab.
- Prepared a single-call MCP probe with a 15-second session deadline and a
  sanitized result. **RECORD BEFORE** a separately approved live check:
  capture the reviewed scope, trusted CA selection and privilege evidence,
  keeping credential paths and contents off screen. See the
  [one-shot procedure](../../mcp-server/README.md#one-shot-validation-pending-approval).
- Offline MCP suite passed 16 tests, including the 9 original synthetic
  tests and 7 new mocked tests. All 140 detection regression tests, Ruff,
  actionlint, offline contracts, configuration and artifact checks, and
  the redacted working-tree secret scan passed. No live lab requests,
  writes, alert-index reads, new identities or privilege changes.
  Active effort was not measured.

## 26 November 2026 — Phase 3A live MCP probe prepared

- Configured the reviewed default-space P1-PS-001 UUID
  `3c4ab643-839d-4d94-a2f5-8743aa4b097f` as the one-shot probe baseline.
  The probe starts the real Kibana backend over MCP stdio and checks the
  returned identity after the backend verifies it against the same baseline.
- Added direct, read-only macOS Keychain retrieval for the existing detection
  reader. The one-shot probe selects that source explicitly. Synthetic remains
  the default and both MCP tool schemas are unchanged.
- Offline testing passed all 19 MCP tests, including Keychain selection,
  credential error redaction, exact Kibana routing and rejection of an
  unexpected returned UUID. The live MCP test remains pending approval.
  No live request, credential change, privilege change, rule change or
  infrastructure change was made during preparation.

### First live MCP-to-Kibana verification

- The first attempt timed out after the macOS Keychain authorization prompt.
  Its audit contained only `START`. Whether Kibana received that request
  remains unconfirmed.
- Moved Keychain authorization ahead of MCP initialization for the controlled
  retry. At 13:01:56 UTC on 26 November, the user ran one confirmed retry in
  the VS Code terminal. Its projected result matched the reviewed UUID for
  `P1-PS-001` in `default` and showed revision `2`, interval `5m`,
  and `enabled: false`. The local audit independently showed `START`
  followed by `OK`, one result, and 150 ms tool duration.
- **RECORD AFTER.** Capture the existing sanitized output and audit outcome.
  No additional GET is needed for recording.
