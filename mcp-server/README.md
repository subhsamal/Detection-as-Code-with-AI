# Day 5 Phase 1 MCP server

The stdio server ships with deterministic synthetic rule and alert fixtures. Its two tools are scoped to `P1-PS-001` in the `default` space. See the [Day 5 design](../docs/day5-mcp-design.md) for the contracts and live integration plan.

From the repository root, with Python 3.11 available, install into an isolated environment and run the offline suite.

```sh
work_dir=$(mktemp -d)
python3.11 -m venv "$work_dir/venv"
"$work_dir/venv/bin/python" -m pip --isolated --disable-pip-version-check install \
  --require-hashes --only-binary=:all: --index-url https://pypi.org/simple \
  -r mcp-server/requirements.lock
"$work_dir/venv/bin/python" -B -m unittest discover -s mcp-server/tests
```

Configure the MCP host to launch the venv interpreter. Pass the absolute path to `server.py` and an absolute audit directory path. Create the audit directory with mode 0700 under a directory you control.

```sh
mkdir -m 700 "$work_dir/audit"
"$work_dir/venv/bin/python" -B "$PWD/mcp-server/server.py" --audit-directory "$work_dir/audit"
```

Use numeric JSON-RPC request IDs. Stdio input frames are limited to 8 KiB and malformed or unsupported frames terminate the session. Tool errors use fixed codes with a generated request ID. The private JSONL audit file is capped at 256 KiB. A full or unavailable audit file blocks tool results. Stop the server before archiving it.

For a synthetic alert demo, use a UTC window from `2026-01-01T11:00:00Z` to `2026-01-01T13:00:00Z`. Pass the returned cursor with the same filters and limit. Cursors expire after five minutes or when the server restarts.

For an approved lock update, regenerate with uv 0.9.13 and review the resolved versions and hashes before syncing.

```sh
uv --no-config pip compile mcp-server/requirements.in --python-version 3.11.14 \
  --universal --generate-hashes --only-binary :all: --no-header \
  --index-url https://pypi.org/simple --output-file mcp-server/requirements.lock
```

## Phase 3A rule backend

The default backend remains `synthetic`. Select `--backend kibana` with
`--ca-file`, `--expected-uuid`, and exactly one credential source
(`--keychain` or `--password-file`) to enable the single rule read. Both tools retain the same schemas. In Kibana mode,
`list_detection_alerts` returns `BACKEND_UNAVAILABLE` without a network call.

Kibana mode uses the existing `p1_detection_reader` identity against
`https://127.0.0.1:5601`. On macOS, `--keychain` reads the existing login Keychain item for service
`P1 Day 5 Elasticsearch reader` and account `p1_detection_reader` directly
through Security.framework. Use the same interactive macOS login context
as the verified reader setup. For file mode, use an owner-only regular file
(mode 0600, no symlinks or additional hard links) containing only the password,
optionally followed by one newline. Keep it outside the checkout or at its
existing Git-ignored path. Supply the trusted lab CA and the rule UUID from
independent approved evidence. TLS 1.2 or newer, certificate chain and loopback
IP identity are required. Every accepted rule call performs one GET with no
redirects, retries or request body. The transport uses a 10-second socket
timeout and a 256 KiB response limit.

### One-shot validation pending approval

Before approval, confirm that the existing identity still has only Kibana
Security Read (`feature_siem.read`) in `space:default` and no global,
Elasticsearch cluster, index, or run-as grants. Day 4 verified this role
shape and the specific GET. Current effective privileges and credential
availability require independent confirmation. Stop on missing evidence.
[Day 4 privilege evidence](../docs/implementation-logs/P1-M1_Day4_Implementation_Log.md#20-november-2026--dedicated-detection-reader-provisioned) ·
[Elastic 8.13 detection permissions](https://www.elastic.co/guide/en/security/8.13/detections-permissions-section.html)

After explicit approval for one live read, run this once from the repository
root in the macOS login context with the verified Keychain item. Set
`mcp_python` to the isolated Python interpreter. The probe pins the
independently reviewed UUID `3c4ab643-839d-4d94-a2f5-8743aa4b097f`.

```sh
audit_dir=$(mktemp -d /private/tmp/p1-day5-mcp-audit.XXXXXX) &&
  "$mcp_python" -B mcp-server/probe_rule.py --execute-approved-get \
    --audit-directory "$audit_dir" --ca-file "$PWD/infra/certs/ca.crt"
```

The probe places a 15-second deadline on its stdio session and invokes the
tool once with `{"space":"default","rule_id":"P1-PS-001"}`. Its sole lab
request is `GET https://127.0.0.1:5601/api/detection_engine/rules?rule_id=P1-PS-001`.
It prints projected rule metadata or a fixed `BLOCKED` code. Check the expected
UUID and current state in the projected result and record the sanitized audit
outcome. Treat a timeout, denial or unexpected result as a stop.

### Retry after a Keychain prompt timeout

Use `--authorize-then-confirm` with the one-shot command. Launch it in the
interactive macOS login session and choose **Allow** if Keychain prompts.
The stdio child reads the credential before MCP starts and keeps it in memory.
Wait for `KEYCHAIN_READY | no Kibana request sent`. After explicit live
approval, enter `retry` at the prompt to start the 15-second MCP session.
Any other input stops before the GET. Do not grant permanent Keychain access
for this procedure.
