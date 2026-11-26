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
