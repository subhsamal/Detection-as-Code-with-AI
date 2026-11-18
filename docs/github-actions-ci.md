# Offline GitHub Actions CI

Prepared 18 November 2026. The workflow passed its first [GitHub-hosted run](https://github.com/subhsamal/Detection-as-Code-with-AI/actions/runs/44337482225) on commit `e1333f203df8e1e25da814432b72f6778f4a66cb`. All three validation jobs and the completion gate succeeded. [PR #2](https://github.com/subhsamal/Detection-as-Code-with-AI/pull/2) targets `main` and awaits review; no merge or deployment was performed.

`.github/workflows/ci.yml` runs on pull requests targeting `main` and pushes to `main`. Three jobs run independently:

| Job | Checks |
|---|---|
| Detection tests and contracts | All tests discovered by unittest; rule/export/query parity, source mappings, metadata contract, schedule, alert limits and severity/risk mapping types |
| Configuration and code quality | Strict YAML/JSON, Python syntax, security configuration invariants, Compose config only, Ruff, actionlint and Git diff whitespace |
| Secrets and artifact policy | Ignored-secret/recording policies, prohibited publishable artifacts, Gitleaks on checked-out history and current publishable files |

`CI completion` depends on all three jobs and fails unless each reports `success`, including when a dependency fails, is skipped or is cancelled. An external cancellation can cancel the completion job itself; it does not produce successful validation. Repository branch-protection settings are not changed. Requiring this status before merge is a separate administrator decision.

## Security and dependencies

Jobs use `contents: read`, checkout without persisted credentials, no repository secrets, no deployments, no uploaded artifacts and no live service calls. The completion job has no permissions and does not check out code. Validation jobs have ten-minute timeouts; completion has two minutes. Superseded pull-request runs can be cancelled. Untrusted pull requests use `pull_request`, never `pull_request_target`.

CI pins Python 3.11.14 and Ruby 3.3.10. Existing rule-export tests already require Ruby/Psych. YAML validation uses Psych's syntax tree without constructing tagged objects; it rejects duplicate keys, aliases, merge keys, custom tags and multiple documents. Plain scalars use a restricted YAML 1.2-style interpretation, keeping GitHub's `on` key as text. JSON rejects duplicate keys and non-finite numbers.

`scripts/ci/tools.lock.json` records immutable action SHAs and release SHA-256 values for Ruff 0.17.5, actionlint 1.7.12, Gitleaks 8.30.1 and Compose 5.3.0. Pins were checked against official upstream GitHub release/tag metadata and checksum manifests on 18 November 2026. Actions are checkout v7.0.1, setup-python v7.1.0 and setup-ruby v1.340.0. Binaries support Linux x86-64 CI and macOS ARM64 local validation. The installer downloads to an external temporary directory, verifies checksums before use, and extracts only the expected regular file. Checksums protect integrity relative to the reviewed lock; they are not an independent publisher signature. GitHub-hosted runner images and bundled standard libraries still receive platform updates.

Ruff enables correctness/import rules E4, E9 and F, without blanket ignores; this is not comprehensive style enforcement or security analysis. actionlint checks workflow syntax and expressions. Its optional ShellCheck and pyflakes engines are disabled explicitly to avoid unpinned runner dependencies. Bash gate behavior is covered by regression tests. No third-party Python package installation is required.

Compose receives an isolated environment, explicit non-secret placeholders, `/dev/null` as the environment file and `--no-env-resolution --quiet`. This checks configuration without loading local credentials, contacting Docker Engine, starting containers or verifying certificates. Placeholder strings cannot authenticate to the lab.

Gitleaks retains its default rules plus a private-key-header rule, without path or regex allowlists. Only four verified historical placeholder findings have exact commit/file/rule/line exceptions in `.gitleaksignore`; current-content scans explicitly use an empty ignore file. Its wrapper captures diagnostics, prints only file/line/rule metadata and removes temporary reports. The working-tree scan copies only Git-publishable files, excluding ignored local credentials and recordings. Artifact checks independently reject tracked secret paths; ignore rules alone cannot protect an already tracked secret. Secret scans are heuristic and do not guarantee absence of secrets.

## Local checks

Run from the repository root with Python 3.11 and Ruby available. The installer requires network access to official GitHub release assets; checks themselves require no lab credentials or services. Choose a temporary destination outside the checkout.

```sh
python3 -B scripts/ci/install_tools.py ruff actionlint gitleaks compose --destination /private/tmp/p1-ci-tools
python3 -B -m unittest discover -s detections/tests -p 'test_*.py' -v
python3 -B scripts/ci/validate.py contracts
python3 -B scripts/ci/validate.py config
python3 -B scripts/ci/validate.py compose --compose-bin /private/tmp/p1-ci-tools/compose
/private/tmp/p1-ci-tools/ruff check --no-cache .
/private/tmp/p1-ci-tools/actionlint -shellcheck= -pyflakes=
python3 -B scripts/ci/validate.py artifacts
python3 -B scripts/ci/validate.py format
python3 -B scripts/ci/secret_scan.py --mode git --gitleaks-bin /private/tmp/p1-ci-tools/gitleaks
python3 -B scripts/ci/secret_scan.py --gitleaks-bin /private/tmp/p1-ci-tools/gitleaks
```

## Offline versus runtime evidence

The ES|QL check is a repository-specific contract, not an Elasticsearch parser. It checks the reviewed Kibana 8.13 bracketed metadata/source form, YAML/query equality, field mappings and query limit. It cannot establish ES|QL grammar/type compatibility, query execution, index privileges, API-key ownership, scheduling, alert overrides or deduplication. Those require separately approved live Elastic 8.13 validation. CI neither enables nor updates the disabled lab rule and preserves detection logic and fixtures.

The workflow provides CI only. Deployment/CD remains gated by explicit approval. Public repositories generally receive standard GitHub-hosted runner usage free; private repositories consume the account's included allowance and may incur charges beyond it. No paid service or billing setting is configured. Three parallel jobs and full-history scanning consume runner time; download/network availability can fail a run.

## Initial findings and maintenance

Initial Gitleaks scans failed on four `curl-auth-user` findings in `docs/BUILD-MANUAL.md` at original lines 331, 366, 371 and 376. On 18 November 2026, each current example and its historical source at commit `388758e711371bad961799df71eb66d7e3228206` was verified to use the literal `YOUR_PASSWORD` placeholder, not actual credential material. Current examples now use `--user elastic` to prompt without a password argument. Their legacy HTTP context and write operations are explicitly distinguished from the current HTTPS lab and CI.

The user's approved historical false-positive policy is implemented using Gitleaks' [specific finding fingerprints](https://github.com/gitleaks/gitleaks#gitleaksignore): exactly four entries bind the reviewed commit, file, rule and original line. No commit-wide, file-wide or placeholder-regex exception exists. Current scans receive an empty ignore file, so these exceptions cannot suppress new working-tree findings. Regression tests verify the exception set, original placeholder evidence and scan-mode separation. No Git history, live credentials or infrastructure were changed. The pinned Gitleaks version must be revalidated when upgraded because fingerprint handling is upstream-defined.

Update tool versions and checksums together after reviewing upstream releases, then rerun all checks. Review action SHAs against their official tag objects. Rollback before publication is removal/reversion of these CI files and the test import cleanup; no infrastructure rollback is required. After publication, revert the CI commit through review. Keep any future live integration workflow separate and explicitly approved.
