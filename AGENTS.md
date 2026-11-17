# Codex Project Instructions — Detection-as-Code-with-AI

## Project scope
- This repository is **P1: AI-Augmented Detection Engineering Platform**.
- Build incrementally on the verified local Elasticsearch, Kibana/Elastic Security, and n8n Docker Compose foundation.
- The README describes both implemented and **planned** capabilities. Inspect working files and tests; do not assume planned MCP, agents, telemetry simulators, detection rules, or CI/CD already exist.
- Keep this career-development project separate from any commercial cybersecurity product discussions.

## Execution workflow
1. At the start of a task, inspect repository state and summarize the objective, relevant files, and acceptance criteria.
2. For routine, reversible, in-scope coding and read-only checks, proceed autonomously. Run appropriate validation and tests.
3. **Stop and request user approval** before changing infrastructure or authentication, creating/deleting credentials, destructive commands, altering persistent data, adding dependencies or paid services, deploying to an external environment, publishing content, or pushing/merging Git changes.
4. If a test cannot run, explain why and report only evidence actually observed. Never call static validation a runtime test.
5. Finish with a concise report: changes, test results, risks/limitations, recording opportunities, and next recommended step.

## Git and pull requests
- Keep `main` stable. Perform feature work on focused branches such as `feature/p1-first-detection-rule`, `fix/<description>`, or `docs/<description>`.
- For new features, follow **branch → tests/review → PR → merge**. Prefer squash merge after approval.
- Never force-push. Do not commit or push automatically without explicit user approval.
- Before staging and publishing, check changed files and diffs for secrets and accidental personal information. Verify `.env` and secret files are excluded.
- Existing Day 1 baseline: commit `747947d1c5b0cc5a9d347ec4a6c4d46b123a5e15`.

## Security and infrastructure
- Never print, echo, paste into reports, or commit passwords, API keys, service-account token values, `.env` contents, or unredacted configuration output.
- Preserve local-only published port bindings (`127.0.0.1`) for Elasticsearch, Kibana, and n8n unless approved otherwise.
- Preserve named Docker volumes and existing data. Do not run `docker compose down -v`, destructive cleanup, or unnecessary container recreation.
- Kibana uses `KIBANA_SERVICE_ACCOUNT_TOKEN` through `infra/.env` and Compose; don't revert to embedded credentials.
- n8n uses built-in user management; do not reintroduce legacy `N8N_BASIC_AUTH_*` settings. The intended workflow mount is `../n8n/workflows` relative to `infra/docker-compose.yml`.
- Use synthetic, non-sensitive telemetry for detection tests. Explain detection limitations and test against both suspicious and benign events.
- Prefer least privilege and explicit review of any AI-agent tools or automated response actions.

## Detection engineering standards
- Version detection rules as code with clear identifiers, purpose, data prerequisites, query, severity/risk, ATT&CK mapping, expected matches, benign counterexamples, and deployment/rollback instructions.
- Verify the installed Elastic version, license, privileges, index mappings, and Elastic Security rule API before choosing an implementation.
- Validate syntax, deploy only to the local lab after approval, and record observed alert results, false-positive considerations, and known gaps.

## Documentation
- Keep GitHub-facing technical documentation truthful about **implemented vs. planned** functionality.
- Maintain a chronological implementation log under `docs/implementation-logs/`, recording decisions, commands (sanitized), test evidence, open issues, and estimated active effort (clearly labeled when not measured).
- Update relevant README/setup documentation when functionality changes, but do not silently rewrite the project's overall vision or roadmap.
- Personal content-production materials — article drafts, video recording plans, voice-over scripts, and publication schedules — are managed in ChatGPT, **not committed to this repository**, unless the user explicitly changes that decision.

## Recording checkpoints
- Before any visually useful or hard-to-reproduce implementation milestone, **flag `RECORD BEFORE`** and specify exactly what screen or state to capture. Ask the user before proceeding if recording the pre-change state matters.
- After a demonstrable outcome, flag `RECORD AFTER` with the safe demonstration to capture.
- Otherwise state `NO RECORDING NEEDED` where helpful.
- Never request filming credentials, `.env` contents, private account details, or sensitive logs. Recording and voice-over editing are deferred to project milestones rather than every task.

## Current Day 2 context
- Active branch: `feature/p1-first-detection-rule` (verify before working).
- Immediate objective: assess Elastic Security readiness, then implement and validate the first suspicious PowerShell **synthetic-event** detection rule.
- Before implementation, assess prerequisites and propose a minimal plan for approval. Don't invent implementation or test outcomes.
