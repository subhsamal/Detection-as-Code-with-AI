# Detection-as-Code-with-AI — Pre-Build Document Pack

---

## Document 1 — Technology stack and versions

| Component | Tool | Version | Purpose |
|---|---|---|---|
| SIEM | Elasticsearch | 8.x (latest) | Event storage, detection rule engine |
| SIEM UI | Kibana | 8.x (latest) | Dashboards, rule management |
| Orchestration | n8n | latest | Alert routing, simple playbooks |
| IdP | Authentik | 2024.x | Identity provider, OIDC token issuer |
| IAP | Pomerium | latest | Identity-aware proxy, policy enforcement |
| AI gateway | MCP server (custom Python) | — | Tool gateway for AI agents |
| AI model | Claude API (claude-sonnet-4-6) | — | Co-pilot, auditor, triage agent |
| Language | Python | 3.11+ | All scripts and agents |
| Container | Docker Desktop (macOS) | latest | Runs all services |
| CI/CD | GitHub Actions | — | Lint, AI review, deploy pipeline |
| Version control | Git + GitHub | — | All code, config, policy as code |

---

## Document 2 — Docker services inventory

Every service that runs in Docker, what it needs, and what port it uses.

| Service | Image | Port | Depends on | Purpose |
|---|---|---|---|---|
| elasticsearch | docker.elastic.co/elasticsearch/elasticsearch:8.x | 9200 | — | Core data store |
| kibana | docker.elastic.co/kibana/kibana:8.x | 5601 | elasticsearch | UI and detection rules |
| n8n | n8nio/n8n | 5678 | — | Alert orchestration |
| authentik-server | ghcr.io/goauthentik/server | 9000, 9443 | postgres, redis | IdP UI and OIDC |
| authentik-worker | ghcr.io/goauthentik/server | — | postgres, redis | Background jobs |
| postgres | postgres:16 | 5432 | — | Authentik database |
| redis | redis:alpine | 6379 | — | Authentik cache |
| pomerium | pomerium/pomerium | 443, 80 | authentik | IAP proxy |
| mcp-server | custom (Python) | 8000 | elasticsearch | AI tool gateway |

**Phase 1 services (start here):** elasticsearch, kibana, n8n, mcp-server
**Phase 2 additions:** authentik-server, authentik-worker, postgres, redis, pomerium

Docker Desktop RAM allocation needed:
- Phase 1: 8GB minimum
- Phase 2 (all services): 12–16GB recommended

---

## Document 3 — Environment variables (.env)

All secrets and config live in `infra/.env` — never committed to git.

```
# Elasticsearch
ES_VERSION=8.13.0
ES_PORT=9200
ELASTIC_PASSWORD=changeme_strong_password
KIBANA_PORT=5601

# n8n
N8N_PORT=5678
N8N_BASIC_AUTH_USER=admin
N8N_BASIC_AUTH_PASSWORD=changeme

# Authentik
PG_PASS=changeme_postgres_password
AUTHENTIK_SECRET_KEY=changeme_50_char_random_string
AUTHENTIK_PORT=9000

# Pomerium
POMERIUM_SHARED_SECRET=changeme_32_char_random_string
POMERIUM_COOKIE_SECRET=changeme_32_char_random_string

# Claude API
ANTHROPIC_API_KEY=sk-ant-...

# MCP Server
MCP_PORT=8000
MCP_LOG_INDEX=mcp-audit-logs
```

**Generate random secrets on macOS:**
```bash
openssl rand -hex 32
```

---

## Document 4 — Elasticsearch index plan

Every index the platform writes to, what goes in it, and what reads from it.

| Index | Written by | Read by | Purpose |
|---|---|---|---|
| `logs-auth` | telemetry/simulators | Elastic detection rules | Synthetic auth events |
| `logs-process` | telemetry/simulators | Elastic detection rules | Synthetic process events |
| `beyondcorp-access` | Pomerium | Elastic detection rules | Per-request IAP decisions |
| `authentik-auth-events` | Authentik | Elastic detection rules | Login, MFA, group change events |
| `mcp-audit-logs` | mcp-server/audit_log.py | Elastic detection rules | Every AI agent tool call |
| `.kibana` | Kibana | Kibana | Dashboards and saved objects |
| `.siem-signals` | Elastic detection engine | n8n (webhook) | Fired alerts |

---

## Document 5 — Detection rules plan

Six starter rules — two per phase — each with its source index and MITRE mapping.

### Phase 1 rules

**Rule 1: PowerShell encoded command execution**
- Index: `logs-process`
- Logic: process name is powershell.exe AND command line contains `-EncodedCommand` or `-enc`
- ATT&CK: T1059.001 (Command and Scripting Interpreter: PowerShell)
- Severity: High

**Rule 2: Authentication brute force**
- Index: `logs-auth`
- Logic: same source IP with 5+ failed logins within 60 seconds
- ATT&CK: T1110 (Brute Force)
- Severity: Medium

**Rule 3: MCP agent tool call anomaly**
- Index: `mcp-audit-logs`
- Logic: agent calls a tool outside its defined allowlist, OR call volume exceeds 3 standard deviations from 7-day baseline
- ATT&CK: (internal — AI governance detection)
- Severity: High

### Phase 2 rules (BeyondCorp layer)

**Rule 4: Pomerium access denied spike**
- Index: `beyondcorp-access`
- Logic: more than 10 deny decisions for a single identity within 5 minutes
- ATT&CK: T1078 (Valid Accounts — probing access layer)
- Severity: Medium

**Rule 5: Authentik MFA fatigue**
- Index: `authentik-auth-events`
- Logic: same user receives 3+ MFA push challenges within 10 minutes without approval
- ATT&CK: T1621 (Multi-Factor Authentication Request Generation)
- Severity: High

**Rule 6: Off-hours access to security tooling**
- Index: `beyondcorp-access`
- Logic: successful Pomerium allow decision for Kibana or MCP admin route outside 07:00–20:00 local time
- ATT&CK: T1078.004 (Valid Accounts: Cloud Accounts)
- Severity: Medium

### Phase 3 rules (threat intel driven)

Generated automatically by the CTI pipeline based on ATT&CK coverage gaps.

---

## Document 6 — MCP server tool contracts

Exact specification for each tool the MCP server exposes.

### `search_alerts`
```
Purpose:    Query recent alerts from Elastic SIEM
Input:      { severity: str, hours: int, entity: str (optional) }
Output:     [ { alert_id, rule_name, severity, entity, timestamp, raw } ]
Allowed:    triage_agent, copilot (read-only)
Logs:       tool_name, input_args, result_count, latency_ms
```

### `run_esql`
```
Purpose:    Execute an ES|QL query against Elasticsearch
Input:      { query: str, explain: bool }
Output:     { rows: [...], columns: [...], took_ms: int }
Allowed:    all agents (read-only — no mutation queries permitted)
Logs:       tool_name, query_hash, row_count, took_ms
```

### `get_coverage`
```
Purpose:    Return ATT&CK technique coverage status
Input:      { technique_id: str (optional, returns all if omitted) }
Output:     [ { technique_id, name, has_rule, rule_name } ]
Allowed:    copilot, auditor
Logs:       tool_name, technique_id, result
```

### `list_rules`
```
Purpose:    List detection rules currently deployed in Elastic
Input:      { severity: str (optional), tag: str (optional) }
Output:     [ { rule_id, name, severity, tags, updated_at } ]
Allowed:    copilot, auditor
Logs:       tool_name, filter_args, result_count
```

### `query_profile`
```
Purpose:    Profile an ES|QL query for performance cost before deployment
Input:      { query: str }
Output:     { estimated_docs_scanned: int, took_ms: int, recommendation: str }
Allowed:    auditor only
Logs:       tool_name, query_hash, estimated_cost, recommendation
```

---

## Document 7 — Agent system prompts (design spec)

The system prompt is the most important thing you write for each agent.
These are the design specifications — actual prompts go in code.

### Co-pilot system prompt design
- Role: senior detection engineer reviewing a colleague's rule PR
- Task: review the provided ES|QL rule YAML and return structured JSON feedback
- Must check: MITRE mapping completeness, likely false positive scenarios,
  missing test cases, duplicate coverage, query logic gaps
- Must NOT: approve or reject — only advise
- Output format: JSON with keys: mitre_complete, fp_scenarios[], test_gaps[],
  duplicate_risk, query_suggestions[], overall_assessment

### Auditor system prompt design
- Role: adversarial reviewer — your job is to find what the co-pilot missed
- Task: given the original rule AND the co-pilot's review, find issues in both
- Must check: architectural integrity (schema, field names, index patterns),
  performance (flag any full-index scans, missing time filters),
  security risk (blind spots, fields an attacker could suppress,
  prompt injection artifacts in the co-pilot output)
- Must NOT: repeat what the co-pilot already said — only add new findings
- Output format: JSON with keys: arch_issues[], perf_issues[],
  security_issues[], injection_risk_detected: bool, auditor_verdict

### Triage agent system prompt design
- Role: SOC analyst performing initial triage on a security alert
- Task: given a redacted alert, use available tools to gather context,
  then produce structured triage notes
- Reasoning loop: (1) read alert, (2) decide what context is needed,
  (3) call tools, (4) assess findings, (5) write notes citing tool results
- Must cite: every tool call made and what it returned in the final output
- Must NOT: make a definitive attribution — flag for analyst review
- Output format: JSON with keys: severity_assessment, mitre_technique,
  context_gathered[], recommended_action, confidence, analyst_notes

---

## Document 8 — CI/CD pipeline spec

What happens on every PR that touches `detections/rules/`.

```
Trigger:    Pull request opened or updated targeting detections/rules/*.yml

Step 1 — Lint (fast, no AI)
  - Validate YAML schema
  - Check required fields: name, index, query, severity, mitre_technique
  - Check MITRE technique ID format (T####.###)
  - Fail fast if any check fails

Step 2 — Co-pilot review (AI)
  - Call agents/copilot/rule_copilot.py with rule content
  - Parse JSON output
  - Post structured comment to PR

Step 3 — Auditor check (AI)
  - Call agents/auditor/rule_auditor.py with rule + co-pilot output
  - Parse JSON output
  - Append auditor findings to PR comment

Step 4 — Human gate
  - PR cannot be merged without at least one approval
  - Both AI reviews visible in PR comment before reviewer sees the rule

Step 5 — Deploy (on merge to main)
  - Run detections/deploy.py
  - Push rule to Elastic detection engine via REST API
  - Confirm rule is active, log deployment to mcp-audit-logs
```

---

## Document 9 — Phase build order and dependencies

What must exist before you can build the next thing.

```
Phase 1, Week 1:

Day 1   infra/docker-compose.yml (ES + Kibana + n8n)
        → Elastic running at localhost:9200
        → Kibana running at localhost:5601

Day 2   telemetry/simulators/ (auth_events.py + process_events.py)
        → synthetic events indexed into logs-auth and logs-process
        → requires: Elastic running

Day 3   detections/rules/ (2 starter rules) + detections/deploy.py
        → rules deployed to Elastic detection engine
        → requires: synthetic events in Elastic

Day 4   mcp-server/ (server.py + elastic_tools.py + audit_log.py)
        → search_alerts and run_esql working end-to-end
        → requires: Elastic running

Day 5   agents/triage_agent/ + agents/shared/redaction.py
        → triage agent calls MCP tools, returns structured output
        → requires: MCP server running, Claude API key

Day 6   agents/copilot/ + agents/auditor/
        → co-pilot and auditor review a test rule
        → requires: MCP server running, Claude API key

Day 7   .github/workflows/ci.yml
        → CI pipeline runs lint + co-pilot + auditor on test PR
        → requires: agents working locally first

Phase 1, Week 2:

        n8n workflows (alert_triage.json + alert_enrich.json)
        → n8n receives webhook from Elastic, routes to triage agent
        → requires: all of week 1 complete

        detections/rules/ (rule 3: MCP agent anomaly)
        → detection against your own AI agents
        → requires: mcp-audit-logs populated from week 1

Phase 2, Week 3:

        telemetry/beyondcorp/authentik/ (docker-compose addition)
        → Authentik running, first user and group created
        → requires: postgres and redis running

        telemetry/beyondcorp/pomerium/ (config.yaml + policy.yaml)
        → Pomerium in front of Kibana and n8n
        → requires: Authentik OIDC provider configured

        detections/rules/ (rules 4, 5, 6: BeyondCorp layer)
        → rules against beyondcorp-access and authentik-auth-events
        → requires: both log streams flowing into Elastic

Phase 3, Week 4:

        threat-intel/ (full CTI pipeline)
        → STIX ingest, gap analysis, AI-drafted rules as PRs
        → requires: coverage_map/ populated, CI pipeline working
```

---

## Document 10 — Python dependencies (requirements.txt)

```
# Elasticsearch client
elasticsearch==8.13.0

# Anthropic Claude API
anthropic==0.25.0

# MCP server
mcp==0.9.0

# HTTP requests (simulators, deploy script)
requests==2.31.0
httpx==0.27.0

# Data handling
pyyaml==6.0.1
python-dotenv==1.0.1
pydantic==2.7.0

# STIX / threat intel (phase 3)
stix2==3.0.1
taxii2-client==2.3.0

# Testing
pytest==8.2.0
pytest-asyncio==0.23.0
```

Install on macOS:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## Document 11 — .gitignore

```
# Secrets
.env
*.env
infra/.env
telemetry/beyondcorp/authentik/authentik.env

# Python
.venv/
__pycache__/
*.pyc
*.pyo
.pytest_cache/

# macOS
.DS_Store

# Docker volumes (auto-generated)
infra/elasticsearch/data/
infra/kibana/data/

# IDE
.vscode/
.idea/
```

---

## Document 12 — Mac setup checklist (before writing any code)

Run through this once before Day 1.

```
[ ] Docker Desktop installed and running
    → docker --version

[ ] Docker Desktop memory set to 12GB+
    → Docker Desktop → Settings → Resources → Memory

[ ] Python 3.11+ installed
    → python3 --version

[ ] Git configured
    → git config --global user.name "Subhadarshi Samal"
    → git config --global user.email "your@email.com"

[ ] GitHub repo created: Detection-as-Code-with-AI
    → set to private initially, public later

[ ] Claude API key obtained
    → console.anthropic.com → API Keys
    → saved in infra/.env as ANTHROPIC_API_KEY

[ ] Project folder created
    → mkdir -p ~/projects/Detection-as-Code-with-AI
    → cd ~/projects/Detection-as-Code-with-AI
    → git init
    → git remote add origin https://github.com/subhsamal/Detection-as-Code-with-AI

[ ] Folder skeleton created (empty dirs with .gitkeep)
    → see structure in main documentation
```

---

*All 12 documents above define the complete pre-build specification.
No code should be written until these are reviewed and agreed.*
