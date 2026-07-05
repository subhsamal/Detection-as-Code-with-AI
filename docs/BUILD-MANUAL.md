# Detection-as-Code-with-AI — Build Manual

**Version:** 1.0  
**Author:** Subhadarshi Samal  
**Last updated:** July 2026  
**Status:** Living document — updated after every build session

This manual is the step-by-step implementation guide for the Detection-as-Code-with-AI platform. The README is the summary for interviewers and visitors. This document is for the builder — every command, every decision, every explanation is here.

---

## How to use this document

- Follow sections in order — each phase depends on the previous one
- Every command is copy-paste ready
- Decisions and explanations are included so you understand what you built and why
- When you finish a task, check it off
- When something goes wrong, the troubleshooting notes at the end of each section will help

---

## Platform overview

A closed-loop, AI-augmented Detection and Response platform built entirely on open-source tools. Every component has a defined role:

| Component | Role | Phase |
|---|---|---|
| Elasticsearch | Data store — indexes all telemetry, alerts, and AI audit logs | 1 |
| Kibana | Visual interface — dashboards, detection rules, ATT&CK map | 1 |
| n8n | Orchestration — routes alerts, calls AI agents, posts findings | 1 |
| MCP server | AI tool gateway — scoped access for agents, full audit log | 1 |
| Rule drafter agent | Proposes detection rules and reviews logic | 1 |
| Auditor agent | Independently reviews drafter output for risk and performance | 1 |
| Triage agent | Multi-step reasoning loop for complex alert triage | 1 |
| Authentik | Identity provider — users, groups, MFA, OIDC tokens | 2 |
| Pomerium | Identity-aware proxy — enforces policy-as-code on every request | 2 |
| Threat intel pipeline | STIX/OTX ingest, coverage gap analysis, AI-drafted rules | 3 |

---

## Prerequisites

Everything needed before writing a single line of code.

### Mac setup

```bash
# Check your chip type
uname -m
# arm64 = Apple Silicon (M1/M2/M3/M4)
# x86_64 = Intel
```

```bash
# Check Python version (need 3.11+)
python3 --version

# Check Git
git --version

# Check Docker
docker --version
docker ps
```

### Docker Desktop settings

1. Open Docker Desktop
2. Settings → Resources → Advanced
3. Set Memory to **8GB minimum** (12GB for phase 2)
4. Set CPU to 10 (or whatever your Mac allows)
5. Click Apply and Restart

### Accounts and keys needed

| Service | URL | Purpose |
|---|---|---|
| GitHub | github.com | Repo hosting, CI/CD |
| Anthropic Console | console.anthropic.com | Claude API key |
| AlienVault OTX | otx.alienvault.com | Threat intel feed (phase 3) |

---

## Repository structure

```
Detection-as-Code-with-AI/
│
├── .github/
│   └── workflows/
│       └── ci.yml                  ← GitHub Actions CI pipeline
│
├── infra/                          ← Phase 1: Elastic stack
│   ├── docker-compose.yml          ← all services in one file
│   ├── .env                        ← secrets (never committed to git)
│   ├── elasticsearch/
│   │   └── elasticsearch.yml
│   └── kibana/
│       └── kibana.yml
│
├── telemetry/                      ← Phase 2: log sources
│   ├── simulators/
│   │   ├── auth_events.py
│   │   └── process_events.py
│   └── beyondcorp/
│       ├── pomerium/
│       │   ├── config.yaml
│       │   └── policy.yaml
│       └── authentik/
│           └── authentik.env
│
├── detections/                     ← Phase 1: detection-as-code
│   ├── rules/
│   │   └── *.yml  (ES|QL rules)
│   ├── tests/
│   ├── coverage_map/
│   └── deploy.py
│
├── mcp-server/                     ← Phase 1: AI tool gateway
│   ├── server.py
│   ├── tools/
│   │   └── elastic_tools.py
│   ├── scope_policy.py
│   └── audit_log.py
│
├── agents/                         ← Phase 1: AI agents
│   ├── copilot/
│   │   └── rule_copilot.py
│   ├── auditor/
│   │   └── rule_auditor.py
│   ├── triage_agent/
│   │   └── triage.py
│   └── shared/
│       └── redaction.py
│
├── n8n/
│   └── workflows/
│
├── threat-intel/                   ← Phase 3: CTI pipeline
│   ├── stix_ingest.py
│   ├── ttp_mapper.py
│   ├── gap_finder.py
│   ├── draft_rule.py
│   └── otx_feed.py
│
├── docs/
│   ├── architecture-diagram.svg
│   ├── architecture-diagram.html
│   ├── Detection-as-Code-with-AI.md
│   └── project-documents.md
│
├── .gitignore
├── requirements.txt
└── README.md
```

---

## Environment variables

All secrets live in `infra/.env`. This file is never committed to git.

```bash
# Elasticsearch
ES_VERSION=8.13.0
ES_PORT=9200
ELASTIC_PASSWORD=your_strong_password_here
KIBANA_PORT=5601

# n8n
N8N_PORT=5678
N8N_BASIC_AUTH_USER=admin
N8N_BASIC_AUTH_PASSWORD=your_n8n_password_here

# Claude API
ANTHROPIC_API_KEY=sk-ant-...

# MCP Server
MCP_PORT=8000
MCP_LOG_INDEX=mcp-audit-logs
```

**Generate a strong password on macOS:**
```bash
openssl rand -hex 16
```

---

## Phase 1 — Core platform

### Step 1.1 — Create the repo structure

```bash
# Navigate to your projects folder
cd ~/Documents/Development_projects

# Create and enter the repo folder
mkdir Detection-as-Code-with-AI
cd Detection-as-Code-with-AI

# Create all folders in one command
mkdir -p \
  .github/workflows \
  infra/elasticsearch \
  infra/kibana \
  telemetry/simulators \
  telemetry/beyondcorp/pomerium \
  telemetry/beyondcorp/authentik \
  detections/rules \
  detections/tests \
  detections/coverage_map \
  mcp-server/tools \
  agents/copilot \
  agents/auditor \
  agents/triage_agent \
  agents/shared \
  n8n/workflows \
  threat-intel \
  docs

# Keep empty folders tracked by git
find . -type d -empty -exec touch {}/.gitkeep \;

# Initialize git
git init
git remote add origin https://github.com/subhsamal/Detection-as-Code-with-AI.git
```

**Verify the structure:**
```bash
find . -type d | sort
```

### Step 1.2 — Create .gitignore

```bash
cat > .gitignore << 'EOF'
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

# Docker volumes
infra/elasticsearch/data/
infra/kibana/data/
EOF
```

### Step 1.3 — Create infra/.env

```bash
cat > infra/.env << 'EOF'
# Elasticsearch
ES_VERSION=8.13.0
ES_PORT=9200
ELASTIC_PASSWORD=changeme_strong_password
KIBANA_PORT=5601

# n8n
N8N_PORT=5678
N8N_BASIC_AUTH_USER=admin
N8N_BASIC_AUTH_PASSWORD=changeme_n8n_password

# Claude API
ANTHROPIC_API_KEY=your_key_here

# MCP Server
MCP_PORT=8000
MCP_LOG_INDEX=mcp-audit-logs
EOF
```

Open the file and replace all placeholder values with real passwords and your API key.

**Never run `git add infra/.env`**

### Step 1.4 — Docker compose (Elastic + Kibana + n8n)

Files created:
- `infra/docker-compose.yml` — defines all three services
- `infra/elasticsearch/elasticsearch.yml` — Elasticsearch config
- `infra/kibana/kibana.yml` — Kibana config

**Why these settings:**
- `discovery.type: single-node` — this is a lab, not a cluster
- `xpack.security.enabled: true` — security on, required for auth
- `xpack.security.http.ssl.enabled: false` — SSL off for local dev (add in production)
- `ES_JAVA_OPTS=-Xms1g -Xmx1g` — limits Elasticsearch to 1GB RAM heap on each side, leaves room for Kibana and n8n
- `healthcheck` — Kibana waits for Elasticsearch to be healthy before starting

**Commit (without .env):**
```bash
git add infra/docker-compose.yml infra/elasticsearch/elasticsearch.yml infra/kibana/kibana.yml
git commit -m "feat: add phase 1 docker-compose with Elastic stack and n8n"
git push origin main
```

### Step 1.5 — Start the stack

```bash
cd infra
docker compose up -d
```

**Watch the logs:**
```bash
docker compose logs -f
```

**Check all containers are running:**
```bash
docker compose ps
```

All three should show `running` or `healthy`.

**Verify Elasticsearch:**
```bash
curl -u elastic:YOUR_PASSWORD http://localhost:9200/_cluster/health
```

Should return `"status":"green"` or `"status":"yellow"`.

**Open Kibana:**
```
http://localhost:5601
```

Login with `elastic` and your `ELASTIC_PASSWORD`.

**Open n8n:**
```
http://localhost:5678
```

Login with your `N8N_BASIC_AUTH_USER` and `N8N_BASIC_AUTH_PASSWORD`.

**Stop the stack:**
```bash
docker compose down
```

**Stop and delete all data (full reset):**
```bash
docker compose down -v
```

### Step 1.6 — Create Elasticsearch indexes

Run this once after Elasticsearch is healthy to create the indexes the platform writes to:

```bash
# logs-auth index (synthetic auth events)
curl -u elastic:YOUR_PASSWORD -X PUT http://localhost:9200/logs-auth \
  -H 'Content-Type: application/json' \
  -d '{"settings": {"number_of_shards": 1, "number_of_replicas": 0}}'

# logs-process index (synthetic process events)
curl -u elastic:YOUR_PASSWORD -X PUT http://localhost:9200/logs-process \
  -H 'Content-Type: application/json' \
  -d '{"settings": {"number_of_shards": 1, "number_of_replicas": 0}}'

# mcp-audit-logs index (AI agent tool calls)
curl -u elastic:YOUR_PASSWORD -X PUT http://localhost:9200/mcp-audit-logs \
  -H 'Content-Type: application/json' \
  -d '{"settings": {"number_of_shards": 1, "number_of_replicas": 0}}'
```

---

## Key concepts and decisions

### Why Elasticsearch over Splunk for the lab

Elastic is free, open-source, and runs locally in Docker. Splunk requires a license beyond 500MB/day. For a portfolio project that needs to run 24/7 on a MacBook without cost concerns, Elastic is the right choice. ES|QL (Elastic's query language) is also what modern Elastic SIEM users write detection rules in.

### Why n8n over XSOAR or Splunk SOAR

n8n is free, open-source, and self-hosted. It handles deterministic automation (create Jira ticket, post to Slack) without consuming AI API budget. XSOAR and Splunk SOAR require expensive licenses. n8n also has a REST API that the MCP server can call, making it easy to wire into the agentic AI layer.

### Why MCP server instead of direct API calls

The MCP (Model Context Protocol) server is a single gateway between all AI agents and the rest of the platform. Benefits:
- Tool integrations written once, used by any agent
- Per-agent tool access scoped via scope_policy.py
- Every tool call logged to mcp-audit-logs (the audit trail)
- Follows least-privilege — triage agent cannot call query_profile, only the auditor can

### Why two AI agents (drafter + auditor) instead of one

A single model reviewing its own output has no mechanism to catch its own mistakes. The two-model critic pattern runs two independent models sequentially:
1. Rule drafter proposes — writes the detection rule, suggests ATT&CK mapping, flags false positive scenarios
2. Auditor critiques — independently reviews for schema correctness, query performance cost, security blind spots, and prompt injection artifacts in the drafter's output

Neither model knows what the other will say. The auditor's job is explicitly adversarial.

### Why Authentik + Pomerium (not just one)

Authentik is the identity provider — it owns users, passwords, groups, MFA, and issues OIDC tokens. It is the passport office.

Pomerium is the Identity-Aware Proxy — it checks every request against policy-as-code before forwarding to the upstream app. It is the bouncer at every door.

Using both mirrors the enterprise pattern where the IdP (Okta, Azure AD) and the access proxy (Cloudflare Access, Zscaler) are separate products. Decoupling them means you could swap Pomerium for Cloudflare Access without touching Authentik or your user database.

### Why agent behavior is a detection source

The MCP server logs every tool call an agent makes to the `mcp-audit-logs` Elasticsearch index. Detection rules run against this index. This means:
- A prompt injection attack (malicious log entry tricks the triage agent into making unusual tool calls) is detectable
- Out-of-scope tool calls (agent attempts a tool outside its allowlist) are detectable
- Auditor pass rate spikes (possible system prompt tampering) are detectable

The platform monitors its own AI layer. This is the part most AI-in-security implementations skip.

---

## Troubleshooting

### Elasticsearch won't start

```bash
# Check logs
docker compose logs elasticsearch

# Common fix: increase virtual memory
sudo sysctl -w vm.max_map_count=262144
```

### Kibana shows "Kibana server is not ready yet"

Wait 2-3 minutes after Elasticsearch starts. Kibana waits for ES to be healthy. If it persists:

```bash
docker compose logs kibana
```

### Port already in use

```bash
# Find what's using port 9200
lsof -i :9200

# Kill it or change ES_PORT in .env
```

### API key not working

```bash
# Verify the key is in .env
grep ANTHROPIC_API_KEY infra/.env

# Verify it's not committed to git
git status | grep .env
# Should return nothing
```

---

## Git workflow

```bash
# Check what's changed
git status

# Add specific files (never add .env)
git add path/to/file

# Commit
git commit -m "feat: description of what you built"

# Push
git push origin main
```

**Commit message conventions:**
- `feat:` — new file or feature
- `fix:` — bug fix
- `docs:` — documentation change
- `refactor:` — code restructure, no behavior change

---

## Build progress tracker

### Phase 1 — Core platform

- [x] Repo structure created
- [x] .gitignore created and committed
- [x] infra/.env created (not committed)
- [x] docker-compose.yml created
- [x] elasticsearch.yml created
- [x] kibana.yml created
- [ ] Stack started and verified healthy
- [ ] Elasticsearch indexes created
- [ ] Python virtual environment set up
- [ ] requirements.txt created
- [ ] telemetry/simulators/auth_events.py
- [ ] telemetry/simulators/process_events.py
- [ ] detections/rules/ — 3 starter rules
- [ ] detections/deploy.py
- [ ] mcp-server/server.py
- [ ] mcp-server/tools/elastic_tools.py
- [ ] mcp-server/scope_policy.py
- [ ] mcp-server/audit_log.py
- [ ] agents/shared/redaction.py
- [ ] agents/triage_agent/triage.py
- [ ] agents/copilot/rule_copilot.py
- [ ] agents/auditor/rule_auditor.py
- [ ] n8n alert routing workflow
- [ ] .github/workflows/ci.yml

### Phase 2 — Zero-trust access layer

- [ ] Authentik added to docker-compose
- [ ] Pomerium added to docker-compose
- [ ] Pomerium policy.yaml protecting Kibana and n8n
- [ ] Authentik OIDC provider configured
- [ ] Access logs flowing into Elastic
- [ ] BeyondCorp detection rules written

### Phase 3 — Threat intel pipeline

- [ ] threat-intel/stix_ingest.py
- [ ] threat-intel/ttp_mapper.py
- [ ] threat-intel/gap_finder.py
- [ ] threat-intel/draft_rule.py
- [ ] threat-intel/otx_feed.py
- [ ] ATT&CK heatmap dashboard in Kibana

---

## Session log

Use this section to track what was done each session.

### Session 1 — June 22, 2026
- Designed full platform architecture
- Decided on six modules: infra, telemetry, detections, mcp-server, agents, threat-intel
- Added n8n as orchestration layer
- Decided on Authentik + Pomerium for BeyondCorp zero-trust
- Created GitHub repo: github.com/subhsamal/Detection-as-Code-with-AI
- Created folder structure, .gitignore, documentation files
- Pushed initial commit with README and architecture diagram

### Session 2 — July 5, 2026
- Fixed SVG architecture diagram rendering in GitHub README
- Made repo public
- Created infra/.env with API key
- Created docker-compose.yml, elasticsearch.yml, kibana.yml
- Committed infra files (excluding .env)
- Next: start the stack and verify all three services healthy

---

*This document is updated at the end of every build session. The README is updated when a full phase is complete.*
