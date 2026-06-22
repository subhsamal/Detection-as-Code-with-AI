# Detection-as-Code-with-AI

**A production-grade, AI-augmented Detection and Response platform built on open-source tools.**

Built by Subhadarshi Samal — Senior Detection and Response Engineer.

---

## What this is

This platform answers a question that comes up in every senior D&R interview: *"How would you build a world-class SOC capability using open-source tooling?"*

The answer is not "install Elastic and write some rules." The answer is a closed-loop system where telemetry feeds detections, detections trigger AI agents, agents produce audited output, and the agents themselves become a detection surface. Every component has a defined role, a defined interface, and a defined feedback path.

This is also a living portfolio — each module maps directly to skills that matter at AI-forward security organizations: detection engineering, zero-trust access, agentic AI, LLM output auditing, REST API integration, and threat intelligence operationalization.

---

## Architecture overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                   Detection-as-Code-with-AI Platform                │
│                                                                     │
│  ┌──────────────┐     ┌──────────────┐     ┌─────────────────────┐ │
│  │  Telemetry   │────▶│ Elastic SIEM │────▶│  n8n Orchestration  │ │
│  │  & Access    │     │              │     │                     │ │
│  │              │     │ Detections   │     │ Simple: ticket/Slack│ │
│  │ Elastic Agent│     │ as Code      │     │ Complex: → AI layer │ │
│  │ BeyondCorp   │     │ ES|QL rules  │     │                     │ │
│  │ IAP logs     │     │ ATT&CK map   │     └──────────┬──────────┘ │
│  └──────────────┘     └──────┬───────┘                │            │
│                              │ audit logs              │            │
│                              │◀────────────────────────┤            │
│                              │                         ▼            │
│                              │               ┌─────────────────────┐│
│                              │               │    MCP Server       ││
│                              │               │                     ││
│                              │               │  search_alerts      ││
│                              │               │  run_esql           ││
│                              │               │  get_coverage       ││
│                              │               │  list_rules         ││
│                              │               │  query_profile      ││
│                              │               │                     ││
│                              │               │  scope_policy.py    ││
│                              │               │  audit_log.py  ─────┼┼──▶ Elastic
│                              │               └──────────┬──────────┘│
│                              │                          │            │
│                              │               ┌──────────┴──────────┐│
│                              │               │     AI Agents       ││
│                              │               │                     ││
│                              │               │  Co-pilot           ││
│                              │               │  Auditor            ││
│                              │               │  Triage Agent       ││
│                              │               └─────────────────────┘│
└─────────────────────────────────────────────────────────────────────┘
          ▲                                              │
          │                                             ▼
  ┌───────────────┐                           ┌─────────────────┐
  │  Threat Intel │                           │  Analyst (you)  │
  │  MITRE STIX   │                           │  reviews ·      │
  │  OTX feeds    │                           │  approves ·     │
  └───────────────┘                           │  overrides      │
                                              └─────────────────┘
```

---

## Repository structure

```
Detection-as-Code-with-AI/
│
├── infra/                        # Elastic stack (Docker)
│   ├── docker-compose.yml
│   ├── .env
│   ├── elasticsearch/
│   │   └── elasticsearch.yml
│   └── kibana/
│       └── kibana.yml
│
├── telemetry/                    # Log sources and simulators
│   ├── simulators/
│   │   ├── auth_events.py
│   │   └── process_events.py
│   └── beyondcorp/
│       └── pomerium.yml
│   │   ├── authentik.yml
│   │   ├── authentik-db.yml
│
├── detections/                   # Detection-as-code
│   ├── rules/
│   │   └── *.yml  (ES|QL rules with MITRE mapping)
│   ├── tests/
│   ├── coverage_map/
│   └── deploy.py
│
├── mcp-server/                   # AI tool gateway
│   ├── server.py
│   ├── tools/
│   │   └── elastic_tools.py
│   ├── scope_policy.py
│   └── audit_log.py
│
├── agents/                       # AI agent roles
│   ├── copilot/
│   │   └── rule_copilot.py
│   ├── auditor/
│   │   └── rule_auditor.py
│   ├── triage_agent/
│   │   └── triage.py
│   └── shared/
│       └── redaction.py
│
├── threat-intel/                 # CTI pipeline
│   ├── stix_ingest.py
│   ├── ttp_mapper.py
│   ├── gap_finder.py
│   ├── draft_rule.py
│   └── otx_feed.py
│
├── n8n/                          # SOAR-equivalent workflows
│   └── workflows/
│       ├── alert_triage.json
│       └── alert_enrich.json
│
└── .github/
    └── workflows/
        └── ci.yml               # Lint → co-pilot → auditor → deploy
```

---

## Component roles

### 1. `infra/` — Elastic stack

**What it is:** The data foundation. Elasticsearch stores all security telemetry, detection rule output, and AI agent audit logs. Kibana provides dashboards, the detection rules UI, and the ATT&CK coverage heatmap.

**Why this approach:** The `elastic-start-local` Docker script gives a fully portable, expiry-free Elastic stack that anyone can clone and run in two commands. No cloud trial, no license expiry mid-demo. The entire platform runs on a MacBook.

**Key interfaces:**
- Elasticsearch REST API (`localhost:9200`) — used by `detections/deploy.py`, `mcp-server/tools/elastic_tools.py`, and `mcp-server/audit_log.py`
- Kibana UI (`localhost:5601`) — dashboards and detection rule management

**Role in the platform:** Everything flows through Elasticsearch. Telemetry is indexed here. Detection rules run against it. AI agent tool calls are logged back into it. It is the source of truth for the entire system.

---

### 2. `telemetry/` — Log sources and synthetic simulators

**What it is:** The raw security signal. Two components: Python simulators that generate realistic synthetic events (auth failures, process executions, lateral movement patterns), and a full zero-trust identity stack: Authentik as the identity provider (IdP) and Pomerium as the Identity-Aware Proxy (IAP). Authentik manages users, groups, MFA, and issues OIDC tokens. Pomerium trusts those tokens and enforces per-route access policy in front of Kibana, n8n, and the MCP server admin interface.

**Why simulators:** A lab without realistic data produces no meaningful detections and no meaningful AI triage output. The simulators generate both benign baseline traffic and injected attack patterns (encoded PowerShell, brute force sequences, suspicious process chains) so every detection rule can be validated against real-looking telemetry.

**Why BeyondCorp/Pomerium:** Every access decision Pomerium makes — device posture, identity, context — becomes a structured log entry indexed into Elasticsearch. This gives the platform a zero-trust log source to write access-anomaly detections against, and it gives you hands-on experience with a Google BeyondCorp-equivalent model on your own infrastructure.

**Key interfaces:**
- Simulators bulk-index events to Elasticsearch via REST API
- Pomerium writes access logs to a dedicated Elasticsearch index

**Role in the platform:** Produces the telemetry that detections run against. The BeyondCorp layer adds a zero-trust access surface that itself becomes a detection source.

---

### 3. `detections/` — Detection-as-code

**What it is:** All detection logic lives as versioned YAML files in this directory. Each rule contains the ES|QL query, MITRE ATT&CK mapping (tactic, technique, subtechnique), severity, response guidance, and test cases. `deploy.py` pushes rules to the Elastic detection engine via REST API.

**Why YAML + CI/CD:** Detection rules are code. They belong in version control with peer review, automated testing, and a deployment pipeline — the same standards applied to application code. This is the core "Detection-as-Code" practice, and it makes every rule change auditable and reversible.

**ATT&CK coverage map:** A `coverage_map/` folder tracks which MITRE techniques have detection coverage and which do not. This feeds directly into the threat intel pipeline (phase 3) and powers a Kibana heatmap dashboard.

**Key interfaces:**
- `deploy.py` calls the Elasticsearch detection rules API
- CI pipeline (`ci.yml`) runs tests, calls the AI co-pilot and auditor, then runs deploy on merge

**Role in the platform:** The detection layer. Every alert that flows into n8n and the AI agents originates from a rule in this directory.

---

### 4. `mcp-server/` — AI tool gateway

**What it is:** A Python MCP (Model Context Protocol) server that exposes a defined set of tools to AI agents. Every interaction an agent has with Elasticsearch, the detection rule library, or query profiling goes through this server — never directly.

**Why MCP:** MCP is the emerging standard for giving AI agents structured, auditable access to external systems. Building your own MCP server rather than using one-off Python functions means tool integrations are written once and any future agent can use them. It also means access can be scoped, logged, and monitored at a single point.

**Tools exposed:**

| Tool | What it does | Who can use it |
|---|---|---|
| `search_alerts` | Query recent alerts by severity, time, entity | Triage agent, co-pilot (read) |
| `run_esql` | Execute an ES|QL query against the SIEM | All agents (read-only) |
| `get_coverage` | Return ATT&CK technique coverage status | Co-pilot, auditor |
| `list_rules` | List deployed detection rules | Co-pilot, auditor |
| `query_profile` | Profile an ES|QL query for performance cost | Auditor only |

**`scope_policy.py`:** Implements least-privilege for AI agents. Each agent role has an allowlist of tools it can call. A triage agent cannot call `query_profile`. An auditor cannot create or modify rules. The same zero-trust principle applied to human users, applied to AI agents.

**`audit_log.py`:** Every tool call an agent makes is written as a structured JSON log entry to a dedicated Elasticsearch index (`mcp-audit-logs`). Fields include: agent role, tool name, arguments, response summary, timestamp, and latency. This is not optional telemetry — it is a first-class security data source.

**Key interfaces:**
- Exposes MCP protocol endpoints consumed by agents in `agents/`
- Writes to Elasticsearch via REST API

**Role in the platform:** The single controlled gateway between AI agents and the rest of the platform. It enforces scope, produces the audit trail, and makes the entire AI layer observable.

---

### 5. `agents/` — AI agent roles

**What it is:** Three distinct AI agents, each with a scoped system prompt, a defined tool allowlist via the MCP server, and a specific job in the D&R workflow.

#### Detection rule co-pilot (`copilot/rule_copilot.py`)

The co-pilot's job is to assist with detection engineering. When a new rule PR is opened, the CI pipeline calls the co-pilot with the rule content. The co-pilot reviews it and returns structured feedback: MITRE ATT&CK mapping completeness, likely false-positive scenarios, missing test cases, suggested query improvements, and whether the rule duplicates existing coverage.

The co-pilot does not approve or deploy anything. It produces a review comment on the PR. The analyst decides what to do with it.

**Tool access:** `run_esql` (to test query logic), `list_rules` (to check for duplicate coverage), `get_coverage` (to verify ATT&CK mapping).

#### Auditor (`auditor/rule_auditor.py`)

The auditor is the two-model critic pattern in action. After the co-pilot produces output — a rule review, a triage assessment, a query suggestion — the auditor independently reviews it before it reaches the analyst or the CI pipeline. The auditor checks three things:

- **Architectural integrity:** Does the proposed rule follow schema conventions? Does it map correctly to the detection rule data model?
- **Performance:** Will this ES|QL query be expensive? The auditor calls `query_profile` to get an actual cost estimate, not a guess.
- **Security risk:** Does the rule create a blind spot? Does it rely on a field an attacker could suppress? Does the co-pilot's output contain anything that looks like a prompt injection artifact?

The auditor's findings are attached to the PR comment alongside the co-pilot's review. The analyst sees both before deciding.

This is the rarest capability in D&R AI tooling — most teams use one model and trust its output. Running an independent critic on every AI output, and logging both sets of findings, is a meaningful security control.

**Tool access:** `run_esql`, `list_rules`, `get_coverage`, `query_profile`.

#### SOC triage agent (`triage_agent/triage.py`)

The triage agent is the most agentic of the three. When n8n routes a complex alert to the AI layer, the triage agent receives the (redacted) alert and runs a multi-step reasoning loop:

1. Calls `search_alerts` to pull related alerts for the same entity over the prior 24 hours
2. Calls `run_esql` to check for additional context (e.g. did this user authenticate from an unusual location in the same window?)
3. Assesses severity, maps to ATT&CK technique, identifies recommended next action
4. Writes structured triage notes citing exactly which tool calls informed each conclusion
5. Returns output to n8n, which posts to the analyst via Slack or updates the Jira ticket

The key difference from a SOAR playbook: the triage agent reasons about what to look for, not just what to execute. The tool-call trace is visible, so the analyst can see the agent's reasoning process, not just its conclusion.

**`shared/redaction.py`:** Before any alert data touches an AI model, this module strips or hashes sensitive fields (usernames, hostnames, IP addresses). The AI works on redacted data. The redaction map is held in memory and used to rehydrate entity names in the final triage output shown to the analyst. This is a data governance control applied at the AI boundary.

**Tool access:** `search_alerts`, `run_esql`.

---

### 6. `n8n/` — Orchestration layer

**What it is:** A self-hosted n8n instance running alongside the Elastic stack in Docker. n8n is the first receiver of fired alerts from Elastic and acts as a lightweight SOAR layer.

**Why n8n alongside the MCP server:** These two components serve different purposes and should not be conflated. n8n handles deterministic, repeatable automation — create a Jira ticket, post to Slack, call VirusTotal for IP enrichment. These workflows do not require AI reasoning and should not consume AI API budget. The MCP server and AI agents handle non-deterministic, reasoning-required work — correlating events, assessing intent, writing triage notes.

The routing decision lives in n8n: if the alert severity and type match a simple playbook, n8n handles it entirely. If the alert requires contextual reasoning, n8n calls the MCP server's triage agent endpoint and posts the agent's output back to the analyst.

**Key workflows:**
- `alert_triage.json` — routes alerts, calls triage agent for complex cases, posts findings to Slack
- `alert_enrich.json` — enriches alert entities with VirusTotal, AbuseIPDB, and Shodan before passing to the AI layer

**Role in the platform:** The operational automation layer. Keeps simple things simple and routes complex things to the right place. Prevents the AI layer from becoming a bottleneck for routine work.

---

### 7. `threat-intel/` — CTI pipeline

**What it is:** An automated pipeline that ingests structured threat intelligence, maps it to the platform's current ATT&CK detection coverage, identifies gaps, and uses the AI co-pilot to draft candidate detection rules for uncovered techniques.

**Components:**

- `stix_ingest.py` — Pulls MITRE ATT&CK STIX data from the official TAXII server. Parses techniques, subtechniques, and associated data sources.
- `otx_feed.py` — Pulls recent threat reports from AlienVault OTX. Extracts TTPs mentioned in pulse reports.
- `ttp_mapper.py` — Cross-references ingested TTPs against the ATT&CK coverage map in Elasticsearch. Produces a list of techniques with no detection coverage.
- `gap_finder.py` — Prioritizes coverage gaps by threat actor relevance (are APT groups currently using this technique?), data source availability, and detection difficulty.
- `draft_rule.py` — For the highest-priority gaps, calls the co-pilot agent to draft a candidate ES|QL detection rule. The draft goes through the auditor before being committed to `detections/rules/` as a PR for analyst review.

**Role in the platform:** Closes the loop between external threat intelligence and internal detection coverage. "Staying ahead on adversary TTPs" becomes an automated pipeline that produces actionable detection drafts, not a manual research habit.

---

### 8. `.github/workflows/ci.yml` — CI/CD pipeline

**What it is:** The GitHub Actions pipeline that runs on every PR touching `detections/rules/`.

**Pipeline stages:**

```
PR opened
    │
    ▼
1. Lint          validate YAML schema, required fields, MITRE mapping format
    │
    ▼
2. Co-pilot      AI reviews rule quality, flags issues, suggests improvements
    │
    ▼
3. Auditor       AI independently reviews co-pilot output and rule for risk
    │
    ▼
4. PR comment    both reviews posted as a structured comment for analyst
    │
    ▼
5. Merge (manual approval required)
    │
    ▼
6. Deploy        deploy.py pushes rule to Elastic detection engine
```

**Role in the platform:** Makes detection engineering a disciplined, audited practice. No rule reaches production without schema validation, AI review, independent audit, and human approval.

---

## The two signature capabilities

### Two-model critic pattern

Every AI output in this platform is independently reviewed by a second model before it reaches a human or a production system. The co-pilot proposes; the auditor critiques. Neither model knows what the other will say — they run sequentially, not in a shared context window. The auditor's job is adversarial: find what the co-pilot missed.

This pattern addresses the core failure mode of single-model AI in security workflows: an AI that proposes a detection rule with a subtle blind spot has no mechanism to catch it. A second model reviewing specifically for blind spots, query cost, and schema integrity does.

This is also the direct answer to "how do you audit AI-generated output for architectural integrity, performance bottlenecks, and security risks" — it is not a post-hoc code review, it is a built-in automated control in the CI pipeline.

### Agent behavior as a detection source

The MCP server's `audit_log.py` writes every agent tool call to `mcp-audit-logs` in Elasticsearch. Detection rules in `detections/rules/` are written against this index. The platform watches its own AI agents.

Detection examples:
- Triage agent calls `search_alerts` with arguments that look like exfiltration probes (possible prompt injection via a malicious log entry the agent ingested)
- Any agent attempts a tool outside its scoped allowlist (defense in depth — should be blocked at the MCP layer, but this detects if something gets through)
- Auditor pass rate spikes above two standard deviations from baseline (possible system prompt tampering)
- Triage agent produces structured output that diverges significantly from its tool-call trace (agent reasoning and evidence are inconsistent)

This turns the AI layer itself into a monitored, detectable attack surface — which is the correct security posture for any system that processes untrusted data (security logs) and produces privileged output (triage decisions, detection rules).

---

## Implementation roadmap

### Phase 1 — Core platform (weeks 1–2)

**Goal:** Working end-to-end demo. Alert fires in Elastic → n8n routes it → triage agent reasons over it → analyst sees structured output.

| Task | Module | Deliverable |
|---|---|---|
| Elastic stack via Docker | `infra/` | `docker-compose.yml`, `.env`, Kibana accessible at `localhost:5601` |
| Synthetic event simulators | `telemetry/simulators/` | `auth_events.py`, `process_events.py` indexing to Elastic |
| 3 starter detection rules | `detections/rules/` | ES|QL YAML rules with MITRE mapping and test cases |
| Rule deploy script | `detections/` | `deploy.py` pushing rules via Elastic REST API |
| MCP server — 2 tools | `mcp-server/` | `search_alerts` and `run_esql` working end-to-end |
| MCP audit logging | `mcp-server/` | `audit_log.py` writing tool calls to `mcp-audit-logs` index |
| Triage agent | `agents/triage_agent/` | Multi-step loop, redaction, structured triage output |
| Co-pilot (CI step) | `agents/copilot/` | Reviews rule PRs, posts structured comment |
| Auditor (CI step) | `agents/auditor/` | Reviews co-pilot output, posts audit findings |
| n8n alert routing | `n8n/` | n8n in Docker, alert webhook → route → triage agent |
| GitHub Actions CI | `.github/workflows/` | Lint → co-pilot → auditor → deploy pipeline |

**Phase 1 interview story:** "I built a detection-as-code pipeline on open-source Elastic where every detection rule goes through an AI co-pilot review and an independent AI auditor before it reaches production. The AI agents themselves are monitored — every tool call they make is indexed back into the SIEM and I've written detections against anomalous agent behavior."

---

### Phase 2 — Zero-trust access layer (week 3)

**Goal:** BeyondCorp-style IAP in front of Kibana. Access decisions become a log source.

| Task | Module | Deliverable |
|---|---|---|
| Pomerium IAP in Docker | `telemetry/beyondcorp/` | `pomerium.yml
│   │   ├── authentik.yml
│   │   ├── authentik-db.yml`, Kibana only accessible via IAP |
| Access log ingestion | `telemetry/` | Pomerium logs indexed to `beyondcorp-access` Elastic index |
| Access anomaly detection rule | `detections/rules/` | ES|QL rule firing on unusual access patterns to security tooling |

**Phase 2 interview story:** "The security tooling itself — Kibana, the n8n dashboard — sits behind a BeyondCorp-style Identity-Aware Proxy. Every access decision is logged and I've written detections that fire if someone accesses the SOC tooling outside normal patterns. Zero-trust applied to the SOC's own infrastructure."

---

### Phase 3 — Threat intelligence pipeline (week 4)

**Goal:** Automated TTP-to-coverage-gap pipeline producing AI-drafted detection rules.

| Task | Module | Deliverable |
|---|---|---|
| MITRE ATT&CK STIX ingest | `threat-intel/` | `stix_ingest.py` pulling from TAXII server |
| OTX feed ingest | `threat-intel/` | `otx_feed.py` parsing pulse reports for TTPs |
| Coverage gap analysis | `threat-intel/` | `gap_finder.py` cross-referencing coverage map |
| AI-drafted rule pipeline | `threat-intel/` | `draft_rule.py` → co-pilot → auditor → PR |
| ATT&CK heatmap dashboard | Kibana | Coverage heatmap showing detected vs undetected techniques |

**Phase 3 interview story:** "The platform ingests MITRE ATT&CK STIX data and threat reports, cross-references them against current detection coverage, prioritizes gaps by active threat actor relevance, and uses AI to draft candidate rules for the top gaps. The analyst sees a PR, not a spreadsheet."

---

## Skills demonstrated — mapped to interview requirements

| Platform capability | Skill demonstrated |
|---|---|
| Elastic SIEM, ES|QL rules, deploy via REST API | SIEM architecture, detection engineering |
| Detection-as-code with GitHub Actions CI | DevSecOps, CI/CD for security content |
| MCP server with scoped tool access | REST API integration, AI tool design |
| Two-model critic pattern (co-pilot + auditor) | LLM output auditing, AI governance |
| Triage agent with multi-step reasoning | Agentic AI, LLM integration in security workflows |
| Agent behavior indexed as detection source | Creative detection engineering, AI security |
| Pomerium IAP in front of Kibana | BeyondCorp / zero-trust access model |
| STIX ingest, TTP-to-coverage gap pipeline | Threat intelligence operationalization |
| n8n orchestration layer | SOAR-equivalent workflow automation |
| Redaction gateway before AI boundary | Data governance, PII handling in AI systems |

---

## Getting started (phase 1)

Prerequisites: Docker Desktop on macOS with at least 8GB RAM allocated, Python 3.11+, a Claude API key.

```bash
# Clone the repo
git clone https://github.com/subhsamal/Detection-as-Code-with-AI
cd Detection-as-Code-with-AI

# Start the Elastic stack
cd infra
docker compose up -d

# Verify Elasticsearch is healthy
curl -u elastic:$ES_PASSWORD http://localhost:9200/_cluster/health

# Run the event simulators to populate Elastic with synthetic telemetry
cd ../telemetry/simulators
python auth_events.py
python process_events.py

# Deploy starter detection rules
cd ../../detections
python deploy.py

# Start the MCP server
cd ../mcp-server
python server.py

# Kibana is now available at http://localhost:5601
```

---

*This document is the north star for the build. Every code file written, every PR opened, and every demo recorded maps back to a row in the roadmap above.*
