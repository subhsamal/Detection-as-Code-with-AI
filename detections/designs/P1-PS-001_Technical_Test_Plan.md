# P1-PS-001 — Supporting technical and test plan

**Status:** Synthetic lab implementation and controlled runtime validation completed 14 November 2026; rule disabled afterward. Current schedule: interval 5m, from now-7m, to now. Actual alerts: 6 Medium/47 and 8 High/73 (two intentional automation false positives); 15 exclusions; same 14 alert IDs across two overlapping scheduled runs. Local code corrections and safety tests are recorded in the 17 November Day 2 log update.

Exact supported grammar is in [the processor README](../processing/README.md); actual dated results are in [runtime evidence](../tests/P1-PS-001_Runtime_Validation.md). [Repository tools](../processing/RUNTIME_TOOLS.md) provide reproducible generation, read-only audit and explicitly gated live validation. Future extended cases below are specifications, not claims of coverage.

Read the [short detection design](P1-PS-001_Office_Encoded_PowerShell.md) first. Medium/47 for understood download-only instructions and High/73 for linked download-and-run instructions were verified on actual lab alerts. This is instruction evidence; successful transfer/payload execution and production efficacy remain unproven. Historical implementation decisions are preserved in the chronological Day 2 log.

## Conditional severity — one rule

The base match requires Office ancestry, an encoded PowerShell invocation, and a supported download instruction. After inspecting the complete supported script, assign Medium/47 for download-only instructions or High/73 if downloaded content is passed to execution. High takes precedence; return one result per qualifying source event, not separate Medium and High rows.

Elastic 8.13 documentation and version-pinned ES|QL alert-building code support `severity_mapping` and `risk_score_mapping`. The implemented fields p1.priority.severity and numeric p1.priority.risk_score remain in query results; actual alert overrides passed the controlled runtime test. Medium/47 are defaults, not a fallback for unknown script analysis. Filter or explicitly report incomplete/unsupported analysis rather than silently treating it as download-only.

This is classification at alert creation, not automatic escalation when later events arrive. Preserve event metadata for deduplication and test repeated runs. A changed source-document version can change the alert identifier; do not assume updating source evidence updates the existing alert. No automatic alert-mutation mechanism is proposed.

References: [Elastic 8.13 rule API](https://www.elastic.co/guide/en/security/8.13/rules-api-create.html), [8.13 ES|QL alert builder](https://github.com/elastic/kibana/blob/v8.13.0/x-pack/plugins/security_solution/server/lib/detection_engine/rule_types/esql/wrap_esql_alerts.ts).

## Script-reading details

### Recommended v1: linked script instructions

The minimum source is process-start telemetry containing the encoded command value, required lineage, and enough command-line fidelity for safe decoding. Script Block Logging (4104) is an alternative evidence source only when content can be tied to the same host/process instance and a bounded execution window. It is not currently collected. Any fragmented script blocks require complete reconstruction by script-block ID/message number before classification; a timestamp or PID alone is insufficient linkage.

The implemented local matcher recognizes the following bounded retrieval-to-execution patterns:

| Retrieval operation | Required execution linkage | Proposed v1 coverage |
|---|---|---|
| `Invoke-WebRequest` | Its response `.Content` is supplied to `Invoke-Expression` / `IEX`, directly or through an explicitly tracked variable | Implemented for the declared grammar; arbitrary response objects are not executable text |
| `System.Net.WebClient.DownloadString` | Its returned text is supplied to `Invoke-Expression` / `IEX` | Implemented for the declared grammar |
| Download to disk (`-OutFile` / `DownloadFile`) | Subsequent execution of the same downloaded path | Defer; requires additional path/data-flow logic or runtime correlation |

Handle uppercase/lowercase and `IEX`. For High severity, check that downloaded content is passed to an execution command—not just that both words appear. Comments and quoted examples must not trigger the rule. Unrecognized forms remain untested.

## First-version script patterns — implemented contract

The matcher inspects text only. It does not run PowerShell, evaluate expressions, create a web client or contact any URL. The examples below are pseudocode, not executable commands.

### Download expressions

For this first version, recognize only:

- `Invoke-WebRequest` with a literal HTTP/HTTPS URL and access to its response `.Content`.
- A directly constructed `System.Net.WebClient` or `Net.WebClient` calling `DownloadString` with a literal HTTP/HTTPS URL. Begin with the explicit `New-Object` constructor form; other constructors require separate fixtures.

Use `Invoke-WebRequest` spelled in full initially; `iwr`, `curl`, custom aliases, additional request options and dynamically assembled URLs are not implicitly supported. `.Content` is needed for the WebRequest text-to-execution pattern. A plain supported WebRequest without `.Content` can be download-only if the entire statement is understood; it must never be treated as passing script text to IEX without that content access. Download-to-disk options remain outside this first version.

### Three execution patterns

In this table, `DOWNLOAD_TEXT` means a recognized expression returning downloaded text. It is a placeholder, not an expected word in a real script.

| Pattern ID | Script shape (Pseudocode) | Analysis result |
|---|---|---|
| `direct_argument` | `IEX(DOWNLOAD_TEXT)` | High / 73 |
| `direct_pipeline` | `DOWNLOAD_TEXT → IEX` | High / 73 |
| `single_variable` | `text = DOWNLOAD_TEXT; IEX(text)` | High / 73 |
| `download_only` | A supported download statement or assignment with no execution operation | Medium / 47 |

Support `Invoke-Expression` as well as its built-in `IEX` alias, case-insensitively. For `single_variable`, require the same simple variable name and no reassignment, extra variable hop or intervening command. A direct execution argument may be parenthesized; full PowerShell command syntax must be spelled out and tested in the actual grammar, not inferred from this pseudocode.

### Keep the analysis narrow

- Parse quoted text and comments as separate elements; words inside them are not commands. Accept simple literal URLs; interpolation and computed strings remain unknown.
- Require the entire script to fit the supported small set of statements, allowing whitespace, simple line comments and statement separators. Do not stop after a promising fragment and ignore an unsupported remainder.
- Do not accept function definitions, loops, conditionals, custom alias definitions, command redefinition, nested encodings, dynamic invocation or arbitrary extra statements. Mark these `unknown` rather than guessing what runs.
- Report `download_only` only when the full supported script is understood and has no execution step. A script with a known download plus an unrecognized remainder is `unknown`, not Medium.
- A fully understood harmless local-output statement can be `no_download`. Other unrelated scripts outside the grammar may remain `unknown`; neither generates this rule's alert.
- Keep syntax evidence separate from runtime outcomes. Even a High result means the script instructs retrieval and execution; it does not prove either succeeded.

### Required tests before claiming support

| Input | Expected analysis |
|---|---|
| Each of the three execution patterns, for each download-text expression | High / 73 |
| Supported download alone and supported assignment-only download | Medium / 47 |
| Upper/lowercase variants and full `Invoke-Expression` name | Same result as equivalent IEX pattern |
| Comment or quoted example containing download and IEX words | No match if the whole script is otherwise supported; otherwise unknown |
| Download result assigned to one variable but IEX given another | Unknown; not High or a confirmed Medium |
| Download variable reassigned before IEX | Unknown |
| Download followed by an unsupported extra command | Unknown; no Medium fallback |
| Wrong execution argument, incomplete brackets, malformed encoding or truncated text | Unknown |
| Encoded harmless local output only | No download; no alert |
| Valid complete script plus missing Office ancestry | No rule alert; preserve the incomplete lineage finding |

These expectations are exercised by the local Python test suite where within its documented scope. Native PowerShell behavior and Elastic outcomes are not verified. The implementation uses a limited tokenizer/pattern matcher, not a PowerShell interpreter; exact grammar, bounds and launcher handling are documented in the processor README. No dependency or live collection was added.

## Telemetry contract and proposed mapping

Source name remains `logs-p1-powershell-synthetic`, matching the existing operator's read-only boundary. Index creation and ingestion require separate approval. A regular-index attempt was rejected by the built-in logs data-stream template. The [exact-name data-stream proposal](P1-PS-001_Data_Stream_Review.md) preserves these explicit mappings and one-primary/zero-replica lab settings; it was approved and installed; indexed query validation passed, with the rule still disabled. This is not a production retention or availability design.

| Field | Proposed mapping | Purpose |
|---|---|---|
| `@timestamp` | date | Source process-start time; UTC fixtures anchored to a controlled run time |
| `event.id` | keyword | Unique synthetic source event identifier |
| `event.category`, `event.type` | keyword | `process`, `start`; test array-valued ECS representations separately |
| `event.dataset` | keyword | Mark synthetic origin without exposing real identities |
| `host.id`, `host.os.type` | keyword | Host correlation boundary and Windows scope |
| `process.entity_id`, `process.parent.entity_id` | keyword | Stable process-instance linkage; never PID-only |
| `process.name`, `process.parent.name` | keyword | Raw process/parent basenames |
| `process.command_line` | wildcard | Original command-line evidence |
| `process.args` | keyword | Argument array, if supplied by source or a reviewed parser |
| `process.pid`, `process.parent.pid` | long | Investigation context only; PID reuse prevents using these alone as identity |
| `p1.fixture_id`, `p1.test_run_id` | keyword | Test bookkeeping; never a reason to classify behavior as suspicious |
| `p1.powershell.decoded_script` | wildcard | Proposed retained, safely decoded script text; treat real-world content as potentially sensitive |
| `p1.powershell.script_evidence.source` | keyword | `encoded_command` or associated `script_block`; retain provenance |
| `p1.powershell.script_evidence.status` | keyword | `download_only`, `download_and_execute`, `no_download`, `unknown`; calculated from script evidence |
| `p1.powershell.script_evidence.pattern` | keyword | Recognized retrieval-to-execution pattern; retain source event references |

Process Creation 4688/Sysmon 1 are proposed future source options, not currently integrated. Actual source availability, command-line auditing, ProcessGuid/entity-ID mapping, and argument parsing must be validated. An ordinary process-start document does not establish that encoded code executed successfully.

## Agreed architecture: prepare evidence before ES|QL

The user selected preprocessing followed by one non-aggregating ES|QL rule on Elastic 8.13. This replaces the earlier open choice between enriched ES|QL and EQL. No deployment, ingestion pipeline, runtime, or dependency is approved or created by that decision.

The proposed local preparation component will:

1. Preserve raw input events and command lines. Synthetic fixtures remain local until ingestion is approved.
2. Index process records in memory by `(host.id, process.entity_id)`. Trace the immediate parent; when it is `cmd.exe`, resolve its parent to the Office process. Use source instance IDs and event times to check ordering; never join solely by PID. Missing, conflicting or out-of-order ancestry remains incomplete until resolvable, not a fabricated Office connection.
3. Read only the true encoded launcher argument, decode Base64/UTF-16LE within an explicit size limit, and inspect text without evaluating it or contacting a URL. Recognize only reviewed patterns; unsupported script structure remains unknown.
4. Classify the fully understood script as `download_only`, `download_and_execute`, or `no_download`; use `unknown` when analysis is incomplete. A supported recognized download is necessary for either alerting classification. Keep evidence-source references and analysis-version metadata.
5. Produce one finalized result per original PowerShell event. Keep a stable document ID derived from its source identity and preserve original event time. ES|QL filters qualifying results and severity/risk mappings consume prepared priority fields. Do not emit separate Medium and High rows for one event.

The implemented parser/limits are documented in the processor README; source evidence is retained locally in ignored validation storage. Analysis version is p1-ps-001-local-v1. Unsupported/late evidence is not automatically reindexed or upgraded. Do not create an Elasticsearch raw-event index or broaden the role merely to store evidence. The synthetic source name remains the already reviewed `logs-p1-powershell-synthetic`. Source setup/ingestion uses approved setup privileges, never the read-only detection identity.

This is not an Elasticsearch ingest pipeline implementation: no ingest pipeline, service or new infrastructure is assumed. The local helper implements the first lab iteration. Synthetic input must contain real linked process records that the helper resolves, rather than prefilled `office_origin: true` labels used as expected results.

### Prepared-event example

Illustrative input, not live telemetry:

| Event ID | Host / process instance | Parent instance | Process | Script evidence |
|---|---|---|---|---|
| `lab-office-01` | `lab-host-01` / `office-01` | unrelated shell | `winword.exe` | Not applicable |
| `lab-cmd-01` | `lab-host-01` / `cmd-01` | `office-01` | `cmd.exe` | Not applicable |
| `lab-ps-01` | `lab-host-01` / `ps-01` | `cmd-01` | `powershell.exe` | Encoded command whose decoded text passes downloaded content to IEX |

Example derived fields appended to the preserved PowerShell record:

```json
{
  "p1": {
    "lineage": {
      "office_origin": true,
      "path": "office_cmd_powershell",
      "verified": true
    },
    "powershell": {
      "encoded_command": true,
      "script_evidence": {
        "source": "encoded_command",
        "status": "download_and_execute",
        "pattern": "direct_argument"
      }
    },
    "priority": {
      "severity": "high",
      "risk_score": 73
    },
    "evidence": {
      "event_ids": ["lab-office-01", "lab-cmd-01", "lab-ps-01"]
    }
  }
}
```

These are illustrative outputs the helper must calculate from the input. They do not demonstrate that any parsing or correlation has run. Original ECS fields, encoded command and evidence records must remain available; the example omits them for readability.

### Proposed additional fields

| Field | Mapping | Meaning |
|---|---|---|
| `p1.lineage.office_origin` | boolean | Office origin established from linked source events |
| `p1.lineage.path` | keyword | `office_powershell` or `office_cmd_powershell` |
| `p1.lineage.verified` | boolean | Required instance/host/order checks passed |
| `p1.powershell.encoded_command` | boolean | Supported encoded launcher option was identified |
| `p1.priority.severity` | keyword | `medium` or `high` only for fully classified qualifying events |
| `p1.priority.risk_score` | integer | 47 or 73, consistently paired with severity |
| `p1.evidence.event_ids` | keyword | Source event IDs supporting the result; resolve within host/dataset context |

`p1.powershell.script_evidence.status` uses the four states above, replacing the earlier generic match/non-match proposal. For `unknown` or `no_download`, omit alert-priority fields and exclude the event from alert creation. An understood download-only case becomes Medium/47; linked download-and-run becomes High/73. If valid evidence is absent, do not invent evidence or use Medium as an error fallback.

### Query and duplicate handling requirements

The ES|QL predicate requires Windows process-start, a PowerShell image, verified Office origin, encoded invocation, and one of the two qualifying script classifications. It retains `[metadata _id, _index, _version]` for the installed Kibana 8.13 extraction helper and Elasticsearch engine. Bare METADATA was accepted by Elasticsearch but incorrectly extracted as index names by Kibana 8.13. Behavior matching must not depend on exact priority values: filter classification, then validate provisional scores separately. Configure severity/risk mappings to the prepared priority fields and verify nested field handling in actual alerts before claiming success.

Finalize the classification before initial alerting. Stable source identity alone does not guarantee one alert after later document updates, because 8.13 includes document version in its alert identity. Test unchanged repeated ingestion/runs separately from changed evidence. No existing-alert escalation or mutation mechanism is included. Late/incomplete evidence handling and a bounded preparation delay still need a concrete implementation specification; do not silently reindex a Medium event as High and promise an in-place upgrade.

## Extended suspicious and benign fixture specification

The completed runtime batch used the 14 reviewed script cases for both Word ancestry paths plus one missing ancestor (29 prepared events). The extended matrix below also includes future source/native-version/Office-name cases; it is not a claim that every matrix row ran live. All payloads remain inert text fixtures. Use reserved `.invalid` domains and fictional host/entity IDs. The offline fixture generator Base64-encodes harmless script strings; never execute those strings, download content or contact destinations. Encoded `Write-Output` alone is now a negative case, superseding the earlier encoded-only design.

| Case | Synthetic behavior / condition | Expected result |
|---|---|---|
| P01 | Word directly starts encoded PowerShell; decoded supported WebClient retrieval-to-IEX linkage | One High alert / 73 |
| P02 | Excel direct branch; mixed-case names/options; supported WebRequest response Content-to-Invoke-Expression linkage | One High alert / 73 |
| P03 | Candidate `-enc`, `-ec`, `-e` fixtures with supported linked script | One High alert / 73 only after option compatibility and parsing tests |
| P04 | Office → cmd → encoded PowerShell with verified entity linkage and supported linked script | One High alert / 73 under the chosen ancestry architecture |
| P05 | Entire composite with no hidden/bypass options | One High alert / 73; supporting flags not required |
| P06 | Entire composite plus hidden/bypass options | One High alert / 73 per source PowerShell event |
| N01 | Office-originated encoded harmless local output | No composite match |
| P07 | Office-originated encoded supported retrieval with no execution of retrieved content | One Medium alert / 47 |
| N03 | Office-originated encoded IEX of local text with no retrieval | No composite match |
| N04 | Supported retrieval and execution text without encoding | No match in this scoped rule |
| N05 | Encoded linked download/execution without qualifying Office ancestry | No match in this scoped rule |
| N06 | Retrieval/IEX names occur only in comments, quoted examples or unrelated variables | No match for supported structural cases; unknown for unsupported syntax |
| N07 | `-ExecutionPolicy`, `-EncodedArguments`, or tokens after `-File` confused with launcher encoding | No match |
| N08 | Missing encoded value, failed decoding with no associated qualifying script, or missing lineage | No match; visibility/parsing issue recorded separately |
| N09 | Matching PIDs but different host/process-instance identities | No intermediate match |
| N10 | Names such as `notpowershell.exe` | No match |
| N11 | Qualifying script block belongs to a different process or is incomplete | No composite match |
| C01 | Entire instruction composite but blocked/failed network retrieval | One High alert / 73; transfer/execution success remains unconfirmed |
| C02 | Entire composite with no available network telemetry | One High alert / 73; no invented network evidence |
| FP01 | Approved Office automation retrieves and dynamically executes a trusted script with encoding | Match by design; document a realistic false-positive case |
| C03 | Script contains retrieval but execution analysis is unsupported/incomplete | Unknown; do not silently assign Medium |
| C04 | Same source event satisfies both download and run conditions | One High alert / 73; no additional Medium alert |
| G01 | Download-to-disk then execution, WMI-mediated lineage, renamed image, deeper ancestry or unsupported obfuscation | Explicit gap/unknown as applicable; not claimed covered |

Do not add broad Office/host/user allowlists to suppress FP01. Any exception needs justification and additional positive/negative tests. Compare the previous encoded-only predicate with the composite on the same labeled fixtures, reporting excluded benign cases and missed/unknown suspicious cases. A synthetic comparison does not establish a production false-positive rate.

## Validation procedure and acceptance

Analyze the script as text without running it. Review the available tools before choosing an approach; obtain approval before installing anything new.

1. Implement the agreed event preparation approach after review of safe script normalization, supported structures, raw-evidence retention and CLI parsing contract. Test the proposed encoded-command options against Windows PowerShell 5.1 and PowerShell 7 separately; include quoting, escaping and abbreviation cases before claiming support. Choose how array-valued fields and missing/null fields are handled on 8.13 before writing the final query.
2. Author YAML metadata/query, explicit JSON mappings, JSON/NDJSON fixtures and expected-result manifest; validate using existing tools without adding dependencies silently. Convert only supported deployment fields to Kibana API JSON; retain engineering prerequisites/tests in the repository.
3. Before resources exist, run meaningful local checks of fixture identity/linkage, option position handling, bounded decoding, structural pattern/data-flow handling, mapping definitions and expected IDs. Impose an explicit size limit and fail to unknown on unsupported encoding/content; never evaluate script text. Local predicates must not be presented as proof of the Elastic engine's behavior.
4. After explicit approval, create only the agreed lab index and ingest fixtures using a setup identity with write permission. The detection operator remains source-read-only; do not expand its role to ingest.
5. Execute the actual selected engine query and compare exact source event IDs against expected results. Verify that every alert includes references to Office ancestry, encoding and download evidence; assert Medium/47 or High/73 as appropriate. High alerts must reference the downloaded-content-to-execution linkage. Label instructions as such, not confirmed transfer/execution. Test nulls, absent fields, mixed case, argument boundaries, multiple hosts, PID reuse and, where applicable, ordering/missing events and the proposed correlation window. Record parser and engine failures honestly.
6. Current scheduling: five-minute interval, `from: now-7m`, `to: now` (two-minute additional look-back), maximum 100 alerts per run, no connectors/response actions. Account for preprocessing delay and source event age; schedule, correlation span and ingestion delay are distinct. Test look-back inclusion/exclusion with fresh deterministic UTC fixture times; do not claim boundary behavior without observed results.
7. Deploy initially disabled using the approved scoped identity, inspect saved query/settings, then enable only after approval. Creation may generate a rule execution API key; treat that as part of explicit deployment authorization, not previously validated Phase C functionality.
8. Observe successful scheduled executions and exact expected alert-source relationships; confirm benign exclusions and repeated overlapping runs do not duplicate alerts for unchanged sources. Separate query matches, preview artifacts and scheduled alerts in evidence.
9. Compare specificity and coverage against encoded-only cases, retaining realistic legitimate composite matches. Do not claim lower false positives without recording the measured test population and results.
10. Keep the same stable rule identifier for controlled updates. No production efficacy/recall claim from a small synthetic fixture set. Document count limits, dropped telemetry and expected false positives.

Acceptance: both severity/risk branches and High precedence pass with exactly one alert per unchanged qualifying source event; all agreed engine-query fixtures pass, scheduled runs succeed under the scoped identity, exact expected alerts appear with no unexpected duplicates, and no connectors, unrelated indices or infrastructure settings are modified. Every unchecked requirement stays marked pending.

## Deployment and rollback boundaries

The exact data stream/template, fixtures and tested P1-PS-001 lab rule exist. The rule is disabled; 58 source records and 14 alerts are retained. Further resource/data creation, Kibana-managed execution-key replacement, activation and cleanup require explicit authorization. Current code changes do not authorize a new live run.

Before deployment, inventory existing rule IDs and resources to avoid overwrite. Rollback disables only the new rule, preserving source/alert evidence. Deletion of the rule, its API key, synthetic index or alerts needs explicit cleanup approval and exact identifiers. Never delete shared alert indices, change operator privileges or rotate existing credentials as a workaround. Preserve TLS, encryption, volumes and n8n.

## Sources and evidence limits

- [CERT-EU Emotet 2019](https://cert.europa.eu/publications/security-advisories/2019-021/): encoded PowerShell and WMI-mediated execution; supports the stated coverage gap.
- [Unit 42 Emotet chain, December 2020–January 2021](https://unit42.paloaltonetworks.com/attack-chain-overview-emotet-in-december-2020-and-january-2021/): nested command-shell execution before encoded PowerShell; no population-wide prevalence claim.
- [Microsoft Invoke-Expression](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression): executes supplied string content; the built-in alias is IEX.
- [Microsoft Invoke-WebRequest](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest): retrieval and response handling; retrieval alone is not code execution.
- [Microsoft Windows PowerShell executable reference](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1): encoded-command semantics and UTF-16LE input.
- [Elastic 8.13 detection creation](https://www.elastic.co/guide/en/security/8.13/rules-ui-create.html): version-specific ES|QL preview and deduplication requirements.
- [Elastic introduction of LOOKUP JOIN in 8.18](https://www.elastic.co/blog/esql-lookup-join-elasticsearch): do not assume later join capabilities on 8.13.

## Verifier and safety policy

Use an immutable activation timestamp. Pending/missing evidence cannot be called a
confirmed rule failure; deadline expiry is inconclusive. A success observed after
the seven-minute bound cannot pass. All ancestor event IDs must be nonempty
strings before verified lineage is emitted; malformed IDs stay unknown.

The approved warm-up procedure permits one isolated first-run historical gap only
with explicit opt-in and no other error; coverage stays failed. Require a clean
second run within seven minutes of the first, or disable. The fixture test has a
12-minute bound after ingestion and always disables afterward. Exactly 29 fresh
create-only operations use separate setup authentication; no refresh, conflict
retry, extra batch, role edits, key API writes or configuration changes are allowed.
Read-only audit and fixture generation do not enable anything. Tests mock live
operations; rerun deployment only after a new approval/recording checkpoint.
