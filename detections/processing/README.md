# Local PowerShell evidence preparation

The Python classifier is an offline lab prototype for P1-PS-001. Its prepared output has been tested through an actual Elastic lab rule; that rule is now disabled. This is not an endpoint collector or production pipeline.

**Hypothesis:** Office-originated encoded PowerShell with download instructions deserves investigation. If the downloaded text also feeds execution, assign a higher provisional priority.

## Run with synthetic input only

From the project root:

```sh
python3 -B -m unittest discover -s detections/tests -p 'test_*.py' -v
python3 -B detections/processing/powershell.py detections/tests/fixtures/office_cmd_high.json
```

The second command prints a JSON bundle containing the unchanged original events and derived PowerShell records. Decoded script text appears in this bundle: do not run it on sensitive input or display unreviewed production evidence during recording. The program reads only the input file; it has no network, PowerShell, shell-evaluation or subprocess implementation. Tests use inert `.invalid` URLs and never execute the script strings.

## What Python establishes

1. Resolve source events by host ID and process-instance ID. Accept Office → PowerShell or Office → cmd.exe → PowerShell; require consistent parent names, process-start events and timezone-aware start times. Missing/conflicting evidence becomes unknown.
2. Require a normalized `process.args` array that includes the executable as its first element. Locate a supported encoded launcher option before script arguments. Decode strict Base64/UTF-16LE; never run it.
3. Tokenize the decoded script into commands, strings, variables and punctuation. Discard simple line comments. Match only the explicitly supported structures below, consuming the entire script.
4. Add source references and a deterministic `p1.document_id`. Preserve the original ECS record; ignore any supplied `p1` classification/priority labels. The CLI bundle keeps the complete original input, including any original custom fields.

| Full-script classification | Proposed output |
|---|---|
| Understood download only | `download_only`; Medium / 47 |
| Downloaded text passed to IEX | `download_and_execute`; High / 73 |
| Supported literal output / empty script / comments only | `no_download`; no priority |
| Missing, ambiguous, malformed or unsupported evidence | `unknown`; no priority |

All scores are **provisional**. A legitimate authorized Office automation script can receive High; no broad allowlist was added. A syntactic High result does not prove a transfer or execution succeeded.

## Why IEX matters

`IEX` is the built-in alias for `Invoke-Expression`. It treats a string as PowerShell instructions and runs them.

For an attacker, this can turn downloaded script text into running code without first saving that script as a `.ps1` file. Downloading content alone retrieves data; passing that content to IEX adds instructions to execute it. That is why this detection assigns a higher provisional priority when it finds that connection.

IEX is also used legitimately, and attackers can execute code in other ways. Its presence alone does not make a script malicious, and a missing IEX does not make one safe. Our processor reads these instructions as text—it never runs them or confirms that execution succeeded.

## Exact initial pattern scope

- Literal quoted HTTP/HTTPS URLs. Quotes/comments are handled as tokens, not keyword evidence. Double-quoted interpolation/backticks are rejected; single-quoted doubled quotes are recognized.
- `Invoke-WebRequest` in full, with positional URL or `-Uri`; no additional options. The response itself supports download-only classification. Its parenthesized `.Content` supports execution-text classification.
- `(New-Object Net.WebClient).DownloadString(...)` and the `System.Net.WebClient` form, with a literal URL.
- Downloaded text passed to `IEX` / `Invoke-Expression` as a direct argument, through a direct pipeline, or through one unchanged simple variable. Names are case-insensitive.
- A single `Write-Output` with one literal string is the benign local-output form. Empty/comment-only content is also recognized. A single download or assignment may be Medium; one assignment followed by execution of that same variable may be High. Extra commands or unsupported structure prevent classification.
- Recognized encoded options: `-EncodedCommand`, `-enc`, `-ec`, `-e`. Optional prefix flags: `-NoProfile`/`-nop`, `-NonInteractive`/`-noni`, `-WindowStyle`/`-w`, `-ExecutionPolicy`/`-ep` with enumerated values. No trailing arguments after the encoded value. `-File`, `-Command`, `-EncodedArguments`, other prefixes and escape forms are unknown.

This tests our declared text grammar, **not native argument acceptance on installed Windows PowerShell 5.1 or PowerShell 7**. Neither runtime was invoked. Do not claim native-version compatibility from Python tests alone.

## Bounds and assumptions

- Maximum decoded input: 65,536 bytes; maximum Base64 argument: 87,384 characters; maximum UTF-8 script representation: 65,536 bytes; 4,096 tokens; parenthesis recursion depth 16.
- For the cmd path, cmd startup must precede PowerShell by no more than 120 seconds, inclusive. This provisional window is tested but not campaign-calibrated. Office itself may have been open much longer. All ancestor start times must precede their children.
- Input is a finite local JSON array of process-event objects using the documented ECS-shaped fields. It is not a streaming collector. Out-of-order file records are resolved by identity, not file position; missing records stay unknown. Duplicate process-instance identities are ambiguous, even if identical.
- `process.args` is authoritative supplied telemetry in this prototype; raw Windows command lines are retained but not independently parsed/compared. Upstream argument accuracy is an assumption, not a capability verified here.
- Built-in command names are assumed unmodified in the target session. Earlier session customization, executable masquerading, absent telemetry, WMI, renamed images and deeper ancestry are outside coverage. Inline redefinitions/complex statements are rejected.
- No script-block event reconstruction, arbitrary variable-flow analysis, dynamic URLs, custom aliases, branches/loops, nested encoding, disk download/execution or network-outcome correlation.
- A deterministic Python result is not proof of Elastic alert deduplication. Updated source versions can still affect future alert IDs.

## What ES|QL will and will not do

The ES|QL rule filters **prepared** fields for verified Office ancestry, encoded invocation and one of the two qualifying classifications. Severity and risk mappings consume the prepared priority. ES|QL does not perform this Python decoding, script matching or ancestry reconstruction automatically.

The [ES|QL query](../rules/P1-PS-001_Office_Encoded_PowerShell.esql), [disabled YAML definition](../rules/P1-PS-001_Office_Encoded_PowerShell.yml), and strict source mappings match the tested lab deployment. Interval 5m plus two-minute additional look-back gives from now-7m/to now. Controlled runtime evidence verified 6 actual Medium/47 and 8 High/73 alerts, 15 exclusions and identical alert IDs across two overlapping runs. Two High alerts intentionally represent legitimate automation. The lab retains 58 source documents and 14 alerts; the rule was disabled afterward. See [runtime evidence](../tests/P1-PS-001_Runtime_Validation.md).

Repository [runtime tools](RUNTIME_TOOLS.md) replace the temporary execution scripts. They include offline 29-case generation, read-only status/audit, and separately gated warm-up/ingestion. Ancestor event IDs must be nonempty strings before lineage is verified. The execution verifier distinguishes pending evidence from actual failure, and cannot pass a success observed after its deadline. Historical evidence is never rewritten by fixture improvements.

Native PowerShell semantics, production false-positive rates, source updates, rollover and later automatic severity escalation remain unverified/out of scope. Python tests alone cannot establish Elastic behavior; the dated runtime evidence supports only the controlled lab cases.
