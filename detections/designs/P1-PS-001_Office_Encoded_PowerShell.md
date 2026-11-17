# P1-PS-001 — Office → encoded PowerShell → download

**Status:** Implemented and validated in the synthetic lab on 14 November 2026; rule disabled after testing. The controlled batch produced 6 Medium/47 and 8 High/73 alerts, including two intentional automation false positives; 15 exclusions and unchanged-source deduplication passed across two overlapping scheduled runs. No production effectiveness claim.

## Purpose

Detect an Office application starting encoded PowerShell that contains download instructions. Assign High severity when the script also contains instructions to run the downloaded content. This targets a common malware-delivery pattern, including behavior seen in Emotet campaigns.

## When it should alert

All three conditions must be present:

1. **Office starts PowerShell**, directly or through `cmd.exe`.
2. **PowerShell uses an encoded command.**
3. **The script contains a supported download instruction.**

Supported process paths:

```text
Office → PowerShell
Office → cmd.exe → PowerShell
```

A hidden window or execution-policy bypass can add context, but neither is required or enough to trigger this rule.

## Detection logic (Pseudocode)

```text
IF Office starts PowerShell, directly or through cmd.exe
AND PowerShell uses an encoded command
AND the decoded script contains supported download instructions:

    IF the downloaded content is passed to execution:
        Create one HIGH alert, risk score 73
    ELSE IF the script is understood and download-only:
        Create one MEDIUM alert, risk score 47
    ELSE:
        Record incomplete evidence; do not assume download-only
```

This describes instructions found in the script, not confirmation that they ran successfully.

## Severity and risk score

This is one rule with conditional severity, not two separate alerts.

| Evidence in the script | Severity | Risk score |
|---|---|---:|
| Download instructions without instructions to run that content | Medium | 47 |
| Download instructions plus instructions to run that downloaded content | High | 73 |

Inspect the complete supported script before creating the alert. High takes precedence: a script meeting both conditions produces one High alert. These scores prioritize investigation; they are not probabilities and do not trigger automatic blocking.

Unreadable or unsupported script content is incomplete evidence, not a confirmed download-only case. This version does not automatically upgrade an existing alert when later evidence arrives.

## What we need to see

- Process records showing the Office connection and PowerShell command line.
- The encoded command decoded into readable text, without running it. Process-linked script-block logs are a future alternative; this implementation does not collect/reconstruct them.
- A supported download operation. For High severity, its returned content must be passed to `Invoke-Expression` or its alias, `IEX`.

For the first version, proposed download operations are `Invoke-WebRequest` (its response content) and `WebClient.DownloadString` (its returned text). To assign High severity, finding a download word and `IEX` somewhere in the script is not enough: the downloaded content must be what the script intends to run. Comments and quoted examples must not trigger an alert.

Network activity can help the investigation, but is not required. Severity describes instructions found in the script. Confirming that a download or execution succeeded needs additional evidence.

## Examples to test

| Example | Expected result |
|---|---|
| Office → encoded PowerShell → download text and pass it to IEX | One High alert / 73 |
| Office → cmd.exe → encoded PowerShell with the same behavior | One High alert / 73, once Office ancestry is established |
| Office → encoded PowerShell that only prints a message | No alert |
| Office → encoded PowerShell with supported download-only instructions | One Medium alert / 47 |
| Script only mentions download/IEX in a comment | No alert |
| Same behavior without encoding or without Office ancestry | Outside this rule's scope |
| Script cannot be read, or its Office connection is missing | Insufficient evidence; do not count it as a match |
| Legitimate Office automation meets all three conditions | May alert; use this to evaluate false positives |

Local tests cover casing, declared argument abbreviations, missing/malformed fields, incomplete scripts and priority assignments. Actual Elastic alerts verified both priority branches and unchanged-source duplicate handling for the reviewed 29-event batch. Native PowerShell argument compatibility remains untested.

## Limits

The first version does not cover renamed executables, WMI-mediated launches, longer process chains, or downloading a file to disk and running it later. Unrecognized script forms remain untested. Combining signals may reduce noise, but we must test that rather than assume it.

## Agreed processing approach

Prepare the evidence before ES|QL reads it:

```text
Original process events → trace Office ancestry → read encoded script safely
→ prepare one event with evidence and priority → ES|QL rule → alert
```

Keep the original events and references showing how the result was reached. Missing ancestry or unreadable scripts remain incomplete evidence. The proposed fields and a worked example are in the [supporting plan](P1-PS-001_Technical_Test_Plan.md#prepared-event-example).

A standard-library Python prototype now recognizes a limited set of script patterns without running them. See the [local processor and its limits](../processing/README.md). No new dependency was added.

## Implementation and testing

Actual query: [P1-PS-001 ES|QL](../rules/P1-PS-001_Office_Encoded_PowerShell.esql). Rule settings: [YAML definition](../rules/P1-PS-001_Office_Encoded_PowerShell.yml). The installed lab rule uses interval 5m and a seven-minute search window (two-minute additional look-back). It was enabled for controlled validation and disabled afterward.

The source uses an exact-name, priority-501 data-stream template with strict ECS-shaped and p1 fields. See [actual results and limits](../tests/P1-PS-001_Runtime_Validation.md) and [runtime tool instructions](../processing/RUNTIME_TOOLS.md). Future live runs require approval. No malware execution, connectors or automated response actions are included.

Detailed fields, test cases, implementation choices, references and rollback steps are in the [supporting technical and test plan](P1-PS-001_Technical_Test_Plan.md). Keep the existing rule ID, `P1-PS-001`, across revisions.
