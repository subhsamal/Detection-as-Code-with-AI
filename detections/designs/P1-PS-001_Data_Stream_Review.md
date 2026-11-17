# P1-PS-001 — Data-stream source review

**Status:** Subsequently approved and installed on 14 November 2026. Data stream and indexed-query validation passed; controlled scheduled alerts and deduplication subsequently passed, and the rule was disabled afterward. See the runtime results for the 58 retained source records and 14 alerts. The proposal and rollback constraints below record the reviewed design.

## Why change the source setup?

The approved name, `logs-p1-powershell-synthetic`, matches the built-in `logs` template. Its `logs-*-*` pattern has priority **100** and requires a data stream, so the regular-index creation request was rejected.

Keep the name and operator role unchanged. Create a data stream using a dedicated template rather than changing the global logs template.

## Reviewed installed template

File: [logs-p1-powershell-synthetic.template.json](../mappings/logs-p1-powershell-synthetic.template.json).

| Setting | Proposal |
|---|---|
| Template name | `p1-powershell-synthetic` |
| Matching name | Exactly `logs-p1-powershell-synthetic`; no wildcard |
| Priority | **501**, above the currently matching priority 100 |
| Data stream | Enabled with `data_stream: {}` |
| Mapping | All reviewed ECS and `p1.*` properties unchanged; strict mapping; `@timestamp` stays `date` |
| Lab shard settings | One primary, zero replicas, only for this new stream's backing indices |
| Components | None; mapping/settings are explicit |

The original [mapping file](../mappings/logs-p1-powershell-synthetic.json) remains the reviewed source contract; the new template wraps it unchanged. Priority affects only matching names. This template does not update existing indices, stream settings or the two unassigned list/item replicas.

**Deliberate difference:** Highest-priority composable templates are selected, not merged with every lower-priority template. Our exact-name template therefore replaces the built-in logs configuration for this stream alone. It does not inherit `logs@mappings`, `logs@settings`, optional `logs@custom`, `ecs@mappings`, their ingest pipelines or lifecycle policies. This controlled lab keeps only our explicit mappings/settings. No automatic rollover, retention or cleanup policy is added; review those separately before sustained ingestion.

## Actual simulation evidence — Elasticsearch 8.13.0

- Anonymous `POST /_index_template/_simulate` with the proposed body returned **HTTP 200**, without installing it.
- All reviewed mapping properties and strict mode were preserved. `@timestamp` remained `date`; settings resolved to one primary and zero replicas. The built-in `logs` template appeared as the overlapping lower-priority template.
- The simulation accepted the data-stream declaration. Its mapping response did not expose the internal `_data_stream_timestamp` mapper; actual data-stream creation must verify that metadata later. No real stream was created to claim that test passed.
- Checked the exact pattern against **40 existing index/stream names** and five other representative names: none matched. Three neighboring logs-name resolution simulations returned identical results before/after the anonymous simulation. The other representative names were checked for pattern non-match, not independently engine-simulated.
- Existing template inventory, data-stream inventory and the operator role were identical before/after simulation. Proposed template, source data stream and source index remained absent (404).
- Initial review probes used GET against a POST-only simulation endpoint and returned 405; corrected POST probes supplied the evidence above. No persistent changes occurred in either case.

These checks establish current template scope and simulated configuration. They do not prove ingestion, operator searches of real backing indices, generated alerts, severity mapping or deduplication.

## Fixture ingestion

The reviewed validation workflow already builds bulk action lines using **`create`**, not `index`, `update` or `delete`. That is compatible with data streams:

```text
POST /logs-p1-powershell-synthetic/_bulk
{"create":{"_id":"<stable synthetic document ID>"}}
<prepared event containing @timestamp>
```

This is a request-format illustration, not a command run during review. Send only prepared records; keep raw evidence local. Use unique test-run IDs, preserve timestamps/order, check every bulk-item status and stop on unexpected errors. Do not overwrite documents or retry conflicts blindly. Stable IDs prevent replacement in the current write index, but do not establish cross-rollover uniqueness or Elastic alert deduplication.

The next approved execution must replace the failed regular-index PUT with template installation plus explicit `PUT /_data_stream/logs-p1-powershell-synthetic`, then resolve its backing index before comparing accepted mappings. Query and operator role can continue using the data-stream name; verify those reads at runtime. The approved revised workflow subsequently completed; the simulation-only results above remain historical.

## Minimum setup privileges

Use a separate setup identity or the existing administrator under explicit exact-operation authorization. Do not expand `p1_detection_operator`.

| Operation | Minimum relevant privilege |
|---|---|
| Simulate/install/read/delete index templates | Cluster `manage_index_templates` (broader `manage` also works but is unnecessary) |
| Explicitly create this data stream | Index `create_index` on `logs-p1-powershell-synthetic` |
| Create-only ingestion into the pre-created stream | Index `create_doc` on that name |
| Optional bulk `refresh=wait_for` (not used by the approved executor) | Additionally `maintenance` on that name; omit refresh and wait for normal visibility to avoid this extra grant |
| Read mappings/source for validation | `view_index_metadata` / `read`, already held by the detection operator for this name |
| Cluster-health guard | Cluster `monitor` for the separate setup/inspection identity; not required merely to create a stream |

`manage_index_templates` is cluster-wide and cannot be restricted to this one template through an index-name grant. Restrict the reviewed procedure to the exact template and keep that privilege off the operator. No new setup role/user/key is proposed or provisioned by this review. Existing administrator use is broad authentication with narrow authorized actions, not a claim of least-privilege authentication.

## Rollout for approval

1. Repeat the exact yellow-health guard: all primaries active, only the two known list/item replicas unassigned, Elasticsearch/Kibana operational. Recheck template/stream/rule collisions and template precedence.
2. Install only `p1-powershell-synthetic` with the reviewed body, using create-only template installation to avoid overwriting an existing template.
3. Simulate target resolution again, then explicitly create only the named data stream. Confirm accepted mapping, timestamp metadata, backing-index shard settings and unchanged health condition.
4. Ingest approved synthetic fixtures with create-only bulk actions, then query as `p1_detection_operator`.
5. If results match, create/inspect the disabled rule as that operator. Preserve the user's **pause before enabling**. Activation and alert tests remain unperformed.

## Rollback and stop conditions

- Before stream creation, if only the new template was installed, stop and request exact-template cleanup approval; remove only that template after verifying it is unused.
- After stream creation, a template used by an existing stream cannot simply be deleted. Stop ingestion; disable only the new detection rule if one exists; preserve evidence and leave the dedicated stream/template in place pending review.
- Destructive cleanup requires separate approval specifying the new stream and its backing indices, followed by its unused dedicated template. Deleting a data stream deletes its backing data; never delete shared logs templates, shared alerts, existing lists/items or unrelated streams.
- To preserve data, retaining the dedicated stream/template is the safe stopped state; there is no automatic return to the rejected regular-index design.
- Stop on extra unassigned shards, inactive primaries, Kibana failure, mapping/privilege errors or unexpected bulk results. Do not broaden permissions, change existing replica settings, add nodes or bypass TLS.

## References

- [8.13 template simulation](https://www.elastic.co/guide/en/elasticsearch/reference/8.13/indices-simulate-template.html)
- [8.13 data-stream creation and privileges](https://www.elastic.co/guide/en/elasticsearch/reference/8.13/indices-create-data-stream.html)
- [8.13 bulk operation and refresh privileges](https://www.elastic.co/guide/en/elasticsearch/reference/8.13/docs-bulk.html)
- [8.13 data-stream behavior and deletion constraints](https://www.elastic.co/guide/en/elasticsearch/reference/8.13/data-streams.html)
