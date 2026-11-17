# Day 2 security preparation — review before execution

Current summary reviewed 17 November 2026; security rollout on 12 November, synthetic runtime validation on 14 November: Phases A and B are complete. CA/server material and the persistent Kibana key were generated and backed up; only Elasticsearch and Kibana were recreated. Authenticated HTTPS, CA/hostname verification, green cluster health, Kibana availability and `has_encryption_key: true` passed. n8n, credentials, volumes and loopback bindings were preserved; no rollback was needed. Phase C was subsequently approved and completed: the exact reviewed role/user was provisioned and positive/negative permission checks passed. The synthetic rule was subsequently approved and validated on 14 November 2026; it is disabled with 58 source records and 14 alerts retained. See runtime evidence for the 6 Medium/47, 8 High/73, 15 exclusions and deduplication results. See the Day 2 implementation log for sanitized evidence. Procedures below preserve the reviewed rollout plan; do not regenerate existing keys or repeat rollout without authorization.

## Configuration and secret inventory

| Location | Prepared change / later prerequisite |
|---|---|
| `.gitignore` | Excludes all `infra/certs/` material, including generation archives. |
| `infra/.env` | Phase A added the persistent `KIBANA_ENCRYPTION_KEY` (64 hexadecimal characters), preserving existing values; never display it. File mode is now `0600`. |
| `infra/docker-compose.yml` | Removes Elasticsearch's HTTP-disable override; HTTPS healthcheck trusts the CA; passes the required encryption key; read-only, non-auto-creating certificate binds; HTTPS Kibana upstream. |
| `infra/elasticsearch/elasticsearch.yml` | Enables HTTP TLS with `certs/elasticsearch.crt` and `certs/elasticsearch.key`. No client certificate required; existing authentication remains required. |
| `infra/kibana/kibana.yml` | HTTPS upstream; trusted `certs/ca.crt`; full hostname verification; saved-object encryption from environment. |

The Elasticsearch healthcheck expands its password inside the container using Compose `$$`, rather than embedding the interpolated password into the configured healthcheck command. Docker administrators can still access environment credentials; never share unredacted inspect/config output.

## Certificate and key procedure — historical reviewed procedure

1. Verify ignore rules and a secure backup destination before generating anything. Do not overwrite any existing local certificate or key without review.
2. Use `elasticsearch-certutil ca --pem` and `elasticsearch-certutil cert --pem` from the installed 8.13 image, in an isolated approved generation job that has no project data volumes. Select node name `elasticsearch`, DNS SANs `elasticsearch,localhost`, IP SAN `127.0.0.1`, and an explicit 365-day server validity period. Protect generation archives because they contain private material. Review the exact invocation and mounts before running the job.
3. Keep the CA signing key and generation archives in protected, ignored offline storage, outside all service mounts. Copy only the public CA certificate to `infra/certs/ca.crt`, the server certificate to `infra/certs/elasticsearch.crt`, and the server private key to `infra/certs/elasticsearch.key`.
4. The proposed PEM server key has no passphrase to avoid introducing an Elasticsearch keystore persistence dependency. Protect it with restrictive host permissions and a read-only file mount accessible only to the intended container identity/host administrators. If that boundary is insufficient, stop and review an encrypted-key/keystore design before generation. Do not use world-readable private keys.
5. Generate the Kibana key directly into ignored local storage without stdout, shell-history, or command-argument exposure. Back it up securely. Never regenerate it on startup. Persisting the same key across recreation is essential for decrypting saved rule credentials.
6. Verify certificate chain, expiry, SANs, matching private key, file ownership, and actual container readability. Kibana receives only the CA certificate. No global OS trust-store changes or verification bypasses are proposed.

Only HTTP-layer TLS is included; this remains a single-node deployment. Browser-to-Kibana and n8n endpoints remain HTTP on loopback. Every Elasticsearch client must switch to HTTPS and explicit CA trust. Certificate renewal is a later approved operation before expiry.

## Concrete generation commands — documentation only; do not execute before approval

Run from the repository root only after checking these destinations do not already exist and confirming the intended Docker image is present. No image pull, dependency installation, or network access is needed. The generation containers mount only the ignored staging directory, never Elasticsearch data. They are temporary tooling containers, not running services.

```sh
umask 077
mkdir -m 700 infra/certs
mkdir -m 700 infra/certs/generation
# Generate a private CA valid for three years; do not publish the archive.
docker run --rm --network none --user "$(id -u):$(id -g)" \
  --mount "type=bind,src=$PWD/infra/certs/generation,dst=/work" \
  docker.elastic.co/elasticsearch/elasticsearch:8.13.0 \
  bin/elasticsearch-certutil ca --silent --pem --days 1095 --out /work/ca.zip
unzip -q infra/certs/generation/ca.zip -d infra/certs/generation
# Sign the 365-day Elasticsearch server certificate.
docker run --rm --network none --user "$(id -u):$(id -g)" \
  --mount "type=bind,src=$PWD/infra/certs/generation,dst=/work" \
  docker.elastic.co/elasticsearch/elasticsearch:8.13.0 \
  bin/elasticsearch-certutil cert --silent --pem --name elasticsearch \
  --dns elasticsearch,localhost --ip 127.0.0.1 --days 365 \
  --ca-cert /work/ca/ca.crt --ca-key /work/ca/ca.key --out /work/elasticsearch.zip
unzip -q infra/certs/generation/elasticsearch.zip -d infra/certs/generation
```

After inspection, copy `generation/ca/ca.crt`, `generation/elasticsearch/elasticsearch.crt`, and `generation/elasticsearch/elasticsearch.key` to the reviewed service paths above. Use mode 0644 for public certificates, mode 0600 or narrowly scoped 0640 for the server key, and restricted directory traversal permissions. Confirm the actual Elasticsearch container UID/GID and Docker Desktop bind-mount behavior before setting ownership; host-owned mode 0600 may not be container-readable. Never solve a permission failure with world-readable keys. Back up the CA key/archives securely and keep them outside service mounts. Archive storage is not claimed to be offline until actually moved to approved offline storage.

Generate `KIBANA_ENCRYPTION_KEY` using a cryptographic generator (for example, 32 random bytes represented as 64 hexadecimal characters), append directly to `.env` with no stdout, and refuse an existing assignment rather than overwriting it. Generate a separate random password for the native user and store it as `P1_DETECTION_PASSWORD` in ignored `.env`; it must not be passed to any service container. Set `.env` mode 0600 and preserve all existing values. Record only success/validation booleans. Secret generation and these local writes require execution approval.

Native-user creation will use Elasticsearch `PUT /_security/user/p1_detection_operator`, an in-memory JSON body containing `password` loaded from ignored storage, `roles: ["p1_detection_operator"]`, and `enabled: true`. Omit email/full-name personal information. The role uses Kibana `PUT /api/security/role/p1_detection_operator` with the reviewed JSON file. Use administrator Basic authentication loaded into memory, a non-secret `kbn-xsrf` header for Kibana, and the trusted CA for Elasticsearch. Do not put passwords in shell arguments or print HTTP request bodies.

Approved rollout commands, after secret/certificate preflight and a securely stored pre-change configuration copy:

```sh
docker compose --env-file infra/.env -f infra/docker-compose.yml config --quiet
docker compose --env-file infra/.env -f infra/docker-compose.yml up -d --no-deps --force-recreate elasticsearch
# Verify Elasticsearch HTTPS, certificate trust, authentication, and health before continuing.
docker compose --env-file infra/.env -f infra/docker-compose.yml up -d --no-deps --force-recreate kibana
```

`config --quiet` does not verify minimum key length or certificate contents: preflight must enforce both. Never run these rollout commands during preparation. If an installed tool/image is missing or tooling cannot run under the proposed non-root UID, report the specific problem before introducing dependencies or broad permissions.

## Scoped identity — reviewed payload, provisioned in Phase C

Proposed native username: `p1_detection_operator`; role: `p1_detection_operator`. Password delivery/storage must be approved and kept outside tracked files. Assign this role alone, with no superuser or broad Kibana base role. Source creation and ingestion remain administrator-controlled lab setup operations.

The following is a proposed body for Kibana `PUT /api/security/role/p1_detection_operator`. Read-only verification against installed Kibana 8.13.0 confirmed feature IDs `siem` and `indexPatterns`, each with `all` and `read` privileges. The role/user names returned HTTP 404 during the historical pre-provisioning review; Phase C subsequently created them. Do not treat that old probe as current absence or provision again. The exact machine-readable body is also saved in `infra/security/p1_detection_operator.role.json`. If IDs or required permissions differ, stop and revise the proposal rather than silently broadening it.

```json
{
  "elasticsearch": {
    "cluster": ["manage_own_api_key"],
    "indices": [
      {
        "names": ["logs-p1-powershell-synthetic"],
        "privileges": ["read", "view_index_metadata"]
      },
      {
        "names": [".alerts-security.alerts-default", ".lists-default", ".items-default"],
        "privileges": ["manage", "write", "read", "view_index_metadata"]
      },
      {
        "names": [".internal.alerts-security.alerts-default-*"],
        "privileges": ["read", "view_index_metadata"]
      },
      {
        "names": [".preview.alerts-security.alerts-default", ".internal.preview.alerts-security.alerts-default-*"],
        "privileges": ["read", "view_index_metadata"]
      }
    ]
  },
  "kibana": [
    {
      "base": [],
      "feature": {"siem": ["all"], "indexPatterns": ["all"]},
      "spaces": ["default"]
    }
  ]
}
```

This is a bounded lab operator, not per-rule isolation: Security All covers other security rules in the default space, and Data View Management All allows default-space data-view management. Use a dedicated space later if stronger isolation is required. Alert/list `manage` and `write` are scoped but significant. Do not write directly to internal alert indices. No legacy `.siem-signals-*` grants are proposed for this fresh 8.x lab.

An administrator handles missing detection/list initialization separately; the operator receives no cluster `manage`, `manage_security`, or source-write privileges. Kibana manages execution keys using the acting identity when enabling/updating the rule; disabled-rule creation alone did not establish key generation in this lab. Keep rule enable/edit operations under this identity. Do not replace its execution privileges by editing as administrator. No standalone API key is created during preparation.

## Historical ordered rollout — do not repeat without new approval

1. Capture sanitized pre-change health, volume identities, ports, rule count, role/user name collisions, and current Git status. Back up current configuration and secret material securely. Existing source/config bind mounts mean a spontaneous container restart could load prepared files; keep this preparation window short and do not restart before prerequisites exist.
2. Scoped-role feature IDs were verified read-only; recheck for drift before provisioning. Approve the exact role and user provisioning separately. Review generation job and storage permissions before authorizing certificate/key generation.
3. Provision approved material. Validate Compose quietly and check certificate readability. Static validity alone is not a deployment check.
4. Recreate Elasticsearch alone with no dependency recreation, using existing volumes; verify HTTPS with CA trust and administrator authentication. Expect a temporary Kibana upstream interruption during the HTTP-to-HTTPS transition.
5. Recreate Kibana alone to load the CA, HTTPS endpoint, and persistent encryption key. Do not recreate n8n. Confirm both affected containers healthy, Elasticsearch green, Kibana available, and n8n still accessible.
6. Confirm HTTPS succeeds with CA trust, fails without private CA trust, and HTTP no longer serves the REST API. Do not use `-k`. Confirm detection privileges `has_encryption_key: true`. Verify API-key service availability after enabling HTTP TLS before creating the operator/rule.
7. Provision approved role/user; check effective privileges. Positive: exact source read/metadata and default-space rule/alert access. Negative: unrelated source indices, source writes, security administration, connector management, and other-space rule management. Use privilege-check APIs and non-mutating access requests; any write-based negative test needs its own approved disposable test scope.
8. At the original readiness checkpoint the source did not exist. Source reads, scheduled execution and alert behavior were later validated under separate approval; see the runtime evidence. Key persistence through a further container recreation was not tested by the detection runs. Authorization checks alone are not detection results.

## Rollback

- Stop on failed certificate, ownership, trust, health, or privilege validation; do not weaken verification or broaden access as a workaround.
- If Elasticsearch cannot start, restore only the approved TLS configuration/Compose changes to their pre-rollout state and recreate Elasticsearch with the existing data volume. Restore matching Kibana HTTP upstream and the previous healthcheck if reverting HTTPS. Retain certificate material securely for diagnosis; no volume removal or Git reset.
- If only Kibana fails, first correct trust/mount/key issues; retain functional Elasticsearch HTTPS where possible. Full HTTP rollback must coordinate both services and healthchecks.
- Before encrypted objects exist, the encryption configuration can be reverted if necessary. After rules exist, retain the original encryption key; do not remove or rotate it casually. Recovery may require the backed-up original key, not a newly generated replacement.
- If operator provisioning fails before rules exist, disable only the new user and remove the new role after checking ownership/collisions. After rules exist, first disable affected rules, inventory their execution API keys, then review targeted retirement. Never touch existing Kibana service-account tokens.
- Preserve all named volumes and data. Never use `down -v`, destructive cleanup, blanket credential revocation, force-push, or unapproved commits.

## Recording and follow-up

**RECORD BEFORE:** safe service-health view and empty detection-rule list immediately before runtime deployment; ask before proceeding if that capture matters. **RECORD AFTER:** healthy services and encryption-key readiness, without configuration/credentials. **NO RECORDING NEEDED:** preparation-only review.

After security acceptance, separately review the first synthetic PowerShell index, mappings, fixtures and ES|QL rule. Use 8.13 metadata syntax for deduplication, and test suspicious/benign cases, missing fields, casing, timestamps and repeated runs. No endpoint payload execution, connectors or automated response actions.

## Consolidated approval boundary

Approve explicitly, together or individually:

- **A — Material generation:** temporary network-isolated tooling containers; CA/server certificate generation; persistent Kibana key generation; protected ignored storage and secure backup. No service/data volumes mounted into tooling containers.
- **B — Runtime rollout:** recreate only Elasticsearch and Kibana with prepared settings; accept brief service interruption; validate TLS, health, bindings, volumes, and encryption readiness; authorize the documented targeted configuration rollback if rollout fails. Keep n8n running.
- **C — Identity:** create exactly the proposed `p1_detection_operator` role/user, generate its password directly into ignored `.env` as `P1_DETECTION_PASSWORD`, and run non-mutating privilege checks. Do not create a standalone API key or source index. Targeted identity rollback must affect only newly provisioned resources.

No synthetic data/index/rule creation, dependencies, commit, push, or publication is included. Approval does not waive the pre-change recording checkpoint if capturing the state matters to the user.

## References

- [Elastic 8.13 HTTPS setup](https://www.elastic.co/guide/en/elasticsearch/reference/8.13/security-basic-setup-https.html)
- [Elastic 8.13 detection requirements and permissions](https://www.elastic.co/guide/en/security/8.13/detections-permissions-section.html)
- [Kibana 8.13 feature privileges and role API](https://www.elastic.co/guide/en/kibana/8.13/kibana-privileges.html)

## Outstanding healthcheck follow-up — proposal only

The password still expands into curl process arguments inside the container. See
[protected credential-file alternative](day2-healthcheck-proposal.md). No healthcheck,
credential file, mount, identity or container change is included in the 17 November
local-code corrections. That security follow-up requires separate approval.
