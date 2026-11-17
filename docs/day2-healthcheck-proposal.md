# Elasticsearch healthcheck credential input — proposal only

The current healthcheck expands `ELASTIC_PASSWORD` into curl's argument list.
Compose `$$` prevents interpolation into the configured command, but does not
remove runtime argument exposure. Curl documents that even argument scrubbing
does not eliminate the transient exposure window.

**Proposed alternative:** use curl's `--netrc-file` with a protected read-only
credential file mounted at `/run/secrets/es-healthcheck.netrc`. The healthcheck
arguments would contain only a path, never a password. Keep the current HTTPS URL,
CA trust, authenticated cluster-health check and green/yellow handling unchanged.
Do not use verbose/debug curl output or print the credential file.

This needs separate approval to prepare secret material outside Git, mount it and
modify/redeploy the healthcheck. No netrc file, credential, Compose change or
container action has been made by this proposal. The existing administrator
credential could be reused without rotation; a dedicated monitor identity would
be a separate least-privilege decision, not an automatic addition.

Before implementation, verify the installed curl supports the file format, escape
its values correctly, and ensure only the intended container UID/host administrator
can read the file (0600 or reviewed 0640). Never make it world-readable to solve a
Docker Desktop mount problem. Keep it outside the Git checkout or explicitly
ignored before creating it. Secret content must stay out of history, process
arguments, rendered configuration output and evidence artifacts.

Validation after separate approval: quiet Compose parsing; inspect only command
structure, permissions and mount metadata; verify no password-bearing curl
arguments; authenticated trusted HTTPS and healthy services. Preserve localhost
bindings, named volumes, keys, role settings, alerts and source data. Do not rotate
credentials or recreate unrelated containers as part of this change.

Rollback: restore the prior reviewed healthcheck configuration and remove only the
new mount through a separately approved targeted deployment. Preserve the secret
file securely pending review; no broad cleanup or credential revocation.

Reference: [curl server-authentication arguments and exposure warning](https://curl.se/docs/manpage.html#-u).
