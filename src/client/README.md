# Password lookup CLI

Build with `go build -o testpassword .` in this directory.

For manual checks, use a hidden terminal prompt:

```sh
./testpassword --prompt
```

For automation, inject `TESTPASSWORD_PASSWORD` through your runner's secret
configuration, then run:

```sh
./testpassword
```

The variable is used only when no explicit input (`--prompt`, `--sha1`, `--ntlm`,
or `--password`) is selected. A set-but-empty variable checks an empty password;
an unset variable is an input error. Whitespace is preserved. Environment
variables cannot represent a NUL byte.

Use `--formats sha1`, `--formats ntlm`, or `--formats both` (the default) for
password inputs. `--prompt` requires terminal stdin and never falls back to the
environment if terminal input fails. Only one explicit input may be selected.

Plaintext passwords are no longer printed. The legacy `--password VALUE` flag
remains for compatibility, but exposes the value in process arguments and
possibly shell history. Prefer the prompt or an injected environment variable.
Environment variables can still be visible to privileged processes, inherited
by child processes, or captured in diagnostic dumps. Do not print the environment
or enable shell tracing around secret injection.

Passwords are still sent to the API's `/check` endpoint for hashing. The default
API is `http://127.0.0.1:8000`; use a trusted local service or HTTPS for remote
connections (`--api https://...`). Output includes the resulting password hashes,
which should also be treated as sensitive.

Exit codes:

- `0`: Every requested format returned a valid result from a loaded, complete
  dataset, with no breach match.
- `1`: A confirmed breach match in any requested format, even if another result
  is missing, invalid, or uses an unavailable/incomplete dataset. Other
  inconclusive checks are reported on stderr.
- `2`: An input, network, or API error, or no confirmed match with at least one
  inconclusive check. Missing/invalid results and unavailable/incomplete datasets
  cannot establish a negative result.

Only requested formats affect the exit code. Automation should branch on all
three codes and treat `2` as an unsuccessful check, not a negative result.

## Self-signed HTTPS certificates

Certificate and hostname verification are enabled by default. To skip them for
an end-user-hosted API, use `--insecure` or export
`TESTPASSWORD_TLS_INSECURE=true`. HTTPS traffic remains encrypted, but the CLI
cannot authenticate the server, so an intermediary could impersonate it.

From the project root, load the supplied `.env` and run:

```sh
set -a
. ./.env
set +a
./src/client/testpassword --api https://localhost --prompt
```

The CLI reads environment variables; it does not automatically load `.env`.
Docker Compose reading `.env` does not export it into your shell. Alternatively:

```sh
./src/client/testpassword --api https://your-host --insecure --prompt
```

An explicit `--insecure=false` overrides the environment and restores
verification. Invalid environment values fail with an input error. To keep
verification with a private CA, install that CA in the client's trust store.
This option does not affect browsers or the API's optional S3 connections.
