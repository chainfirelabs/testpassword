# Operating TestPassword

Reference for the data jobs, S3 storage and the API's limits. To start a
deployment, see the [README](../README.md).

## Loading data

Loading data is explicit — starting the API never downloads or modifies data.
`ingest` downloads and validates SHA1 and NTLM and, where the folder uses S3,
then publishes both to the bucket. It checks the bucket before starting, so bad
credentials fail in seconds rather than after hours of downloading, and it stops
at the first failure. Validation reads all 1,048,576 range files per format and
writes `complete.json` on success. You can query while it runs; results are just
not yet conclusive, and the API reports completeness per format.

Running `ingest` again refreshes everything: downloads are incremental, but both
formats are published again. To redo a single step, the individual jobs remain:
`download-sha1`, `download-ntlm`, `upload-sha1` and `upload-ntlm`. An upload
refuses to run until that format's download has completed and validated, and
waits if it is still downloading. Uploading with no local data at all fails on a
missing `data/.<format>.lock` file; that means "download first", not a bug in
your S3 setup.

## Following progress

Every data job logs timestamped progress; `ingest` starts with its plan, then
logs each step. Run in the foreground (`docker compose run --rm ...`) it streams
to your terminal. To run a job in the background and follow it:

```sh
id=$(docker compose run -d ingest)
docker logs -f "$id"          # Ctrl-C stops following, not the job
```

`docker compose logs` does not show `run` jobs. If you lose the ID,
`docker compose ps -a` lists them by name for `docker logs -f <name>`; remove
finished ones with `docker rm`.

A download prints the downloader's own `Hash ranges processed: N%` once per
percent, then validation progress. Validation and uploads report every 15
seconds:

```
2026-09-10 12:44:43 upload sha1: 8,192/1,048,576 ranges (0.8%), 0m30s elapsed, about 1h04m left
```

A job waiting for another job's lock, or for the bucket, says so instead of
sitting silent.

## Ingestion details

- Each job removes the old marker, downloads, validates every range, then
  atomically writes `complete.json`. A failure leaves the format incomplete.
- Concurrent jobs for the same format are serialized by a filesystem lock.
  Different formats run independently.
- Downloads are incremental. An interrupted dataset with no index may need `-o`:

  ```sh
  docker compose run --rm download-sha1 sha1 -o
  ```

- An existing dataset needs one validation pass before negative results count as
  conclusive. This reads the whole dataset without downloading it:

  ```sh
  docker compose run --rm --entrypoint /usr/bin/python3 download-sha1 /app/common/manage.py validate sha1
  docker compose run --rm --entrypoint /usr/bin/python3 download-ntlm /app/common/manage.py validate ntlm
  ```

- Always use the supplied ingestion commands. External writers do not take the
  lock. A `sha1.index`/`ntlm.index` alone is **not** a completion marker, and
  missing or corrupt ranges cannot yield a definitive negative. Positive matches
  stay useful while a dataset is incomplete.

## S3 details

Configure in the deployment folder's `.env`. Use HTTPS for remote endpoints.

| Variable | Notes |
| --- | --- |
| `PWNED_S3_BUCKET` | Defaults to `pwned`. Bundled SeaweedFS creates it; with `external-s3`, create it yourself. |
| `PWNED_S3_ENDPOINT` | `split/api-host` and `external-s3` only; AWS uses its default when unset. |
| `PWNED_S3_ACCESS_KEY` / `PWNED_S3_SECRET_KEY` | Set **both**. `external-s3` may leave both unset to use the AWS credential chain (e.g. a container role). |
| `PWNED_S3_REGION` | `external-s3` only. Defaults to `us-east-1`. |

Where the store supports it, grant the API read/list and use separate uploader
credentials with write access. Bundled SeaweedFS has a single identity, so it
cannot. The old `s3/rclone.conf` is unused.

Uploads wait for an accessible bucket, re-validate each range, and write into
`generations/<uuid>/<format-directory>/`. Only after every range succeeds is
`<format-directory>/complete.json` replaced, so a failed upload preserves the
previously published dataset. Readers pick up new publications within five
seconds; range caches expire after 30 seconds and are keyed by generation.
Legacy objects can give positive matches but cannot establish completeness.

Old generations are retained deliberately, for rollback and for in-flight
readers, so storage temporarily holds both datasets. To clean up: stop upload
jobs, find the generations referenced by both completion markers, and delete only
unreferenced generations older than your retention window (at least a minute).
Failed uploads can leave unreferenced generations behind.

## API limits and security

The proxy reads routing from files and has no Docker socket access. The direct
HTTP API stays loopback-only. Private keys and `.env` are gitignored.

Requests are capped at 16 KiB, passwords at 1,024 Unicode code points, formats at
two entries. The API bounds simultaneous requests and body-read time, redacts
validation failures, disables URL access logs (hashes are sensitive), and returns
`Cache-Control: no-store`. `/health` is a cheap liveness check; `/api/info`
reports dataset availability. No match means only that the password was absent
from the available breach dataset — not that it is a strong password.

## CLI certificate verification override

For self-signed API certificates the CLI supports `--insecure` or the exported
`TESTPASSWORD_TLS_INSECURE=true`. The supplied local `.env` enables this; source
it into your shell before running the CLI. `.env.example` keeps verification on.
See the [CLI instructions](../src/client/README.md#self-signed-https-certificates).
This disables certificate/hostname checks but keeps HTTPS encryption. Browser
checks cannot be disabled by a server-side `.env` — browser users must trust the
certificate or use their browser's exception flow.
