# Pwned Passwords Downloader

Build from the repository root with `ci/build.sh downloader`.
The custom runtime is nonroot distroless Python on Debian 13. A Python supervisor
runs the pinned Native AOT downloader, serializes ingestion using a filesystem
lock, and validates every range before atomically publishing a completion marker.
The image also carries the pinned S3 client, so the deployments' `ingest` job
can download, validate and publish both formats from one container.

```sh
docker compose run --rm download-sha1
docker compose run --rm download-ntlm
# Pass downloader options after the format; single-file mode is unsupported.
docker compose run --rm download-sha1 sha1 -o
```

The data directory must be writable by `PWNED_UID:PWNED_GID` (default 1000:1000).
Each format contains 1,048,576 prefix files plus its downloader index and a
validated `complete.json`. Budget for tens of GB and millions of filesystem
entries. Existing data can be validated without downloading; see the root
[README](../../README.md) for migration, optional S3 publication and deployment.

Unlike the previous image, the default entrypoint takes `sha1` or `ntlm`, not
an output directory. Override the entrypoint with
`/usr/local/bin/haveibeenpwned-downloader` only to inspect upstream help/version;
direct downloads bypass the completion-marker workflow.
