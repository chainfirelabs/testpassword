# Standalone with S3

One host running the bundled SeaweedFS. SeaweedFS speaks plain HTTP on the
Compose network only: no S3 port is published, and nothing off this host can
reach it.

Set `PWNED_S3_ACCESS_KEY` and `PWNED_S3_SECRET_KEY` in `.env` first. The same
keys configure SeaweedFS and its clients.

```sh
cp .env.example .env                      # then set the two keys
mkdir -p data                             # must be writable by PWNED_UID:PWNED_GID
docker compose pull
docker compose pull ingest
docker compose up -d                      # SeaweedFS, bucket setup, API, proxy

id=$(docker compose run -d ingest)        # download both formats, then publish both
docker logs -f "$id"                      # progress; takes a few hours
```

A readiness job authenticates and creates the bucket if needed; the API,
`ingest` and uploads wait for it. See [Ingestion details](../../docs/operations.md#ingestion-details),
[S3 details](../../docs/operations.md#s3-details) and
[Remote HTTPS](../../README.md#3-open-it-to-your-network).
