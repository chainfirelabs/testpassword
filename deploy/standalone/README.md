# Standalone (no S3)

One host. The dataset lives in `./data` and the API reads it directly. No S3 and
no credentials.

```sh
cp .env.example .env
mkdir -p data                             # must be writable by PWNED_UID:PWNED_GID
docker compose pull
docker compose pull ingest                # downloader image, used by every data job
docker compose up -d                      # UI on https://localhost, API on http://127.0.0.1:8000

id=$(docker compose run -d ingest)        # downloads and validates SHA1 and NTLM
docker logs -f "$id"                      # progress; Ctrl-C stops following, not the job
```

See [Ingestion details](../../docs/operations.md#ingestion-details) for interrupted and
existing downloads, and [Remote HTTPS](../../README.md#3-open-it-to-your-network) to serve
beyond localhost.
