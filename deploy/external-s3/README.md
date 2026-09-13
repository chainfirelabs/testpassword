# External S3

One host that downloads the dataset, publishes it to an S3 bucket **you
provide** (AWS or any S3-compatible store), and serves the API from it. Nothing
here runs storage: creating, securing and paying for the bucket is up to you.

1. Create the bucket.
2. Copy `.env.example` to `.env` and set `PWNED_S3_BUCKET`. For a non-AWS store,
   also set `PWNED_S3_ENDPOINT` to its HTTPS URL. Set both keys, or leave both
   unset to use the AWS credential chain.
3. Start it and load the data:

```sh
mkdir -p data                             # must be writable by PWNED_UID:PWNED_GID
docker compose pull
docker compose pull ingest
docker compose up -d                      # API and proxy

id=$(docker compose run -d ingest)        # download both formats, then publish both
docker logs -f "$id"                      # progress; takes a few hours
```

This host both uploads and serves, so its keys need write access. To serve from
a separate machine with read-only keys, run
[`../split/api-host`](../split/api-host/) there against the same bucket.

A store with a private-CA certificate needs the same `AWS_CA_BUNDLE` and
`s3-ca.pem` mount as `split/api-host`, added to `x-s3` and to each service that
uses it.

See [Ingestion details](../../docs/operations.md#ingestion-details),
[S3 details](../../docs/operations.md#s3-details) and
[Remote HTTPS](../../README.md#3-open-it-to-your-network).
