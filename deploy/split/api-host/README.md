# Split: API host

Serves the web UI and API from the data host's bucket. It holds no dataset and
no storage. Pair with [`../data-host`](../data-host/), or point it at any S3
bucket you provide.

```sh
cp .env.example .env      # set PWNED_S3_ENDPOINT and the data host's S3 keys
docker compose pull
docker compose up -d      # UI on https://localhost, API on http://127.0.0.1:8000
```

`PWNED_S3_ENDPOINT` is the data host's Traefik address, e.g.
`https://data.example.com:8333`. The name must match its certificate.

If the data host uses a self-signed certificate, copy its
`proxy/certs/fullchain.pem` here as `s3-ca.pem` with mode 644 (the API runs as
UID 65532). Then uncomment the `AWS_CA_BUNDLE` line and the `volumes` block in
`compose.yaml`.

Two behaviours to plan around:

- `/health` is process liveness only and does not probe S3, so the proxy will
  route to an API that cannot reach the bucket. `/api/info` reflects real
  dataset state — monitor that instead.
- Every uncached range lookup is a synchronous S3 GET to the data host (cached
  30s). With 1,048,576 prefixes the miss rate stays high, so keep the two hosts
  close on the network.

To serve beyond localhost, see [Remote HTTPS](../../../README.md#3-open-it-to-your-network).
