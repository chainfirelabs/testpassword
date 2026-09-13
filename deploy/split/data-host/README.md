# Split: data host

Downloads the dataset, stores it in the bundled SeaweedFS, and exposes S3 to the
API host through Traefik over HTTPS on port 8333. SeaweedFS itself speaks plain
HTTP on the Compose network only. Uploads from this host go straight to it, and
Traefik is the only thing published. Pair with [`../api-host`](../api-host/).

## Certificate

Traefik needs a certificate for the name the API host puts in its
`PWNED_S3_ENDPOINT`. Without one it serves its built-in certificate, which the
API host rejects.

1. Put `fullchain.pem` and `privkey.pem` in `proxy/certs/`, readable by UID 65532.
2. Copy `proxy/tls.yaml.example` to `proxy/dynamic/tls.yaml`.

A self-signed certificate works if the API host trusts it:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 825 \
  -subj /CN=data.example.com -addext "subjectAltName=DNS:data.example.com" \
  -keyout proxy/certs/privkey.pem -out proxy/certs/fullchain.pem
sudo chown 65532 proxy/certs/privkey.pem
cp proxy/tls.yaml.example proxy/dynamic/tls.yaml
```

Then copy `proxy/certs/fullchain.pem`, and never `privkey.pem`, to the API host
as `s3-ca.pem`.

## Run

```sh
cp .env.example .env                      # then set the two keys
mkdir -p data                             # must be writable by PWNED_UID:PWNED_GID
docker compose pull
docker compose pull ingest
docker compose up -d                      # SeaweedFS, bucket setup, Traefik

id=$(docker compose run -d ingest)        # download both formats, then publish both
docker logs -f "$id"                      # progress; takes a few hours
```

## Security

- The S3 port listens on every interface (`PWNED_S3_BIND`, `PWNED_S3_PORT`).
  Firewall it to the API host.
- SeaweedFS has a single admin identity, so the API host holds the same
  read-write keys as this host. If that is unacceptable, use a store that can
  issue a read-only key, and deploy [`../../external-s3`](../../external-s3/)
  with [`../api-host`](../api-host/) instead.

Generation cleanup (see [S3 details](../../../docs/operations.md#s3-details)) runs from
here.
