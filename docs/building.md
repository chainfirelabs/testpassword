# Building the images

For deploying, see the [README](../README.md). This covers building and
publishing the images, and developing locally.

## Image names

Compose only ever **pulls**; it never builds. Three images come from this repo —
`pwned-downloader`, `pwned-api` and `pwned-api-s3` — and are addressed as
`$PWNED_REGISTRY/$PWNED_IMAGE_NAMESPACE/<name>:$PWNED_IMAGE_TAG`:

| Variable | Default |
| --- | --- |
| `PWNED_REGISTRY` | `ghcr.io` |
| `PWNED_IMAGE_NAMESPACE` | `chainfirelabs/testpassword` |
| `PWNED_IMAGE_TAG` | `latest` |

Point these at any registry — GitLab, ECR, Harbor, a mirror — by setting them in
`.env`. Pin `PWNED_IMAGE_TAG` to a release tag or a `sha-<commit>` tag in
production; `latest` moves under you.

## ci/build.sh

Build them with `ci/build.sh`, which is the single entry point for local builds,
GitLab CI and GitHub Actions. It detects where it is running and derives the
registry, namespace, tags and credentials from that. It is POSIX sh with no
dependencies beyond the docker CLI, so it runs as-is in the Alpine-based
`docker:*-cli` images without installing anything:

```sh
ci/build.sh                    # build locally, load into the docker daemon
ci/build.sh --push             # build and push all three
ci/build.sh --push api         # just one
ci/build.sh --dry-run --push   # print the commands without running them
```

| | GitHub Actions | GitLab CI | Local |
| --- | --- | --- | --- |
| Registry | `ghcr.io` | `$CI_REGISTRY` | `$PWNED_REGISTRY` |
| Namespace | `$GITHUB_REPOSITORY`, lowercased | `$CI_REGISTRY_IMAGE` | `$PWNED_IMAGE_NAMESPACE` |
| Tags | ref name, `sha-<12>`, `latest` on default branch | same | `$PWNED_IMAGE_TAG` |
| Credentials | `$GITHUB_TOKEN` | `$CI_REGISTRY_USER` / `$CI_REGISTRY_PASSWORD` | your `docker login` |

`PWNED_REGISTRY`, `PWNED_IMAGE_NAMESPACE` and `PWNED_IMAGE_TAG` override the
detected values everywhere, so CI can publish somewhere other than its own
registry without editing the pipeline. Local builds read them from the `.env` at
the repository root.

Both pipelines build all three images on every merge request / pull request and
publish only from the default branch and version tags.

## Building behind a proxy

Every network fetch in a build — base images, NuGet for the downloader, PyPI for
the API — honours `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY`. `ci/build.sh`
forwards them as predefined build args, so no Dockerfile declares them and the
values stay out of `docker history`. It also supplies the equivalent lowercase
variables (`http_proxy`, `https_proxy`, and `no_proxy`) because NuGet on Linux
uses that spelling. Either spelling may be provided by the runner.

`.gitlab-ci.yml` applies the proxy to the job and to the `docker:dind` service
that pulls base images. Set `HTTP_PROXY`/`HTTPS_PROXY` as project CI/CD
variables, and extend the `NO_PROXY` default rather than replacing it — it lists
`docker`, which must stay direct or the daemon becomes unreachable.

Multi-arch adds a third place. Setting `PWNED_BUILD_PLATFORMS` to more than one
platform switches the job to a `docker-container` builder, which is a separate
container that needs the proxy passed to it explicitly. The `before_script`
handles that, including CSV-quoting the values — buildx splits `--driver-opt` on
commas, so an unquoted `NO_PROXY` fails with `invalid value ..., expecting k=v`.
`.github/workflows/build.yml` reads the same names from repository variables and
skips the proxy entirely when they are unset.

For a normal forward proxy such as Squid, set only those proxy variables. Do
not set `PWNED_PIP_INDEX_URL` or `PWNED_NUGET_SOURCE_URL` to the Squid address:
those variables select package repositories and are only for PyPI/NuGet-aware
services such as Artifactory or Nexus. Store an authenticated proxy URL as a
masked CI/CD variable or GitHub Actions secret.

## Pulling base images through a registry mirror

Builds pull from three registries — `docker.io` (`python:3.13-slim-trixie`),
`gcr.io` (distroless) and `mcr.microsoft.com` (the .NET SDK that compiles the
downloader). On a runner without direct internet access, mirror all three.

| Variable | Purpose |
| --- | --- |
| `PWNED_BUILDKIT_CONFIG` | Path to a `buildkitd.toml`. A GitLab **File** variable works directly. |
| `PWNED_BUILDKIT_IMAGE` | BuildKit image for the builder. Required with the above. |
| `PWNED_MIRROR_REGISTRY` | Mirror host, if it needs authentication. |
| `PWNED_MIRROR_USER` / `PWNED_MIRROR_PASSWORD` | Mirror credentials. Set both or neither. |

The config itself:

```toml
[registry."docker.io"]
  mirrors = ["harbor.example.com/docker"]

[registry."gcr.io"]
  mirrors = ["harbor.example.com/gcr"]

[registry."mcr.microsoft.com"]
  mirrors = ["harbor.example.com/mcr"]
```

**`PWNED_BUILDKIT_IMAGE` is not optional here.** A BuildKit config needs a
`docker-container` builder, and that builder runs a BuildKit image which the
docker daemon pulls *before* any mirror in the config can apply. Left at the
default it is fetched from Docker Hub, which is exactly what a restricted runner
cannot reach — so point it at a copy you can already pull, e.g.
`harbor.example.com/docker/moby/buildkit:v0.17.2`. The same applies to the
`docker:*-dind` service image and, for multi-arch, `tonistiigi/binfmt`: those are
pulled by the runner and the daemon, so they need mirroring at that level rather
than here.

Three more things to get right:

- Mirror **every** registry in the list. Omitting one leaves that build reaching
  the internet directly, and only the downloader image fails.
- Add the mirror host to `NO_PROXY`, or BuildKit will try to reach an internal
  registry through the proxy.
- `ca`, `insecure` and `http` for an untrusted mirror certificate belong in the
  mirror's own `[registry."harbor.example.com"]` section; credentials come from
  `PWNED_MIRROR_*`, not from the file.

## Installing packages from an internal index

Mirroring base images does not help the `pip install` steps in the API build and
the downloader build (which adds the S3 client for `ingest`); they reach PyPI.
Point them elsewhere with:

| Variable | Purpose |
| --- | --- |
| `PWNED_PIP_INDEX_URL` | Full simple-index URL, e.g. `https://packages.example.com/pypi/+simple/` |
| `PWNED_PIP_TRUSTED_HOST` | Optional host to trust for a plain-HTTP or self-signed index |

Both are passed to BuildKit as **secrets**, not build args, and mounted as
`PIP_INDEX_URL` / `PIP_TRUSTED_HOST` for the single `RUN` that needs them. The
value never appears in argv, an image layer or `docker history`, so an index URL
carrying a token stays out of the published image. `PWNED_PIP_TRUSTED_HOST` on
its own is ignored; set it alongside the index URL.

The downloader image runs `dotnet tool install`. Set
`PWNED_NUGET_SOURCE_URL` to an internal NuGet v3 feed or repository proxy when
the runner cannot reach nuget.org. The build uses that source exclusively, so
the public feed is not contacted. Like the pip index, the URL is passed as a
BuildKit secret and may contain credentials without being saved in the image.
In GitHub Actions, store credential-bearing URLs as repository secrets; plain
URLs may be repository variables. GitLab CI/CD variables are inherited by the
job automatically.

The GitLab job waits for the dind daemon before doing anything. The service
writes its TLS material into the shared `/certs` volume only after it starts, so
a job that gets there quickly can find `/certs/client/ca.pem` missing and fail
with `unable to resolve docker endpoint`. That is a startup race and looks
intermittent; the wait removes it.

`ci/build.sh` owns all of this for both CI systems: it authenticates to the
mirror, creates the builder, and removes both the builder and its context on
exit. On a dind runner with TLS it first creates a docker context, because buildx
will not build a container builder from `DOCKER_HOST` plus TLS environment
variables alone. With `PWNED_BUILDKIT_CONFIG` unset none of that runs and the
default builder is used.

Digest pinning and mirroring compose cleanly: the pinned `@sha256:` is verified
after the pull regardless of which host served it, so a mirror cannot alter what
you build.

## Development and verification

```sh
ci/build.sh                    # build the images locally

python3 -m pip install -r src/api/requirements.txt httpx
python3 src/api/main.py
# S3 development additionally installs requirements-s3.txt.

python3 -m unittest discover -s tests -v
node tests/test_web.cjs
(cd src/client && go test ./... && go vet ./...)

# Requires the built S3 image; starts disposable storage with no host ports:
python3 tests/integration_s3.py
python3 tests/integration_http.py
```

Python dependencies and base images are pinned — upgrade deliberately, rebuild
all targets, and rerun tests and your dependency/image scanners. The Python
builder and runtime must stay ABI-compatible. The downloader build selects the
Native AOT artifact for amd64 or arm64 and fails if unavailable; other
architectures are unsupported.

Custom API, S3 ingestion and downloader images use nonroot distroless Python 3.13
runtimes. The downloader runs its pinned Native AOT binary under a small Python
supervisor that locks, validates and marks completed downloads.
