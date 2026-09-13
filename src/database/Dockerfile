# Build context: src/. The downloader tool publishes Native AOT per architecture.
FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:4beef5b8919dcaa2dc924233bd069257e883cc7a061e09088a97d152d6a48510 AS build
ARG TARGETARCH
ARG DOWNLOADER_VERSION=0.5.2608.1930
RUN --mount=type=secret,id=nuget_source_url,env=NUGET_SOURCE_URL \
    case "$TARGETARCH" in amd64) RID=linux-x64 ;; arm64) RID=linux-arm64 ;; *) exit 1 ;; esac \
    && if [ -n "${NUGET_SOURCE_URL:-}" ]; then \
        printf '%s\n' '<configuration><packageSources><clear /></packageSources></configuration>' > /tmp/nuget.config \
        && dotnet nuget add source "$NUGET_SOURCE_URL" --name ci-proxy --configfile /tmp/nuget.config \
        && NUGET_CONFIG_ARGS="--configfile /tmp/nuget.config"; \
    else NUGET_CONFIG_ARGS=; fi \
    && dotnet tool install --global haveibeenpwned-downloader --version "$DOWNLOADER_VERSION" $NUGET_CONFIG_ARGS \
    && rm -f /tmp/nuget.config \
    && mkdir /out \
    && EXE=$(find /root/.dotnet/tools/.store -path "*$RID*" -name haveibeenpwned-downloader -type f -print -quit) \
    && test -n "$EXE" && cp "$EXE" /out/haveibeenpwned-downloader \
    && chmod 755 /out/haveibeenpwned-downloader

# The ingest job also publishes to S3: install the API image's pinned S3 client,
# without the API. Keep this builder ABI-compatible with the runtime below.
FROM python:3.13-slim-trixie@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285 AS s3-packages
COPY api/requirements-s3.txt /tmp/
RUN --mount=type=secret,id=pip_index_url,env=PIP_INDEX_URL \
    --mount=type=secret,id=pip_trusted_host,env=PIP_TRUSTED_HOST \
    grep -v '^-r' /tmp/requirements-s3.txt > /tmp/s3.txt \
    && pip install --no-cache-dir --target=/install -r /tmp/s3.txt

FROM gcr.io/distroless/python3-debian13:nonroot@sha256:f3d5ddc6c64a019fe520e7f005f2880be21e6afc461b10a3c15ef2e4edc71e33
COPY --from=build /out/haveibeenpwned-downloader /usr/local/bin/haveibeenpwned-downloader
# The downloader is BSD-3-Clause: a binary redistribution must carry its notice.
COPY database/THIRD-PARTY-NOTICES /usr/local/share/licenses/haveibeenpwned-downloader/LICENSE
COPY --from=s3-packages /install /usr/local/lib/python3.13/dist-packages
COPY common /app/common
USER 1000:1000
WORKDIR /data
ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1 PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/usr/local/lib/python3.13/dist-packages
ENTRYPOINT ["/usr/bin/python3", "/app/common/manage.py", "download"]
CMD ["sha1"]
