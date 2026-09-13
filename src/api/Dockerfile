# Build context: src/. Pin the builder and runtime to compatible Debian 13/Python 3.13.
FROM python:3.13-slim-trixie@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285 AS build
WORKDIR /build
COPY api/requirements*.txt ./
# Optional CI-only index override; the URL never reaches an image layer.
RUN --mount=type=secret,id=pip_index_url,env=PIP_INDEX_URL \
    --mount=type=secret,id=pip_trusted_host,env=PIP_TRUSTED_HOST \
    pip install --no-cache-dir --target=/install -r requirements.txt

FROM build AS build-s3
RUN --mount=type=secret,id=pip_index_url,env=PIP_INDEX_URL \
    --mount=type=secret,id=pip_trusted_host,env=PIP_TRUSTED_HOST \
    pip install --no-cache-dir --target=/install-s3 -r requirements-s3.txt

FROM gcr.io/distroless/python3-debian13:nonroot@sha256:f3d5ddc6c64a019fe520e7f005f2880be21e6afc461b10a3c15ef2e4edc71e33 AS runtime
COPY api/main.py /app/api/main.py
COPY api/static /app/api/static
COPY common /app/common
WORKDIR /app/api
ENV PYTHONPATH=/app/common:/usr/local/lib/python3.13/dist-packages \
    PYTHONDONTWRITEBYTECODE=1 PWNED_DATA_DIR=/data PWNED_API_HOST=0.0.0.0
EXPOSE 8000
CMD ["main.py"]

FROM runtime AS s3
COPY --from=build-s3 /install-s3 /usr/local/lib/python3.13/dist-packages

# Default builds have no AWS SDK.
FROM runtime AS dir
COPY --from=build /install /usr/local/lib/python3.13/dist-packages
