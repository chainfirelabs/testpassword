#!/bin/sh
# Build and optionally push the TestPassword images.
#
# One script for both CI systems and for local use. It detects GitHub Actions,
# GitLab CI or a local shell and derives the registry, namespace, tags and
# credentials for whichever it finds.
#
#   ci/build.sh                  # build locally, load into the docker daemon
#   ci/build.sh --push           # build and push every image
#   ci/build.sh --push api       # build and push one image
#   ci/build.sh --dry-run --push # print the commands without running them
#
# Anything that reaches the internet (base images, NuGet, PyPI) honours
# HTTP_PROXY / HTTPS_PROXY / NO_PROXY from the environment. They are forwarded
# as predefined build args, so no Dockerfile changes are needed and the values
# are kept out of `docker history`.
#
# On a restricted runner, set PWNED_BUILDKIT_CONFIG to a buildkitd.toml (a
# GitLab File variable works directly) to pull base images through a mirror.
# That needs a docker-container builder, whose own BuildKit image is pulled by
# the docker daemon before any mirror applies -- so PWNED_BUILDKIT_IMAGE must
# name one this runner can already reach. PWNED_MIRROR_REGISTRY/_USER/_PASSWORD
# authenticate to the mirror when it is not public. PWNED_NUGET_SOURCE_URL and
# PWNED_PIP_INDEX_URL point the package installers at internal proxies instead.
#
# POSIX sh on purpose: the docker:*-cli images are Alpine and have no bash, and
# installing one needs network access a restricted runner may not have.
set -eu

usage() {
    sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

PUSH=0
DRY_RUN=0
PLATFORMS=""
SELECTED=""

while [ $# -gt 0 ]; do
    case "$1" in
        --push) PUSH=1 ;;
        --dry-run) DRY_RUN=1 ;;
        --platform|--platforms)
            [ $# -ge 2 ] || { echo "--platform needs a value" >&2; exit 1; }
            PLATFORMS="$2"; shift ;;
        -h|--help) usage 0 ;;
        -*) echo "unknown option: $1" >&2; usage 1 ;;
        *) SELECTED="$SELECTED $1" ;;
    esac
    shift
done

log() { printf '%s\n' "$*" >&2; }

BUILDER_NAME=""
CONTEXT_NAME=""

cleanup() {
    if [ -n "$BUILDER_NAME" ]; then
        docker buildx rm "$BUILDER_NAME" >/dev/null 2>&1 || true
    fi
    if [ -n "$CONTEXT_NAME" ]; then
        docker context rm -f "$CONTEXT_NAME" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT INT TERM

run() {
    if [ "$DRY_RUN" = 1 ]; then
        printf '+' >&2
        for _a in "$@"; do printf ' %s' "$_a" >&2; done
        printf '\n' >&2
    else
        "$@"
    fi
}

# Value of the variable named by $1, empty if unset.
value_of() { eval "printf '%s' \"\${$1:-}\""; }

short_sha() { printf '%s' "$1" | cut -c1-12; }

add_tag() {
    for _t in $TAGS; do
        [ "$_t" = "$1" ] && return 0
    done
    TAGS="$TAGS $1"
}

# --------------------------------------------------------------------------
# Where are we running?
# --------------------------------------------------------------------------
REGISTRY=""; NAMESPACE=""; TAGS=""; LOGIN_USER=""; LOGIN_PASSWORD=""

if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
    CI_KIND=github
    # GHCR rejects uppercase path components; owner/repo may contain them.
    REGISTRY="${PWNED_REGISTRY:-ghcr.io}"
    if [ -n "${PWNED_IMAGE_NAMESPACE:-}" ]; then
        NAMESPACE="$PWNED_IMAGE_NAMESPACE"
    else
        : "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY unset}"
        NAMESPACE=$(printf '%s' "$GITHUB_REPOSITORY" | tr '[:upper:]' '[:lower:]')
    fi
    LOGIN_USER="${GITHUB_ACTOR:-}"
    LOGIN_PASSWORD="${GITHUB_TOKEN:-}"
    if [ "${GITHUB_REF_TYPE:-}" = "tag" ]; then
        add_tag "${GITHUB_REF_NAME}"
    else
        add_tag "$(printf '%s' "${GITHUB_REF_NAME:-dev}" | tr -c 'a-zA-Z0-9._-' '-')"
    fi
    [ -n "${GITHUB_SHA:-}" ] && add_tag "sha-$(short_sha "$GITHUB_SHA")"
    if [ "${GITHUB_REF_NAME:-}" = "${GITHUB_EVENT_REPOSITORY_DEFAULT_BRANCH:-main}" ]; then
        add_tag latest
    fi
elif [ "${GITLAB_CI:-}" = "true" ]; then
    CI_KIND=gitlab
    REGISTRY="${PWNED_REGISTRY:-${CI_REGISTRY:-ghcr.io}}"
    NAMESPACE="${PWNED_IMAGE_NAMESPACE:-${CI_REGISTRY_IMAGE:-}}"
    # CI_REGISTRY_IMAGE is already registry-qualified; strip it to a namespace.
    case "$NAMESPACE" in "$REGISTRY"/*) NAMESPACE="${NAMESPACE#"$REGISTRY"/}" ;; esac
    : "${NAMESPACE:?set PWNED_IMAGE_NAMESPACE or enable the GitLab container registry}"
    LOGIN_USER="${CI_REGISTRY_USER:-}"
    LOGIN_PASSWORD="${CI_REGISTRY_PASSWORD:-}"
    if [ -n "${CI_COMMIT_TAG:-}" ]; then
        add_tag "${CI_COMMIT_TAG}"
    else
        add_tag "${CI_COMMIT_REF_SLUG:-dev}"
    fi
    [ -n "${CI_COMMIT_SHA:-}" ] && add_tag "sha-$(short_sha "$CI_COMMIT_SHA")"
    if [ "${CI_COMMIT_REF_NAME:-}" = "${CI_DEFAULT_BRANCH:-main}" ]; then
        add_tag latest
    fi
else
    CI_KIND=local
    # Mirror the defaults compose uses so a local build produces the same names.
    if [ -f .env ]; then set -a; . ./.env; set +a; fi
    REGISTRY="${PWNED_REGISTRY:-ghcr.io}"
    NAMESPACE="${PWNED_IMAGE_NAMESPACE:-chainfirelabs/testpassword}"
    add_tag "${PWNED_IMAGE_TAG:-latest}"
fi

if [ -n "${PWNED_IMAGE_TAG:-}" ] && [ "$CI_KIND" != local ]; then
    TAGS=" $PWNED_IMAGE_TAG"
fi
TAGS="${TAGS# }"

# --------------------------------------------------------------------------
# What do we build?  name:dockerfile:target
# --------------------------------------------------------------------------
IMAGES="pwned-downloader:database/Dockerfile: pwned-api:api/Dockerfile:dir pwned-api-s3:api/Dockerfile:s3"

matches() {
    [ -z "$SELECTED" ] && return 0
    for _want in $SELECTED; do
        if [ "$_want" = "$1" ] || [ "pwned-$_want" = "$1" ]; then
            return 0
        fi
    done
    return 1
}

if [ -z "$PLATFORMS" ]; then
    # Multi-arch requires a push; a local build must load a single arch.
    if [ "$PUSH" = 1 ]; then
        PLATFORMS="${PWNED_BUILD_PLATFORMS:-linux/amd64,linux/arm64}"
    else
        PLATFORMS="${PWNED_BUILD_PLATFORMS:-linux/amd64}"
    fi
fi

# Different consumers disagree about proxy-variable casing. In particular,
# NuGet uses the lowercase names on Linux, while CI settings are commonly
# supplied in uppercase. Populate a missing spelling from its counterpart and
# pass both spellings to BuildKit and build steps.
normalize_proxy_pair() {
    _upper="$1"; _lower="$2"
    _upper_value=$(value_of "$_upper")
    _lower_value=$(value_of "$_lower")
    if [ -z "$_upper_value" ] && [ -n "$_lower_value" ]; then
        export "${_upper}=${_lower_value}"
    elif [ -z "$_lower_value" ] && [ -n "$_upper_value" ]; then
        export "${_lower}=${_upper_value}"
    fi
}

normalize_proxy_pair HTTP_PROXY http_proxy
normalize_proxy_pair HTTPS_PROXY https_proxy
normalize_proxy_pair NO_PROXY no_proxy

PROXY_VARS="HTTP_PROXY HTTPS_PROXY NO_PROXY http_proxy https_proxy no_proxy"
proxy_summary=""
for v in $PROXY_VARS; do
    [ -n "$(value_of "$v")" ] && proxy_summary="$proxy_summary $v"
done

log "ci/build.sh: ${CI_KIND} -> ${REGISTRY}/${NAMESPACE}"
log "  tags:      ${TAGS}"
log "  platforms: ${PLATFORMS}"
log "  proxy:     ${proxy_summary:-none}"
[ -n "${PWNED_PIP_INDEX_URL:-}" ] && log "  pip index: overridden"
[ -n "${PWNED_NUGET_SOURCE_URL:-}" ] && log "  nuget source: overridden"

if [ "$PUSH" = 1 ] && [ -n "$LOGIN_PASSWORD" ]; then
    log "  login:     ${LOGIN_USER}@${REGISTRY}"
    if [ "$DRY_RUN" = 1 ]; then
        log "+ docker login $REGISTRY -u $LOGIN_USER --password-stdin"
    else
        printf '%s' "$LOGIN_PASSWORD" | docker login "$REGISTRY" -u "$LOGIN_USER" --password-stdin
    fi
fi

# Create a docker-container builder when a BuildKit config is supplied. Without
# one the default builder is used and nothing here runs.
setup_builder() {
    _cfg="${PWNED_BUILDKIT_CONFIG:-}"
    [ -n "$_cfg" ] || return 0
    if [ ! -f "$_cfg" ]; then
        log "error: PWNED_BUILDKIT_CONFIG is not a file: $_cfg"
        exit 1
    fi
    : "${PWNED_BUILDKIT_IMAGE:?set PWNED_BUILDKIT_IMAGE to a BuildKit image this runner can pull}"

    if [ -n "${PWNED_MIRROR_USER:-}" ] || [ -n "${PWNED_MIRROR_PASSWORD:-}" ]; then
        : "${PWNED_MIRROR_REGISTRY:?set PWNED_MIRROR_REGISTRY alongside the mirror credentials}"
        : "${PWNED_MIRROR_USER:?set both mirror credentials}"
        : "${PWNED_MIRROR_PASSWORD:?set both mirror credentials}"
        log "  mirror:    ${PWNED_MIRROR_USER}@${PWNED_MIRROR_REGISTRY}"
        printf '%s' "$PWNED_MIRROR_PASSWORD" | docker login "$PWNED_MIRROR_REGISTRY" \
            --username "$PWNED_MIRROR_USER" --password-stdin
    fi

    if [ -n "${DOCKER_HOST:-}" ] && \
       { [ -n "${DOCKER_TLS_VERIFY:-}" ] || [ -n "${DOCKER_CERT_PATH:-}" ]; }; then
        # buildx cannot build a container builder from TLS supplied only through
        # the environment; capture the same endpoint as a named context instead.
        CONTEXT_NAME="pwned-tls-$$"
        run docker context create "$CONTEXT_NAME"
    fi

    BUILDER_NAME="pwned-$$"
    log "  builder:   ${BUILDER_NAME} on ${PWNED_BUILDKIT_IMAGE}"
    set -- --name "$BUILDER_NAME" --driver docker-container \
        --driver-opt "image=${PWNED_BUILDKIT_IMAGE}" \
        --buildkitd-config "$_cfg"
    for _v in $PROXY_VARS; do
        _val=$(value_of "$_v")
        # buildx parses --driver-opt as CSV, so a value containing commas
        # (NO_PROXY always does) must be quoted or it is split into fields.
        [ -n "$_val" ] && set -- "$@" --driver-opt "\"env.${_v}=${_val}\""
    done
    set -- "$@" --bootstrap
    [ -n "$CONTEXT_NAME" ] && set -- "$@" "$CONTEXT_NAME"
    run docker buildx create "$@"
}

BUILDX=0
if docker buildx version >/dev/null 2>&1; then
    BUILDX=1
elif [ "$PUSH" = 1 ] || [ "${PLATFORMS#*,}" != "$PLATFORMS" ]; then
    log "error: docker buildx is required for multi-platform builds and pushes"
    exit 1
fi

# Provenance/SBOM attestations add manifests that some registries reject.
BUILDX_NO_DEFAULT_ATTESTATIONS=1
export BUILDX_NO_DEFAULT_ATTESTATIONS

setup_builder

build_one() {
    _name="$1"; _dockerfile="$2"; _target="$3"

    set -- build
    [ -n "$BUILDER_NAME" ] && set -- "$@" --builder "$BUILDER_NAME"
    set -- "$@" --file "src/${_dockerfile}" --pull
    [ -n "$_target" ] && set -- "$@" --target "$_target"
    [ "$BUILDX" = 1 ] && set -- "$@" --platform "$PLATFORMS"
    for _tag in $TAGS; do
        set -- "$@" --tag "${REGISTRY}/${NAMESPACE}/${_name}:${_tag}"
    done
    for _v in $PROXY_VARS; do
        _val=$(value_of "$_v")
        [ -n "$_val" ] && set -- "$@" --build-arg "${_v}=${_val}"
    done
    # Passed by reference, so the index URL never appears in argv, an image
    # layer or `docker history`. Ignored by images that mount no such secret.
    if [ -n "${PWNED_PIP_INDEX_URL:-}" ]; then
        set -- "$@" --secret id=pip_index_url,env=PWNED_PIP_INDEX_URL
        if [ -n "${PWNED_PIP_TRUSTED_HOST:-}" ]; then
            set -- "$@" --secret id=pip_trusted_host,env=PWNED_PIP_TRUSTED_HOST
        fi
    fi
    # The downloader Dockerfile consumes this as an ephemeral environment
    # secret. Other images safely ignore it.
    if [ -n "${PWNED_NUGET_SOURCE_URL:-}" ]; then
        set -- "$@" --secret id=nuget_source_url,env=PWNED_NUGET_SOURCE_URL
    fi
    if [ "$BUILDX" = 1 ]; then
        if [ "$PUSH" = 1 ]; then set -- "$@" --push; else set -- "$@" --load; fi
    fi
    set -- "$@" src

    if [ "$BUILDX" = 1 ]; then
        run docker buildx "$@"
    else
        run docker "$@"
        if [ "$PUSH" = 1 ]; then
            for _tag in $TAGS; do
                run docker push "${REGISTRY}/${NAMESPACE}/${_name}:${_tag}"
            done
        fi
    fi
}

built=0
for entry in $IMAGES; do
    name="${entry%%:*}"
    rest="${entry#*:}"
    dockerfile="${rest%%:*}"
    target="${rest#*:}"
    matches "$name" || continue
    built=$((built + 1))
    log "==> ${name}"
    build_one "$name" "$dockerfile" "$target"
done

if [ "$built" -eq 0 ]; then
    log "error: no images matched:${SELECTED}"
    exit 1
fi
log "built ${built} image(s)"
