#!/usr/bin/env python3
"""Pwned-password lookup API over the HIBP pwned-password dataset.

Data can be served from a local directory (default) or an S3-compatible
object store (e.g. SeaweedFS); the object keys mirror the directory layout:

    <root>/pwnedpasswords/<PREFIX5>.txt        SHA1: lines "<SUFFIX35>:<COUNT>"
    <root>/pwnedpasswords_ntlm/<PREFIX5>.txt   NTLM: lines "<SUFFIX27>:<COUNT>"

A file's name is the first 5 hex chars of the full hash; each line holds the
remaining 35 (SHA1) or 27 (NTLM) hex chars plus an occurrence count. So the
full hash is ``<PREFIX5> + <SUFFIX>`` and a lookup only ever touches the one
prefix file that can contain it.

Endpoints:
    GET  /health
    GET  /lookup/{sha1|ntlm}/{hash}
    POST /check   {"password": "...", "formats": ["sha1", "ntlm"]}

``/check`` hashes the plaintext server-side (SHA1 = SHA1(UTF-8), NTLM =
MD4(UTF-16LE)) so the client only ever sends a hash or the plaintext to a
trusted local service.

Run:  uvicorn main:app --host 127.0.0.1 --port 8000
      (or: python3 main.py)

Environment:
    PWNED_SOURCE        data source: 'dir' (default) or 's3'
    PWNED_DATA_DIR      data root for 'dir' (default: ../../data)
    PWNED_CACHE_SIZE    LRU size for loaded prefix files (default: 512)
    PWNED_S3_ENDPOINT   S3 endpoint URL for 's3' (e.g. http://seaweedfs:8333)
    PWNED_S3_BUCKET     S3 bucket for 's3'
    PWNED_S3_ACCESS_KEY S3 access key id for 's3'
    PWNED_S3_SECRET_KEY S3 secret access key for 's3'
    PWNED_S3_REGION     S3 region for 's3' (default: us-east-1)
    PWNED_API_HOST      host for ``python3 main.py`` (default: 127.0.0.1)
    PWNED_API_PORT      port  for ``python3 main.py`` (default: 8000)
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import threading
import sys
from collections import OrderedDict
import hashlib
import os
import re
import struct
from functools import lru_cache
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator
from fastapi.exceptions import RequestValidationError
from starlette.responses import JSONResponse
from starlette.responses import FileResponse

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))
from dataset import FORMATS, MARKER, MAX_RANGE_BYTES, local_marker, parse_range, signature, valid_marker
from manage import s3_client

DEFAULT_DATA_DIR = Path(__file__).resolve().parents[2] / "data"
DATA_DIR = Path(os.environ.get("PWNED_DATA_DIR", str(DEFAULT_DATA_DIR)))
CACHE_SIZE = int(os.environ.get("PWNED_CACHE_SIZE", "512"))
if not 0 <= CACHE_SIZE <= 4096:
    raise RuntimeError("PWNED_CACHE_SIZE must be between 0 and 4096")
STATIC_DIR = Path(__file__).resolve().parent / "static"

HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")

# --- S3 access logging: visible via `docker logs -f testpassword-api-1` ---
_s3_log = logging.getLogger("pwned.s3")
if not _s3_log.handlers:
    _h = logging.StreamHandler(sys.stderr)
    _h.setFormatter(logging.Formatter("%(asctime)s  S3 %(message)s", "%Y-%m-%d %H:%M:%S"))
    _s3_log.addHandler(_h)
_s3_log.setLevel(logging.INFO)
_s3_log.propagate = False

app = FastAPI(
    title="Pwned Password Lookup",
    version="1.0",
    description="Offline lookup of SHA1 / NTLM hashes against the HIBP pwned-password dataset.",
)


@app.exception_handler(RequestValidationError)
async def invalid_request(request, exc):
    return JSONResponse({"detail": "Invalid request"}, status_code=422)


class RequestLimits:
    def __init__(self, app):
        self.app = app
        self.active = 0

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        if self.active >= 32:
            return await JSONResponse({"detail": "Server busy"}, status_code=503)(scope, receive, send)
        self.active += 1
        try:
            body = bytearray()
            deadline = time.monotonic() + 10
            while True:
                try:
                    message = await asyncio.wait_for(receive(), timeout=max(0, deadline - time.monotonic()))
                except asyncio.TimeoutError:
                    return await JSONResponse({"detail": "Request timeout"}, status_code=408)(scope, receive, send)
                if message["type"] == "http.disconnect":
                    return
                body.extend(message.get("body", b""))
                if len(body) > 16384:
                    return await JSONResponse({"detail": "Request too large"}, status_code=413)(scope, receive, send)
                if not message.get("more_body"):
                    break
            async def bounded_receive():
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            async def private_send(message):
                if message["type"] == "http.response.start":
                    message["headers"] = list(message.get("headers", [])) + [
                        (b"cache-control", b"no-store"),
                        (b"referrer-policy", b"no-referrer"),
                        (b"x-content-type-options", b"nosniff"),
                        (b"content-security-policy", b"default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")]
                await send(message)
            await self.app(scope, bounded_receive, private_send)
        finally:
            self.active -= 1


app.add_middleware(RequestLimits)


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def md4(data: bytes) -> bytes:
    """Pure-Python MD4 (RFC 1320). hashlib dropped MD4 under OpenSSL 3.

    NTLM = MD4 of the UTF-16LE encoding of the password.
    Validated against the RFC 1320 test vectors and NTLM("password") =
    8846F7EAEE8FB117AD06BDD830B7586C.
    """
    ml = len(data)
    data += b"\x80" + b"\x00" * ((55 - ml) % 64) + struct.pack("<Q", ml << 3)

    def rotl(x: int, c: int) -> int:
        return ((x << c) | (x >> (32 - c))) & 0xFFFFFFFF

    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    r1k = list(range(16))
    r1s = (3, 7, 11, 19)
    r2k = (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15)
    r2s = (3, 5, 9, 13)
    r3k = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)
    r3s = (3, 9, 11, 15)

    for off in range(0, len(data), 64):
        x = struct.unpack("<16I", data[off : off + 64])
        a0, b0, c0, d0 = a, b, c, d
        for i in range(16):  # round 1: F
            f = (b & c) | ((~b) & d)
            t = (a + f + x[r1k[i]]) & 0xFFFFFFFF
            a, b, c, d = d, rotl(t, r1s[i & 3]), b, c
        for i in range(16):  # round 2: G
            g = (b & c) | (b & d) | (c & d)
            t = (a + g + x[r2k[i]] + 0x5A827999) & 0xFFFFFFFF
            a, b, c, d = d, rotl(t, r2s[i & 3]), b, c
        for i in range(16):  # round 3: H
            h = b ^ c ^ d
            t = (a + h + x[r3k[i]] + 0x6ED9EBA1) & 0xFFFFFFFF
            a, b, c, d = d, rotl(t, r3s[i & 3]), b, c
        a = (a + a0) & 0xFFFFFFFF
        b = (b + b0) & 0xFFFFFFFF
        c = (c + c0) & 0xFFFFFFFF
        d = (d + d0) & 0xFFFFFFFF
    return struct.pack("<4I", a, b, c, d)


def hash_password(pw: str, fmt: str) -> str:
    if fmt == "sha1":
        return hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
    return md4(pw.encode("utf-16-le")).hex().upper()


# ---------------------------------------------------------------------------
# Data access
# ---------------------------------------------------------------------------

class DataBackend:
    """Interface for a pwned-password data source."""

    source = "dir"

    def describe(self) -> str:
        raise NotImplementedError

    def data_state(self, fmt: str) -> tuple[bool, bool]:
        raise NotImplementedError

    def load_prefix(self, fmt: str, prefix: str) -> dict[str, int]:
        raise NotImplementedError


class DirBackend(DataBackend):
    source = "dir"

    def __init__(self, root: Path):
        self.root = root
        self._load_cached = lru_cache(maxsize=CACHE_SIZE)(self._load_cached)

    def describe(self):
        return str(self.root)

    def _dir(self, fmt):
        return self.root / FORMATS[fmt][0]

    def data_state(self, fmt):
        directory = self._dir(fmt)
        return directory.is_dir(), local_marker(directory, fmt) is not None

    def load_prefix(self, fmt, prefix):
        path = self._dir(fmt) / (prefix + ".txt")
        try:
            version = tuple(signature(path))
            mapping = self._load_cached(fmt, prefix, version)
            if tuple(signature(path)) != version:
                raise ValueError("range changed during read")
            return mapping
        except FileNotFoundError:
            return None

    def _load_cached(self, fmt, prefix, version):
        with (self._dir(fmt) / (prefix + ".txt")).open("rb") as stream:
            body = stream.read(MAX_RANGE_BYTES + 1)
        return parse_range(body, fmt)


class TTLCache:
    """Bounded cache with monotonic expiry; failures are never stored."""
    def __init__(self, size, ttl):
        self.size, self.ttl = size, ttl
        self.items = OrderedDict()
        self.lock = threading.Lock()

    def get(self, key, loader):
        with self.lock:
            entry = self.items.get(key)
            if entry and time.monotonic() < entry[0]:
                self.items.move_to_end(key)
                return entry[1]
        value = loader()
        with self.lock:
            if self.size:
                self.items[key] = (time.monotonic() + self.ttl, value)
                self.items.move_to_end(key)
                while len(self.items) > self.size:
                    self.items.popitem(last=False)
        return value


class S3Backend(DataBackend):
    source = "s3"

    def __init__(self, client, bucket, client_error):
        self.s3, self.bucket, self._client_error = client, bucket, client_error
        self.states = TTLCache(2, 5)
        self.ranges = TTLCache(CACHE_SIZE, 30)

    def describe(self):
        return f"s3://{self.bucket}"

    def _body(self, key, limit):
        _s3_log.info("GET %s", key)
        try:
            response = self.s3.get_object(Bucket=self.bucket, Key=key)
        except self._client_error as exc:
            if exc.response.get("Error", {}).get("Code") in ("NoSuchKey", "404"):
                return None
            raise
        stream = response["Body"]
        try:
            body = stream.read(limit + 1)
        finally:
            stream.close()
        if len(body) > limit:
            raise ValueError("oversized object")
        return body

    def _state(self, fmt):
        def load():
            directory = FORMATS[fmt][0]
            body = self._body(f"{directory}/{MARKER}", 4096)
            if body is not None:
                marker = json.loads(body)
                if not valid_marker(marker, fmt):
                    raise ValueError("invalid completion marker")
                return True, marker["generation"]
            response = self.s3.list_objects_v2(Bucket=self.bucket, Prefix=directory + "/", MaxKeys=1)
            return bool(response.get("KeyCount")), None
        return self.states.get(fmt, load)

    def data_state(self, fmt):
        loaded, generation = self._state(fmt)
        return loaded, generation is not None

    def load_prefix(self, fmt, prefix):
        _, generation = self._state(fmt)
        directory = FORMATS[fmt][0]
        key = f"{directory}/{prefix}.txt"
        if generation:
            key = f"generations/{generation}/{key}"
        def load():
            body = self._body(key, MAX_RANGE_BYTES)
            if body is None:
                return None
            return parse_range(body, fmt)
        return self.ranges.get(key, load)


def _build_backend():
    source = os.environ.get("PWNED_SOURCE", "dir").strip().lower()
    if source == "s3":
        try:
            from botocore.exceptions import ClientError
        except ImportError as exc:
            raise RuntimeError("S3 requires the s3 image target or requirements-s3.txt") from exc
        client, bucket = s3_client()
        return S3Backend(client, bucket, ClientError)
    if source != "dir":
        raise RuntimeError("PWNED_SOURCE must be 'dir' or 's3'")
    return DirBackend(DATA_DIR)


BACKEND: DataBackend = _build_backend()


def _format_states() -> dict[str, dict]:
    states: dict[str, dict] = {}
    for fmt in FORMATS:
        try:
            loaded, complete = BACKEND.data_state(fmt)
        except Exception:
            loaded, complete = False, False
        states[fmt] = {"data_loaded": loaded, "data_complete": complete}
    return states


def lookup(fmt: str, hashval: str) -> dict:
    if fmt not in FORMATS:
        raise HTTPException(status_code=404, detail=f"unknown format {fmt!r}; use one of {sorted(FORMATS)}")
    _, hash_len = FORMATS[fmt]
    h = hashval.strip().upper()
    if len(h) != hash_len or not HEX_RE.match(h):
        raise HTTPException(status_code=400, detail=f"{fmt} hash must be exactly {hash_len} hex chars")
    prefix, suffix = h[:5], h[5:]
    try:
        loaded, complete = BACKEND.data_state(fmt)
        mapping = BACKEND.load_prefix(fmt, prefix)
        # Completion can be revoked while the range is being read.
        _, still_complete = BACKEND.data_state(fmt)
        complete = complete and still_complete and mapping is not None
    except Exception:
        raise HTTPException(status_code=503, detail="Dataset unavailable or invalid") from None
    count = (mapping or {}).get(suffix, 0)
    return {
        "format": fmt,
        "hash": h,
        "pwned": count > 0,
        "count": count,
        "data_loaded": loaded,
        "data_complete": complete,
    }


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class CheckRequest(BaseModel):
    password: str = Field(max_length=1024, strict=True)
    formats: list[str] = Field(default=["sha1", "ntlm"], min_length=1, max_length=2)

    @field_validator("password")
    @classmethod
    def valid_unicode(cls, value):
        value.encode("utf-8")
        return value

    @field_validator("formats")
    @classmethod
    def valid_formats(cls, values):
        normalized = [value.strip().lower() for value in values]
        if any(value not in FORMATS for value in normalized):
            raise ValueError("unsupported format")
        return list(dict.fromkeys(normalized))


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/info")
def api_info() -> dict:
    return {
        "service": "pwned-password-lookup",
        "source": BACKEND.source,
        "data_dir": BACKEND.describe(),
        "formats": _format_states(),
        "endpoints": {
            "health": "GET /health",
            "lookup": "GET /lookup/{sha1|ntlm}/{hash}",
            "check": 'POST /check {"password": "...", "formats": ["sha1","ntlm"]}',
        },
    }


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "source": BACKEND.source}


@app.get("/lookup/{fmt}/{hash}")
def lookup_endpoint(fmt: str, hash: str) -> dict:
    return lookup(fmt, hash)


@app.post("/check")
def check(req: CheckRequest) -> dict:
    fmts: list[str] = []
    for f in req.formats:
        f = f.strip().lower()
        if f not in FORMATS:
            raise HTTPException(status_code=400, detail=f"unknown format {f!r}; use one of {sorted(FORMATS)}")
        if f not in fmts:
            fmts.append(f)
    if not fmts:
        raise HTTPException(status_code=400, detail="formats must not be empty")
    results = {}
    for f in fmts:
        h = hash_password(req.password, f)
        results[f] = lookup(f, h)
    return {"results": results}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host=os.environ.get("PWNED_API_HOST", "127.0.0.1"),
        port=int(os.environ.get("PWNED_API_PORT", "8000")),
        limit_concurrency=64,
        timeout_keep_alive=5,
        access_log=False,
    )
