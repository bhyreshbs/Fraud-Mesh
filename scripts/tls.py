"""TLS settings for every sender's httpx client (scripts/*, api/adapters/suricata*.py).

httpx_kwargs(source) -> kwargs for httpx.Client / httpx.AsyncClient / httpx.get / httpx.post:
  {"verify": ssl.SSLContext} that trusts FM_TLS_CA (the local CA, data/certs/ca.crt from scripts/make_certs.py) when
  set, else the system CAs, and holds the client certificate data/certs/<source>.crt + .key when both files exist
  (mutual TLS to POST /v1/events). Nothing configured -> {} (plain http://localhost:8000 keeps working).
The certificate travels inside the SSLContext because httpx 0.28 deprecated `verify=<path>` / `cert=` and its
top-level httpx.post() no longer accepts `cert` at all. FM_TLS_CERT_DIR overrides data/certs. Env read at call time.
"""
from __future__ import annotations

import os
import ssl
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
SOURCES = ("demo-bank-web", "cloud-audit", "network-ids", "simulator")


def _resolve(path: str) -> Path:
    p = Path(path)
    return p if p.is_absolute() else ROOT / p


def ca_file() -> str | None:
    """FM_TLS_CA as an absolute path, or None (unset). A path that does not exist is an error, not a silent fallback."""
    ca = os.getenv("FM_TLS_CA")
    if not ca:
        return None
    path = _resolve(ca)
    if not path.is_file():
        raise FileNotFoundError(f"FM_TLS_CA={ca}: no such file (run python scripts/make_certs.py)")
    return str(path)


def client_cert_files(source: str | None) -> tuple[str, str] | None:
    """(crt, key) for this sender source when both exist under FM_TLS_CERT_DIR (default data/certs)."""
    if source not in SOURCES:                 # a fixed set: never build a file path from arbitrary input
        return None
    cert_dir = _resolve(os.getenv("FM_TLS_CERT_DIR") or "data/certs")
    crt, key = cert_dir / f"{source}.crt", cert_dir / f"{source}.key"
    return (str(crt), str(key)) if crt.is_file() and key.is_file() else None


def ssl_context(source: str | None = None) -> ssl.SSLContext | None:
    """Client SSLContext (also for websockets.connect to wss://). None when nothing is configured."""
    ca, cert = ca_file(), client_cert_files(source)
    if ca is None and cert is None:
        return None
    ctx = ssl.create_default_context(cafile=ca)          # cafile None -> the system CAs
    if cert:
        ctx.load_cert_chain(*cert)
    return ctx


def httpx_kwargs(source: str | None = None) -> dict:
    ctx = ssl_context(source)
    return {"verify": ctx} if ctx is not None else {}


class SourceRoutedAsyncClient:
    """httpx.AsyncClient look-alike for senders that post events from several sources over one "client" (play.py,
    smoke_test.py, perf.py). Under mutual TLS the client certificate's CN must equal X-FM-Source, so a request that
    carries X-FM-Source goes through an httpx.AsyncClient holding that source's certificate; every other request uses a
    client with only the CA settings. With nothing configured this is one plain AsyncClient."""

    def __init__(self, base_url: str, **kwargs) -> None:
        self._base_url, self._kwargs = base_url, kwargs
        self._clients: dict[str | None, httpx.AsyncClient] = {}

    def _client(self, headers) -> httpx.AsyncClient:
        src = (headers.get("X-FM-Source") or headers.get("x-fm-source")) if headers else None
        if src is not None and client_cert_files(src) is None:
            src = None
        if src not in self._clients:
            self._clients[src] = httpx.AsyncClient(base_url=self._base_url, **self._kwargs, **httpx_kwargs(src))
        return self._clients[src]

    async def request(self, method: str, url: str, **kw) -> httpx.Response:
        return await self._client(kw.get("headers")).request(method, url, **kw)

    async def get(self, url: str, **kw) -> httpx.Response:
        return await self.request("GET", url, **kw)

    async def post(self, url: str, **kw) -> httpx.Response:
        return await self.request("POST", url, **kw)

    async def aclose(self) -> None:
        for c in self._clients.values():
            await c.aclose()
        self._clients.clear()

    async def __aenter__(self) -> SourceRoutedAsyncClient:
        return self

    async def __aexit__(self, *exc) -> None:
        await self.aclose()
