"""Ordinary HTTP reverse proxy: authenticate first, then contact one fixed upstream."""
import asyncio
import json
import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, urlsplit

import httpx
import jwt

HOP_BY_HOP = {
    b"connection", b"keep-alive", b"proxy-authenticate", b"proxy-authorization",
    b"te", b"trailer", b"transfer-encoding", b"upgrade", b"proxy-connection",
}
SPOOFABLE = {
    b"authorization", b"host", b"content-length", b"forwarded",
    b"x-authenticated-user", b"x-forwarded-for", b"x-forwarded-host",
    b"x-forwarded-proto", b"x-real-ip",
}


@dataclass(frozen=True)
class Settings:
    secret: str
    upstream: str = "http://legacy:8081"
    issuer: str = "http-lab"
    audience: str = "legacy-api"
    max_body_bytes: int = 1024 * 1024

    def __post_init__(self):
        target = urlsplit(self.upstream)
        _ = target.port  # Validate a configured explicit port at startup.
        if (target.scheme not in {"http", "https"} or not target.hostname
                or target.username is not None or target.password is not None
                or target.path not in {"", "/"} or target.query or target.fragment):
            raise ValueError("UPSTREAM_URL must be a fixed http(s) origin without a path")
        if len(self.secret.encode()) < 32:
            raise ValueError("JWT key must contain at least 32 bytes; generate a random key")
        if not self.issuer or not self.audience or self.max_body_bytes < 1:
            raise ValueError("Issuer, audience and body limit must be configured")

    @classmethod
    def from_env(cls):
        secret_file = Path(os.getenv("JWT_SECRET_FILE", "/run/secrets/jwt_secret"))
        return cls(
            secret=secret_file.read_text(encoding="utf-8").strip(),
            upstream=os.getenv("UPSTREAM_URL", "http://legacy:8081"),
            issuer=os.getenv("JWT_ISSUER", "http-lab"),
            audience=os.getenv("JWT_AUDIENCE", "legacy-api"),
        )


def end_to_end(headers, blocked=()):
    """Remove both standard hop-by-hop fields and fields named by Connection."""
    connection_fields = set()
    for name, value in headers:
        if name.lower() == b"connection":
            connection_fields.update(x.strip().lower() for x in value.split(b","))
    excluded = HOP_BY_HOP | connection_fields | set(blocked)
    return [(name.lower(), value) for name, value in headers
            if name.lower() not in excluded]


class Proxy:
    def __init__(self, settings, client=None):
        self.settings = settings
        # A client may be injected by tests; production creates it during ASGI startup.
        self.client = client
        self.owns_client = client is None

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            await self.lifespan(receive, send)
            return
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        if scope["type"] != "http":
            return
        await self.http(scope, receive, send)

    async def lifespan(self, receive, send):
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                if self.client is None:
                    self.client = httpx.AsyncClient(
                        follow_redirects=False, trust_env=False,
                        timeout=httpx.Timeout(15.0, connect=5.0),
                        limits=httpx.Limits(max_connections=100),
                    )
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                if self.owns_client and self.client is not None:
                    await self.client.aclose()
                await send({"type": "lifespan.shutdown.complete"})
                return

    def authenticate(self, headers):
        values = [v for k, v in headers if k.lower() == b"authorization"]
        if len(values) != 1 or len(values[0]) > 8192:
            raise ValueError("A single Bearer credential is required")
        parts = values[0].decode("ascii").split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise ValueError("A Bearer credential is required")
        claims = jwt.decode(
            parts[1], self.settings.secret, algorithms=["HS256"],
            issuer=self.settings.issuer, audience=self.settings.audience,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
        subject = claims["sub"]
        # The trusted identity becomes an HTTP field: keep it bounded and ASCII.
        if (not isinstance(subject, str) or not subject or len(subject) > 128
                or any(ord(char) < 33 or ord(char) > 126 for char in subject)):
            raise ValueError("sub must be a printable ASCII identifier of 1..128 characters")
        return subject

    @staticmethod
    async def error(send, status, message, challenge=False, head=False):
        body = json.dumps({"error": message}).encode()
        headers = [(b"content-type", b"application/json"),
                   (b"cache-control", b"no-store"),
                   (b"content-length", str(len(body)).encode())]
        if challenge:
            headers.append((b"www-authenticate", b'Bearer realm="legacy-api"'))
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": b"" if head else body})

    async def http(self, scope, receive, send):
        headers = scope.get("headers", [])
        head = scope["method"] == "HEAD"
        try:
            subject = self.authenticate(headers)
        except (ValueError, TypeError, UnicodeError, jwt.InvalidTokenError):
            await self.error(send, 401, "Missing or invalid JWT", challenge=True, head=head)
            return
        if scope["method"] == "CONNECT":
            await self.error(send, 405, "CONNECT tunnelling is not supported", head=head)
            return

        # Bound memory and receive time before contacting the legacy service.
        body = bytearray()
        try:
            while True:
                message = await asyncio.wait_for(receive(), timeout=15.0)
                if message["type"] == "http.disconnect":
                    return
                body.extend(message.get("body", b""))
                if len(body) > self.settings.max_body_bytes:
                    await self.error(send, 413, "Request body exceeds 1 MiB", head=head)
                    return
                if not message.get("more_body", False):
                    break
        except TimeoutError:
            await self.error(send, 408, "Request body timed out", head=head)
            return

        raw_path = scope.get("raw_path") or quote(scope["path"], safe="/").encode("ascii")
        target = self.settings.upstream.rstrip("/") + raw_path.decode("ascii")
        query = scope.get("query_string", b"")
        if query:
            target += "?" + query.decode("ascii")
        forwarded = end_to_end(headers, SPOOFABLE)
        # Overwrite client-supplied identity. The legacy service trusts only this proxy.
        forwarded.append((b"x-authenticated-user", subject.encode("ascii")))
        response = None
        started = False
        try:
            request = self.client.build_request(
                scope["method"], target, headers=forwarded, content=bytes(body),
            )
            response = await self.client.send(request, stream=True)
            response_headers = end_to_end(response.headers.raw, {b"cache-control"})
            response_headers.append((b"cache-control", b"private, no-store"))
            await send({"type": "http.response.start", "status": response.status_code,
                        "headers": response_headers})
            started = True
            # Raw bytes preserve compression and Content-Length from the upstream.
            async for chunk in response.aiter_raw():
                await send({"type": "http.response.body", "body": chunk, "more_body": True})
            await send({"type": "http.response.body", "body": b"", "more_body": False})
        except httpx.TimeoutException:
            if started:
                raise  # A second HTTP status cannot replace an already-started response.
            await self.error(send, 504, "Upstream timed out", head=head)
        except httpx.RequestError:
            if started:
                raise
            await self.error(send, 502, "Upstream unavailable", head=head)
        finally:
            if response is not None:
                await response.aclose()


def create_app():
    return Proxy(Settings.from_env())
