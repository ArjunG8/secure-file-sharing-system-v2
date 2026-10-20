"""ASGI middleware: security headers on every response, HTTPS enforcement.

The request scheme is whatever uvicorn resolved: https only if the connection itself was
TLS or a trusted proxy (uvicorn --forwarded-allow-ips) sent X-Forwarded-Proto: https.
This middleware never reads X-Forwarded-Proto itself, so a client can't fake HTTPS.
"""

import json

from starlette.types import ASGIApp, Message, Receive, Scope, Send

# Strict policy for API responses (JSON / file downloads: nothing to render or run).
API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
# Swagger UI pages load their assets from a CDN; they are excluded from the strict CSP.
DOCS_PATHS = ("/api/docs", "/docs/oauth2-redirect")
# Health checks (e.g. a container probe over the internal network) may use plain HTTP.
HTTPS_EXEMPT_PATHS = ("/api/v1/health",)

BASE_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp, hsts_max_age: int) -> None:
        self.app = app
        self.hsts = f"max-age={hsts_max_age}; includeSubDomains" if hsts_max_age else None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        is_https = scope.get("scheme") == "https"

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = [(k, v) for k, v in message.get("headers", [])
                           if k.lower() not in {h.lower().encode() for h in BASE_HEADERS}]
                for name, value in BASE_HEADERS.items():
                    headers.append((name.lower().encode(), value.encode()))
                if not path.startswith(DOCS_PATHS):
                    headers.append((b"content-security-policy", API_CSP.encode()))
                if is_https and self.hsts:  # HSTS is only meaningful (and allowed) over TLS
                    headers.append((b"strict-transport-security", self.hsts.encode()))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_headers)


class HTTPSRequiredMiddleware:
    """Reject plain-HTTP requests: GET/HEAD get a 308 to the https URL, others a 400
    (a redirect would make clients resend credentials or bodies over plain HTTP first)."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (scope["type"] != "http" or scope.get("scheme") == "https"
                or scope.get("path", "").startswith(HTTPS_EXEMPT_PATHS)):
            await self.app(scope, receive, send)
            return
        host = next((v.decode("latin-1") for k, v in scope.get("headers", []) if k == b"host"),
                    "")
        if scope.get("method") in ("GET", "HEAD") and host:
            query = scope.get("query_string", b"").decode("latin-1")
            location = f"https://{host}{scope.get('path', '')}" + (f"?{query}" if query else "")
            await _respond(send, 308, {"location": location},
                           "HTTPS is required; use the https:// address.")
        else:
            await _respond(send, 400, {}, "HTTPS is required for this request.")


async def _respond(send: Send, status: int, extra_headers: dict[str, str], message: str) -> None:
    body = json.dumps({"error": {"code": "https_required", "message": message,
                                 "module": "M10", "details": None}}).encode()
    headers = [(b"content-type", b"application/json"),
               (b"content-length", str(len(body)).encode())]
    headers += [(k.encode(), v.encode()) for k, v in extra_headers.items()]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})
