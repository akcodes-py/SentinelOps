"""HTTPS/TLS security headers for every gateway HTTP response.

Pure ASGI (no BaseHTTPMiddleware) so streaming responses are not buffered and
headers are also attached to early denials produced by the gateway middleware.
"""
from __future__ import annotations

from typing import Any, Awaitable, Callable

from starlette.datastructures import MutableHeaders

SECURITY_HEADERS: dict[str, str] = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'self'",
    "Referrer-Policy": "no-referrer",
}

Message = dict[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]


class SecurityHeadersMiddleware:
    """Set the gateway's transport security headers on all HTTP responses."""

    def __init__(self, app: Callable[[dict[str, Any], Receive, Send], Awaitable[None]]) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in SECURITY_HEADERS.items():
                    headers[name] = value
            await send(message)

        await self.app(scope, receive, send_with_headers)
