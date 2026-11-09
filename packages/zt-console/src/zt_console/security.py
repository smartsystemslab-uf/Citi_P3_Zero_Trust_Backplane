"""HTTP guard rails of the console itself.

The console shows text that attackers can influence (messages, tool arguments, audit records), so it:
* answers only for the hosts it is configured for (blocks DNS-rebinding),
* requires a custom header on every state-changing request (blocks cross-site form posts),
* sends a strict content security policy and never renders untrusted text as markup.
"""
from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

CSRF_HEADER = "x-zt-console"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


class GuardMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, allowed_hosts: tuple[str, ...]) -> None:
        super().__init__(app)
        self.allowed = {h.lower() for h in allowed_hosts}

    async def dispatch(self, request: Request, call_next) -> Response:
        host = request.headers.get("host", "").lower()
        bare = host.rsplit(":", 1)[0] if not host.endswith("]") and ":" in host else host
        if bare not in self.allowed:
            return JSONResponse({"error": "host_not_allowed"}, status_code=403)
        if request.method not in SAFE_METHODS and request.headers.get(CSRF_HEADER) != "1":
            return JSONResponse({"error": "missing_console_header"}, status_code=403)
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response
