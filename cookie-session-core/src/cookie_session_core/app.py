from __future__ import annotations

import asyncio
import html
import logging
import secrets
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from urllib.parse import quote
from uuid import UUID

import asyncpg
from fastapi import Depends, FastAPI, HTTPException, Request, Response, WebSocket
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

from .auth import AuthenticatedUser, SupabaseJWTVerifier, current_admin, current_user
from .browser_manager import BrowserSessionManager
from .config import get_settings
from .core import CookieSessionCore
from .schemas import LaunchExchange, LaunchInput, ProfileImport, ServiceInput

logger = logging.getLogger("cookie_session_core")
STATIC_ROOT = Path(__file__).parent / "static"


class RateLimiter:
    def __init__(self):
        self.events: dict[tuple[str, str], deque[float]] = defaultdict(deque)

    def check(self, scope: str, subject: str, maximum: int, window: int = 60) -> None:
        now = time.monotonic()
        bucket = self.events[(scope, subject)]
        while bucket and bucket[0] <= now - window:
            bucket.popleft()
        if len(bucket) >= maximum:
            raise HTTPException(429, "Too many requests; try again shortly")
        bucket.append(now)


async def _cleanup_tokens(pool: asyncpg.Pool) -> None:
    while True:
        await asyncio.sleep(60)
        with suppress(Exception):
            await pool.execute("DELETE FROM cookie_core_launch_tokens WHERE expires_at < now()")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    pool = await asyncpg.create_pool(
        settings.database_url,
        min_size=1,
        max_size=max(3, settings.max_browser_sessions + 2),
        command_timeout=30,
    )
    await pool.fetchval("SELECT 1")
    core = CookieSessionCore(pool, settings.vault_key, settings.token_pepper)
    browsers = BrowserSessionManager(settings, core)
    await browsers.start()
    cleanup_task = asyncio.create_task(_cleanup_tokens(pool))
    app.state.settings = settings
    app.state.pool = pool
    app.state.core = core
    app.state.browsers = browsers
    app.state.jwt_verifier = SupabaseJWTVerifier(settings)
    app.state.rate_limiter = RateLimiter()
    yield
    cleanup_task.cancel()
    with suppress(asyncio.CancelledError):
        await cleanup_task
    await browsers.stop()
    await pool.close()


def create_app() -> FastAPI:
    resolved = get_settings()
    app = FastAPI(
        title="Cookie Session Core",
        version="0.2.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=resolved.origin_list,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Cookie-Core-Admin"],
    )

    @app.exception_handler(RequestValidationError)
    async def sanitized_validation_error(_: Request, exc: RequestValidationError):
        errors = [
            {
                "field": ".".join(str(part) for part in item.get("loc", ()) if part != "body"),
                "message": item.get("msg", "Invalid value"),
            }
            for item in exc.errors()
        ]
        return JSONResponse(
            {"detail": "Invalid request", "errors": errors},
            status_code=422,
        )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        request_id = request.headers.get("x-request-id") or secrets.token_hex(12)
        try:
            response = await call_next(request)
        except Exception as exc:
            logger.error("request_failed request_id=%s error=%s", request_id, type(exc).__name__)
            return JSONResponse(
                {"detail": "Internal service error", "request_id": request_id},
                status_code=500,
            )
        response.headers["X-Request-ID"] = request_id
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Permissions-Policy"] = "camera=(), geolocation=(), payment=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'self'; style-src 'self'; "
            "img-src 'self' blob: data:; connect-src 'self' wss:; "
            "frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        )
        return response

    @app.get("/health/live")
    async def health(request: Request):
        browser = request.app.state.browsers.browser
        return {
            "status": "ok",
            "database": bool(await request.app.state.pool.fetchval("SELECT 1")),
            "browser": bool(browser and browser.is_connected()),
            "active_sessions": len(request.app.state.browsers.sessions),
        }

    @app.get("/v1/services")
    async def list_user_services(
        request: Request, user: AuthenticatedUser = Depends(current_user)
    ):
        rows = await request.app.state.pool.fetch(
            """SELECT s.id,s.name,s.category,s.enabled,p.id AS profile_id,p.label,
                      p.is_default,
                      count(c.id) FILTER (
                        WHERE c.revoked_at IS NULL
                          AND (c.expires_at IS NULL OR c.expires_at > now())
                      ) AS active_cookies
               FROM cookie_core_services s
               JOIN cookie_core_profiles p ON p.service_id=s.id AND p.user_id=$1
               LEFT JOIN cookie_core_stored_cookies c ON c.profile_id=p.id
                 AND c.user_id=p.user_id AND c.service_id=p.service_id
               WHERE s.enabled=true
               GROUP BY s.id,p.id
               ORDER BY s.name,p.is_default DESC,p.label""",
            user.id,
        )
        services: dict[str, dict] = {}
        for row in rows:
            service_id = str(row["id"])
            service = services.setdefault(
                service_id,
                {
                    "id": service_id,
                    "name": row["name"],
                    "category": row["category"],
                    "enabled": row["enabled"],
                    "profiles": [],
                },
            )
            service["profiles"].append(
                {
                    "id": str(row["profile_id"]),
                    "label": row["label"],
                    "is_default": row["is_default"],
                    "status": "ready" if row["active_cookies"] else "expired",
                }
            )
        return {"services": list(services.values())}

    @app.post("/v1/services/{service_id}/launch")
    async def launch_service(
        service_id: UUID,
        data: LaunchInput,
        request: Request,
        user: AuthenticatedUser = Depends(current_user),
    ):
        request.app.state.rate_limiter.check("launch", user.id, 20)
        profile_id = data.profile_id
        if not profile_id:
            profile_id = await request.app.state.pool.fetchval(
                """SELECT id FROM cookie_core_profiles
                   WHERE user_id=$1 AND service_id=$2
                   ORDER BY is_default DESC,created_at LIMIT 1""",
                user.id,
                service_id,
            )
        if not profile_id:
            raise HTTPException(404, "No account is configured for this service")
        try:
            token = await request.app.state.core.issue_launch(
                user_id=user.id,
                service_id=str(service_id),
                profile_id=str(profile_id),
                ttl_seconds=30,
            )
        except ValueError as exc:
            raise HTTPException(404, str(exc))
        base = str(request.app.state.settings.public_base_url).rstrip("/")
        return {
            "launch_url": f"{base}/remote/start#token={quote(token)}",
            "expires_in": 30,
        }

    @app.post("/v1/launch/exchange")
    async def exchange_launch(data: LaunchExchange, request: Request):
        subject = request.client.host if request.client else "unknown"
        request.app.state.rate_limiter.check("exchange", subject, 30)
        try:
            launch = await request.app.state.core.consume_launch(raw_token=data.token)
        except ValueError:
            raise HTTPException(401, "Launch link is invalid, expired, or already used")
        session_id, grant = await request.app.state.browsers.create(launch)
        response = JSONResponse({"session_id": session_id})
        response.set_cookie(
            "__Secure-cookie_core_grant",
            grant,
            max_age=request.app.state.settings.browser_session_ttl_seconds,
            secure=request.app.state.settings.secure_cookies,
            httponly=True,
            samesite="lax",
            path=f"/remote/{session_id}/",
        )
        return response

    @app.get("/remote/start", response_class=HTMLResponse)
    async def remote_start():
        return HTMLResponse(
            """<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Abrindo sessão</title><link rel="stylesheet" href="/remote/remote.css"></head>
<body><main class="overlay" id="status">Abrindo sessão protegida…</main>
<script src="/remote/start.js" defer></script></body></html>"""
        )

    @app.get("/remote/{session_id}/", response_class=HTMLResponse)
    async def remote_page(session_id: str, request: Request):
        item = request.app.state.browsers.authorized(
            session_id, request.cookies.get("__Secure-cookie_core_grant")
        )
        if not item:
            raise HTTPException(401, "Remote session is invalid or expired")
        return_url = html.escape(str(request.app.state.settings.lovable_return_url))
        safe_session = html.escape(session_id)
        return HTMLResponse(
            f"""<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sessão remota</title><link rel="stylesheet" href="/remote/remote.css"></head>
<body data-session="{safe_session}" data-return="{return_url}">
<main class="viewport" tabindex="0"><canvas id="screen" width="1440" height="900"></canvas>
<div class="overlay">Conectando…</div></main>
<nav class="controls"><button data-action="back">←</button>
<button data-action="reload">↻</button><span class="state">Conectando…</span>
<button data-action="close">Fechar</button></nav>
<script src="/remote/remote.js" defer></script></body></html>"""
        )

    @app.get("/remote/remote.js")
    async def remote_javascript():
        return FileResponse(STATIC_ROOT / "remote.js", media_type="application/javascript")

    @app.get("/remote/start.js")
    async def start_javascript():
        return FileResponse(STATIC_ROOT / "start.js", media_type="application/javascript")

    @app.get("/remote/remote.css")
    async def remote_styles():
        return FileResponse(STATIC_ROOT / "remote.css", media_type="text/css")

    @app.websocket("/remote/{session_id}/ws")
    async def remote_websocket(websocket: WebSocket, session_id: str):
        await websocket.scope["app"].state.browsers.websocket(websocket, session_id)

    @app.get("/v1/admin/services")
    async def admin_services(
        request: Request, _: AuthenticatedUser = Depends(current_admin)
    ):
        rows = await request.app.state.pool.fetch(
            "SELECT * FROM cookie_core_services ORDER BY name"
        )
        return {
            "services": [
                {
                    "id": str(row["id"]),
                    "name": row["name"],
                    "category": row["category"],
                    "upstream_url": row["upstream_url"],
                    "allowed_domains": row["allowed_domains"],
                    "allowed_paths": row["allowed_paths"],
                    "allowed_cookie_names": row["allowed_cookie_names"],
                    "enabled": row["enabled"],
                }
                for row in rows
            ]
        }

    @app.post("/v1/admin/services", status_code=201)
    async def create_service(
        data: ServiceInput,
        request: Request,
        admin: AuthenticatedUser = Depends(current_admin),
    ):
        request.app.state.rate_limiter.check("admin-write", admin.id, 20)
        row = await request.app.state.pool.fetchrow(
            """INSERT INTO cookie_core_services(
                 name,category,upstream_url,allowed_domains,allowed_paths,
                 allowed_cookie_names,enabled
               ) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *""",
            data.name,
            data.category,
            str(data.upstream_url),
            data.allowed_domains,
            data.allowed_paths,
            data.allowed_cookie_names,
            data.enabled,
        )
        await request.app.state.pool.execute(
            """INSERT INTO cookie_core_audit_logs(
                 actor_user_id,subject_user_id,service_id,action,details
               ) VALUES($1,$1,$2,'service.create','{}'::jsonb)""",
            admin.id,
            row["id"],
        )
        return {"id": str(row["id"]), "name": row["name"]}

    @app.put("/v1/admin/services/{service_id}")
    async def update_service(
        service_id: UUID,
        data: ServiceInput,
        request: Request,
        admin: AuthenticatedUser = Depends(current_admin),
    ):
        request.app.state.rate_limiter.check("admin-write", admin.id, 20)
        row = await request.app.state.pool.fetchrow(
            """UPDATE cookie_core_services SET
                 name=$1,category=$2,upstream_url=$3,allowed_domains=$4,
                 allowed_paths=$5,allowed_cookie_names=$6,enabled=$7,updated_at=now()
               WHERE id=$8 RETURNING id,name""",
            data.name,
            data.category,
            str(data.upstream_url),
            data.allowed_domains,
            data.allowed_paths,
            data.allowed_cookie_names,
            data.enabled,
            service_id,
        )
        if not row:
            raise HTTPException(404, "Service not found")
        await request.app.state.pool.execute(
            """INSERT INTO cookie_core_audit_logs(
                 actor_user_id,subject_user_id,service_id,action,details
               ) VALUES($1,$1,$2,'service.update','{}'::jsonb)""",
            admin.id,
            service_id,
        )
        return {"id": str(row["id"]), "name": row["name"]}

    @app.post(
        "/v1/admin/services/{service_id}/users/{subject_user_id}/profiles/import",
        status_code=201,
    )
    async def import_profile(
        service_id: UUID,
        subject_user_id: UUID,
        data: ProfileImport,
        request: Request,
        admin: AuthenticatedUser = Depends(current_admin),
    ):
        request.app.state.rate_limiter.check("import", admin.id, 10)
        try:
            profile_id, count = await request.app.state.core.import_profile(
                actor_user_id=admin.id,
                subject_user_id=str(subject_user_id),
                service_id=str(service_id),
                label=data.label,
                raw_cookies=data.cookies,
                profile_id=str(data.profile_id) if data.profile_id else None,
                make_default=data.is_default,
            )
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        return {
            "id": profile_id,
            "label": data.label,
            "cookie_count": count,
            "is_default": data.is_default,
            "status": "ready",
        }

    @app.get("/v1/admin/services/{service_id}/users/{subject_user_id}/profiles")
    async def list_profiles(
        service_id: UUID,
        subject_user_id: UUID,
        request: Request,
        _: AuthenticatedUser = Depends(current_admin),
    ):
        rows = await request.app.state.pool.fetch(
            """SELECT p.id,p.label,p.is_default,
                      count(c.id) AS cookie_count,
                      count(c.id) FILTER (
                        WHERE c.revoked_at IS NULL
                          AND (c.expires_at IS NULL OR c.expires_at > now())
                      ) AS active_count,
                      array_remove(array_agg(DISTINCT c.name),NULL) AS cookie_names,
                      array_remove(array_agg(DISTINCT c.domain),NULL) AS domains,
                      max(c.expires_at) AS latest_expiry
               FROM cookie_core_profiles p
               LEFT JOIN cookie_core_stored_cookies c ON c.profile_id=p.id
                 AND c.user_id=p.user_id AND c.service_id=p.service_id
               WHERE p.user_id=$1 AND p.service_id=$2
               GROUP BY p.id ORDER BY p.is_default DESC,p.label""",
            str(subject_user_id),
            service_id,
        )
        return {
            "profiles": [
                {
                    "id": str(row["id"]),
                    "label": row["label"],
                    "is_default": row["is_default"],
                    "cookie_count": row["cookie_count"],
                    "cookie_names": row["cookie_names"],
                    "domains": row["domains"],
                    "latest_expiry": row["latest_expiry"],
                    "status": "ready" if row["active_count"] else "expired",
                }
                for row in rows
            ]
        }

    @app.delete(
        "/v1/admin/services/{service_id}/users/{subject_user_id}/profiles/{profile_id}",
        status_code=204,
    )
    async def delete_profile(
        service_id: UUID,
        subject_user_id: UUID,
        profile_id: UUID,
        request: Request,
        admin: AuthenticatedUser = Depends(current_admin),
    ):
        async with request.app.state.pool.acquire() as conn, conn.transaction():
            deleted = await conn.fetchval(
                """DELETE FROM cookie_core_profiles
                   WHERE id=$1 AND user_id=$2 AND service_id=$3 RETURNING id""",
                profile_id,
                str(subject_user_id),
                service_id,
            )
            if not deleted:
                raise HTTPException(404, "Profile not found")
            await conn.execute(
                """INSERT INTO cookie_core_audit_logs(
                     actor_user_id,subject_user_id,service_id,profile_id,action,details
                   ) VALUES($1,$2,$3,$4,'cookies.revoke','{}'::jsonb)""",
                admin.id,
                str(subject_user_id),
                service_id,
                profile_id,
            )
        await request.app.state.browsers.close_profile(
            str(subject_user_id), str(service_id), str(profile_id)
        )
        return Response(status_code=204)

    return app


app = create_app()
