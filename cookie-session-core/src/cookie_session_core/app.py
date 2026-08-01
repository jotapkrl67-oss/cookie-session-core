from __future__ import annotations

import asyncio
import logging
import secrets
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager, suppress
from importlib.resources import files
from urllib.parse import urlencode, urlparse
from uuid import UUID

import asyncpg
import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response, WebSocket
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .auth import AuthenticatedUser, SupabaseJWTVerifier, current_admin, current_user
from .config import get_settings
from .core import CookieSessionCore
from .reverse_proxy import ReverseProxy
from .schemas import CookieImport, LaunchInput, ServiceInput

logger = logging.getLogger("cookie_session_core")


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
            await pool.execute("DELETE FROM cookie_core_proxy_grants WHERE expires_at < now()")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    pool = await asyncpg.create_pool(
        settings.database_url,
        min_size=1,
        max_size=20,
        command_timeout=30,
    )
    await pool.fetchval("SELECT 1")
    schema = files("cookie_session_core").joinpath("schema.sql").read_text(encoding="utf-8")
    await pool.execute(schema)
    core = CookieSessionCore(pool, settings.vault_key, settings.token_pepper)
    http_client = httpx.AsyncClient(
        follow_redirects=False,
        http2=True,
        timeout=httpx.Timeout(settings.proxy_timeout_seconds),
        limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
    )
    cleanup_task = asyncio.create_task(_cleanup_tokens(pool))
    app.state.settings = settings
    app.state.pool = pool
    app.state.core = core
    app.state.proxy = ReverseProxy(core, settings, http_client)
    app.state.jwt_verifier = SupabaseJWTVerifier(settings)
    app.state.rate_limiter = RateLimiter()
    yield
    cleanup_task.cancel()
    with suppress(asyncio.CancelledError):
        await cleanup_task
    await http_client.aclose()
    await pool.close()


def create_app() -> FastAPI:
    resolved = get_settings()
    app = FastAPI(
        title="Cookie Session Core",
        version="0.6.0",
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
            hostname = (request.url.hostname or "").lower().rstrip(".")
            service_id = await request.app.state.proxy.service_id_for_hostname(hostname)
            if service_id:
                request.state.cookie_core_proxy = True
                response = await request.app.state.proxy.http(
                    service_id,
                    request.url.path.lstrip("/"),
                    request,
                    transparent=True,
                )
            else:
                response = await call_next(request)
        except HTTPException as exc:
            response = JSONResponse(
                {"detail": exc.detail},
                status_code=exc.status_code,
                headers=exc.headers,
            )
        except Exception as exc:
            logger.error("request_failed request_id=%s error=%s", request_id, type(exc).__name__)
            response = JSONResponse(
                {"detail": "Internal service error", "request_id": request_id},
                status_code=500,
            )
        response.headers["X-Request-ID"] = request_id
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        if request.url.path.startswith("/proxy/") or getattr(
            request.state, "cookie_core_proxy", False
        ):
            response.headers["Referrer-Policy"] = "same-origin"
        else:
            response.headers["Referrer-Policy"] = "no-referrer"
            response.headers["Permissions-Policy"] = "camera=(), geolocation=(), payment=()"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["Content-Security-Policy"] = (
                "default-src 'none'; script-src 'self'; style-src 'self'; "
                "img-src 'self' blob: data:; connect-src 'self' wss:; "
                "frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
            )
        return response

    @app.get("/health/live")
    async def health(request: Request):
        return {
            "status": "ok",
            "database": bool(await request.app.state.pool.fetchval("SELECT 1")),
            "proxy": True,
        }

    @app.get("/v1/services")
    async def list_user_services(request: Request, user: AuthenticatedUser = Depends(current_user)):
        rows = await request.app.state.pool.fetch(
            """SELECT s.id,s.name,s.category,s.enabled,
                      count(c.id) FILTER (
                        WHERE c.revoked_at IS NULL
                          AND (c.expires_at IS NULL OR c.expires_at > now())
                      ) AS active_cookies
               FROM cookie_core_services s
               LEFT JOIN cookie_core_stored_cookies c
                 ON c.service_id=s.id AND c.user_id=$1
               WHERE s.enabled=true
               GROUP BY s.id
               ORDER BY s.name""",
            user.id,
        )
        return {
            "services": [
                {
                    "id": str(row["id"]),
                    "name": row["name"],
                    "category": row["category"],
                    "enabled": row["enabled"],
                    "status": "ready" if row["active_cookies"] else "not_configured",
                }
                for row in rows
            ]
        }

    @app.post("/v1/services/{service_id}/launch")
    async def launch_service(
        service_id: UUID,
        request: Request,
        _data: LaunchInput | None = None,
        user: AuthenticatedUser = Depends(current_user),
    ):
        request.app.state.rate_limiter.check("launch", user.id, 20)
        try:
            token = await request.app.state.core.issue_launch(
                user_id=user.id,
                service_id=str(service_id),
                ttl_seconds=30,
            )
        except ValueError as exc:
            raise HTTPException(404, str(exc))
        service = await request.app.state.pool.fetchrow(
            "SELECT upstream_url,proxy_hostname FROM cookie_core_services WHERE id=$1",
            service_id,
        )
        upstream_path = urlparse(service["upstream_url"]).path or "/"
        base = (
            f"https://{service['proxy_hostname']}"
            if service["proxy_hostname"]
            else str(request.app.state.settings.public_base_url).rstrip("/")
            + f"/proxy/{service_id}"
        )
        query = urlencode({"launch": token})
        return {
            "launch_url": f"{base}{upstream_path}?{query}",
            "expires_in": 30,
        }

    @app.get("/v1/admin/services")
    async def admin_services(request: Request, _: AuthenticatedUser = Depends(current_admin)):
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
                    "proxy_hostname": row["proxy_hostname"],
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
                 name,category,upstream_url,proxy_hostname,allowed_domains,allowed_paths,
                 allowed_cookie_names,enabled
               ) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *""",
            data.name,
            data.category,
            str(data.upstream_url),
            data.proxy_hostname,
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
        request.app.state.proxy.clear_hostname_cache()
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
                 name=$1,category=$2,upstream_url=$3,proxy_hostname=$4,allowed_domains=$5,
                 allowed_paths=$6,allowed_cookie_names=$7,enabled=$8,updated_at=now()
               WHERE id=$9 RETURNING id,name""",
            data.name,
            data.category,
            str(data.upstream_url),
            data.proxy_hostname,
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
        request.app.state.proxy.clear_hostname_cache()
        return {"id": str(row["id"]), "name": row["name"]}

    @app.post(
        "/v1/admin/services/{service_id}/users/{subject_user_id}/cookies/import",
        status_code=201,
    )
    async def import_user_cookies(
        service_id: UUID,
        subject_user_id: UUID,
        data: CookieImport,
        request: Request,
        admin: AuthenticatedUser = Depends(current_admin),
    ):
        request.app.state.rate_limiter.check("import", admin.id, 10)
        try:
            count = await request.app.state.core.import_cookies(
                actor_user_id=admin.id,
                subject_user_id=str(subject_user_id),
                service_id=str(service_id),
                raw_cookies=data.cookies,
            )
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        return {
            "cookie_count": count,
            "status": "ready",
        }

    @app.get("/v1/admin/services/{service_id}/users/{subject_user_id}/cookies")
    async def list_user_cookies(
        service_id: UUID,
        subject_user_id: UUID,
        request: Request,
        _: AuthenticatedUser = Depends(current_admin),
    ):
        row = await request.app.state.pool.fetchrow(
            """SELECT count(c.id) AS cookie_count,
                      count(c.id) FILTER (
                        WHERE c.revoked_at IS NULL
                          AND (c.expires_at IS NULL OR c.expires_at > now())
                      ) AS active_count,
                      array_remove(array_agg(DISTINCT c.name),NULL) AS cookie_names,
                      array_remove(array_agg(DISTINCT c.domain),NULL) AS domains,
                      max(c.expires_at) AS latest_expiry
               FROM cookie_core_stored_cookies c
               WHERE c.user_id=$1 AND c.service_id=$2""",
            str(subject_user_id),
            service_id,
        )
        return {
            "cookie_count": row["cookie_count"],
            "cookie_names": row["cookie_names"],
            "domains": row["domains"],
            "latest_expiry": row["latest_expiry"],
            "status": "ready" if row["active_count"] else "not_configured",
        }

    @app.delete(
        "/v1/admin/services/{service_id}/users/{subject_user_id}/cookies",
        status_code=204,
    )
    async def delete_user_cookies(
        service_id: UUID,
        subject_user_id: UUID,
        request: Request,
        admin: AuthenticatedUser = Depends(current_admin),
    ):
        async with request.app.state.pool.acquire() as conn, conn.transaction():
            deleted = await conn.fetchval(
                """DELETE FROM cookie_core_stored_cookies
                   WHERE user_id=$1 AND service_id=$2 RETURNING id""",
                str(subject_user_id),
                service_id,
            )
            if not deleted:
                raise HTTPException(404, "Cookies are not configured")
            await conn.execute(
                """INSERT INTO cookie_core_audit_logs(
                     actor_user_id,subject_user_id,service_id,action,details
                   ) VALUES($1,$2,$3,'cookies.revoke','{}'::jsonb)""",
                admin.id,
                str(subject_user_id),
                service_id,
            )
        return Response(status_code=204)

    @app.api_route(
        "/proxy/{service_id}/{path:path}",
        methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    )
    async def proxy_http(service_id: UUID, path: str, request: Request):
        request.state.cookie_core_proxy = True
        return await request.app.state.proxy.http(str(service_id), path, request)

    @app.websocket("/proxy/{service_id}/{path:path}")
    async def proxy_websocket(websocket: WebSocket, service_id: UUID, path: str):
        await websocket.scope["app"].state.proxy.websocket(websocket, str(service_id), path)

    @app.api_route(
        "/{path:path}",
        methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        include_in_schema=False,
    )
    async def transparent_proxy_http(path: str, request: Request):
        hostname = (request.url.hostname or "").lower().rstrip(".")
        service_id = await request.app.state.proxy.service_id_for_hostname(hostname)
        if not service_id:
            raise HTTPException(404, "Not found")
        request.state.cookie_core_proxy = True
        return await request.app.state.proxy.http(
            service_id, path, request, transparent=True
        )

    @app.websocket("/{path:path}")
    async def transparent_proxy_websocket(websocket: WebSocket, path: str):
        hostname = (websocket.url.hostname or "").lower().rstrip(".")
        proxy = websocket.scope["app"].state.proxy
        service_id = await proxy.service_id_for_hostname(hostname)
        if not service_id:
            await websocket.close(code=4404)
            return
        await websocket.scope["app"].state.proxy.websocket(
            websocket, service_id, path, transparent=True
        )

    return app


app = create_app()
