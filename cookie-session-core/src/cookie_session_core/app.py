from __future__ import annotations

import asyncio
import hashlib
import logging
import math
import secrets
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager, suppress
from importlib.resources import files
from typing import Any
from urllib.parse import urlencode, urlparse
from uuid import UUID

import asyncpg
from fastapi import Depends, FastAPI, HTTPException, Request, Response, WebSocket
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .auth import AuthenticatedUser, SupabaseJWTVerifier, current_admin, current_user
from .browser_client import BrowserLikeClient
from .config import get_settings
from .core import CookieSessionCore
from .reverse_proxy import ReverseProxy
from .schemas import CfClearanceInject, CfSolveUrlInput, CookieImport, LaunchInput, ServiceInput

logger = logging.getLogger("cookie_session_core")
APP_VERSION = "0.6.7"


class RateLimiter:
    def __init__(self):
        self.events: dict[tuple[str, str], deque[float]] = defaultdict(deque)

    def check(self, scope: str, subject: str, maximum: int, window: int = 60) -> None:
        now = time.monotonic()
        bucket = self.events[(scope, subject)]
        while bucket and bucket[0] <= now - window:
            bucket.popleft()
        if len(bucket) >= maximum:
            retry_after = max(1, math.ceil(bucket[0] + window - now))
            raise HTTPException(
                429,
                "Too many requests; try again shortly",
                headers={"Retry-After": str(retry_after)},
            )
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
    core = CookieSessionCore(
        pool,
        settings.vault_key,
        settings.token_pepper,
        set(settings.blocked_cookie_public_suffixes),
    )
    browser_client = BrowserLikeClient(
        impersonate="chrome124",
        timeout=float(settings.proxy_timeout_seconds),
        max_connections=100,
        settings=settings,
    )
    cleanup_task = asyncio.create_task(_cleanup_tokens(pool))
    app.state.settings = settings
    app.state.pool = pool
    app.state.core = core
    app.state.proxy = ReverseProxy(core, settings, browser_client)
    app.state.browser_client = browser_client
    app.state.jwt_verifier = SupabaseJWTVerifier(settings)
    app.state.rate_limiter = RateLimiter()
    yield
    cleanup_task.cancel()
    with suppress(asyncio.CancelledError):
        await cleanup_task
    await browser_client.aclose()
    await pool.close()


def create_app() -> FastAPI:
    resolved = get_settings()
    app = FastAPI(
        title="Cookie Session Core",
        version=APP_VERSION,
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
        allow_headers=[
            "Authorization",
            "Content-Type",
            "X-Cookie-Core-Admin",
            "X-Force-OAI-Rotate",
        ],
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
            if (
                request.url.path.startswith("/proxy/")
                or request.cookies.get("__Secure-cookie_core_proxy")
                or request.query_params.get("launch")
            ):
                raw_grant = request.cookies.get(
                    "__Secure-cookie_core_proxy"
                ) or request.query_params.get("launch")
                if not raw_grant:
                    raw_grant = request.client.host if request.client else "unknown"
                launch_subject = hashlib.sha256(raw_grant.encode()).hexdigest()
                request.app.state.rate_limiter.check("proxy", launch_subject, 1800)
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
            "version": APP_VERSION,
            "database": bool(await request.app.state.pool.fetchval("SELECT 1")),
            "proxy": True,
        }

    @app.get("/metrics", include_in_schema=False)
    async def prometheus_metrics(request: Request):
        if not request.app.state.settings.metrics_enabled:
            raise HTTPException(404, "Not found")
        from .metrics import metrics

        return Response(metrics.render(), media_type="text/plain; version=0.0.4")

    @app.get("/v1/services")
    async def list_user_services(request: Request, user: AuthenticatedUser = Depends(current_user)):
        request.app.state.rate_limiter.check("services", user.id, 10)
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
        request.app.state.rate_limiter.check("launch", user.id, 5)
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

    @app.get("/v1/admin/cf/clearance")
    async def admin_list_clearance(
        request: Request,
        _: AuthenticatedUser = Depends(current_admin),
    ):
        cache = request.app.state.browser_client.clearance
        entries = []
        import time as _t

        now = _t.time()
        for domain, rec in list(cache._data.items()):
            entries.append(
                {
                    "domain": domain,
                    "expires_in": max(0, int(rec.expires_at - now)),
                    "expires_at": int(rec.expires_at),
                }
            )
        entries.sort(key=lambda e: e["domain"])
        return {
            "count": len(entries),
            "provider": str(request.app.state.settings.cf_solver_provider.value),
            "providers": [
                provider.value for provider in request.app.state.settings.solver_provider_list
            ],
            "entries": entries,
        }

    @app.post("/v1/admin/cf/clearance", status_code=201)
    async def admin_inject_clearance(
        data: CfClearanceInject,
        request: Request,
        admin: AuthenticatedUser = Depends(current_admin),
    ):
        request.app.state.rate_limiter.check("admin-write", admin.id, 30)
        cache = request.app.state.browser_client.clearance
        cache.set(data.domain, data.cf_clearance, ttl=data.ttl_seconds)
        logger.info(
            "Admin %s injected cf_clearance domain=%s ttl=%ss",
            admin.id,
            data.domain,
            data.ttl_seconds,
        )
        return {
            "domain": data.domain,
            "ttl_seconds": data.ttl_seconds,
            "status": "cached",
        }

    @app.delete("/v1/admin/cf/clearance/{domain}", status_code=204)
    async def admin_clear_clearance(
        domain: str,
        request: Request,
        admin: AuthenticatedUser = Depends(current_admin),
    ):
        cache = request.app.state.browser_client.clearance
        if domain == "__all__":
            cache.clear(None)
            logger.info("Admin %s cleared entire cf_clearance cache", admin.id)
        else:
            cache.clear(domain)
            logger.info("Admin %s cleared cf_clearance domain=%s", admin.id, domain)
        return Response(status_code=204)

    @app.get("/v1/admin/cf/status")
    async def admin_cf_status(
        request: Request,
        _: AuthenticatedUser = Depends(current_admin),
    ):
        s = request.app.state.settings
        from .config import CfSolverProvider

        return {
            "provider": str(s.cf_solver_provider.value),
            "providers": [provider.value for provider in s.solver_provider_list],
            "configured": bool(s.solver_provider_list)
            and bool(
                s.cf_solver_api_key
                or s.cf_solver_api_keys
                or CfSolverProvider.CUSTOM in s.solver_provider_list
            ),
            "timeout_seconds": s.cf_solver_timeout_seconds,
            "max_retries": s.cf_solver_max_retries,
            "impersonate_targets": list(s.cf_solver_impersonate_targets),
            "current_impersonate": request.app.state.browser_client.impersonate,
            "endpoint": str(s.cf_solver_api_endpoint) if s.cf_solver_api_endpoint else None,
        }

    @app.post("/v1/admin/cf/solve")
    async def admin_solve_url(
        data: CfSolveUrlInput,
        request: Request,
        admin: AuthenticatedUser = Depends(current_admin),
    ):
        """Fetch a URL through the proxy transport, detect a Cloudflare
        challenge, run the configured third-party solver, and cache the
        resulting ``cf_clearance`` so future proxy requests inherit it.

        Useful both as a diagnostic tool (``GET /v1/admin/cf/status`` to see
        the resulting entry) and as a way to pre-warm the cache for a
        hostname that is currently 429/403 before the real user navigates to
        it.
        """
        from .browser_client import (
            _looks_like_cloudflare_challenge,
            _looks_like_cloudflare_response,
            _parse_retry_after,
        )

        request.app.state.rate_limiter.check("cf-solve", admin.id, 2)
        client: BrowserLikeClient = request.app.state.browser_client
        saved_impersonate = client.impersonate
        if data.impersonate != saved_impersonate:
            try:
                await client._rotate_impersonation.__wrapped__  # type: ignore[attr-defined]
            except AttributeError:
                pass
            client.impersonate = data.impersonate
            async with client._curl_lock:
                if client._curl is not None:
                    with suppress(Exception):
                        await client._curl.close()
                    client._curl = None

        url = str(data.url)
        headers = {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "accept-language": "en-US,en;q=0.9",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        }
        probe_request = client.build_request("GET", url, headers=headers)
        try:
            probe = await client._send_once(probe_request, stream=False, materialized_body=b"")
        except Exception as exc:
            raise HTTPException(502, f"Upstream probe failed: {exc}")

        status = probe.status_code
        body = probe.content or b""
        is_challenge = _looks_like_cloudflare_challenge(status, body, probe.headers)
        is_cf_response = _looks_like_cloudflare_response(status, probe.headers)
        retry_after = _parse_retry_after(probe.headers)
        result_summary: dict[str, Any] = {
            "url": url,
            "status_code": status,
            "cf_challenge_detected": is_challenge,
            "cf_response_headers_present": is_cf_response,
            "retry_after_seconds": retry_after,
            "response_bytes": len(body),
            "solver": None,
            "cached_clearance": None,
        }
        if not (is_challenge or is_cf_response):
            result_summary["note"] = (
                "Probe did not detect a Cloudflare challenge or CF-branded "
                "4xx/5xx response. The origin may be healthy for this IP, or "
                "its protection is implemented purely in the app layer."
            )
            return result_summary

        solver = await client._get_solver()
        if solver is None:
            result_summary["solver"] = {
                "ran": False,
                "reason": "no solver provider configured",
            }
            return result_summary

        try:
            solve_result = await solver.try_solve(url, status, body, probe.headers)
        except Exception as exc:
            result_summary["solver"] = {"ran": True, "success": False, "error": str(exc)}
            return result_summary

        result_summary["solver"] = {
            "ran": True,
            "provider": solve_result.provider.value,
            "success": solve_result.success,
            "cf_clearance_obtained": bool(solve_result.cf_clearance),
            "clearance_ttl_seconds": solve_result.clearance_ttl,
            "turnstile_token_obtained": bool(solve_result.turnstile_token),
            "error": solve_result.error,
        }
        domain = (urlparse(url).hostname or "").lower()
        if domain:
            existing = client.clearance.get(domain)
            result_summary["cached_clearance"] = {"domain": domain, "present": bool(existing)}
        return result_summary

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
        return await request.app.state.proxy.http(service_id, path, request, transparent=True)

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
