from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import socket
import time
from contextlib import asynccontextmanager, suppress
from enum import Enum
from functools import lru_cache
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from playwright.async_api import Browser, async_playwright
from playwright.async_api import Error as PlaywrightError
from playwright.async_api import TimeoutError as PlaywrightTimeoutError
from pydantic import BaseModel, Field, HttpUrl, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Uvicorn owns the production logging configuration. Using its error logger
# guarantees that sanitized lifecycle/solve diagnostics reach Railway stdout.
logger = logging.getLogger("uvicorn.error")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore", case_sensitive=False)

    playwright_service_token: str = Field(min_length=32)
    playwright_service_token_next: str = ""
    solve_timeout_seconds: int = Field(default=120, ge=15, le=300)
    navigation_timeout_seconds: int = Field(default=90, ge=10, le=240)
    max_concurrent_browsers: int = Field(default=1, ge=1, le=16)
    max_queue_size: int = Field(default=20, ge=0, le=1000)
    queue_timeout_seconds: int = Field(default=30, ge=1, le=300)
    max_request_body_bytes: int = Field(default=4096, ge=256, le=65536)
    max_response_cookies: int = Field(default=100, ge=1, le=500)
    max_cookie_value_bytes: int = Field(default=8192, ge=256, le=65536)
    max_redirects: int = Field(default=10, ge=0, le=30)
    allowed_destination_ports: str = "80,443"
    require_https_destination: bool = False
    shutdown_timeout_seconds: int = Field(default=20, ge=1, le=120)
    browser_proxy_server: str = ""
    browser_proxy_username: str = ""
    browser_proxy_password: str = ""

    @field_validator("playwright_service_token", "playwright_service_token_next")
    @classmethod
    def strip_tokens(cls, value: str) -> str:
        return value.strip()

    @field_validator("browser_proxy_server")
    @classmethod
    def valid_proxy_origin(cls, value: str) -> str:
        value = value.strip()
        if not value:
            return value
        parsed = urlparse(value)
        if (
            parsed.scheme not in {"http", "https", "socks5"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("BROWSER_PROXY_SERVER must be a proxy origin without credentials")
        return value.rstrip("/")

    @model_validator(mode="after")
    def validate_related_fields(self) -> "Settings":
        if self.playwright_service_token_next and len(self.playwright_service_token_next) < 32:
            raise ValueError(
                "PLAYWRIGHT_SERVICE_TOKEN_NEXT must be empty or at least 32 characters"
            )
        if (
            self.browser_proxy_username or self.browser_proxy_password
        ) and not self.browser_proxy_server:
            raise ValueError("Proxy credentials require BROWSER_PROXY_SERVER")
        self.destination_ports
        return self

    @property
    def destination_ports(self) -> frozenset[int]:
        try:
            ports = frozenset(
                int(item.strip()) for item in self.allowed_destination_ports.split(",")
            )
        except ValueError as exc:
            raise ValueError("ALLOWED_DESTINATION_PORTS must contain integer ports") from exc
        if not ports or any(port < 1 or port > 65535 for port in ports):
            raise ValueError("ALLOWED_DESTINATION_PORTS contains an invalid port")
        return ports

    @property
    def egress_id(self) -> str:
        raw = "|".join(
            (self.browser_proxy_server, self.browser_proxy_username, self.browser_proxy_password)
        )
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


@lru_cache
def get_settings() -> Settings:
    return Settings()


class SolveInput(BaseModel):
    model_config = {"extra": "forbid"}
    url: HttpUrl


class NavigationState(str, Enum):
    CREATED = "created"
    NAVIGATING = "navigating"
    WAITING_FOR_CHALLENGE = "waiting_for_challenge"
    CLEARANCE_OBSERVED = "clearance_observed"
    COMPLETED = "completed"
    TIMED_OUT = "timed_out"
    FAILED = "failed"


_TRANSPORT_COOKIE_FIELDS = (
    "name",
    "value",
    "domain",
    "path",
    "expires",
    "httpOnly",
    "secure",
    "sameSite",
)


def _transport_cookies(cookies: list[Any], settings: Settings) -> list[dict[str, Any]]:
    """Project browser cookies onto the versioned transport contract.

    Partitioned cookies (CHIPS) depend on a browser top-level-site partition.
    Replaying them as ordinary HTTP cookies would change their security scope,
    so they are deliberately excluded rather than silently de-partitioned.
    """
    if len(cookies) > settings.max_response_cookies:
        raise HTTPException(502, "Browser returned too many cookies")
    output: list[dict[str, Any]] = []
    for cookie in cookies:
        if not isinstance(cookie, dict):
            raise HTTPException(502, "Browser returned an invalid cookie")
        if cookie.get("partitionKey"):
            continue
        value = cookie.get("value")
        if not isinstance(value, str) or len(value.encode()) > settings.max_cookie_value_bytes:
            raise HTTPException(502, "Browser returned an invalid cookie")
        output.append(
            {field: cookie[field] for field in _TRANSPORT_COOKIE_FIELDS if field in cookie}
        )
    if not any(cookie.get("name") == "cf_clearance" for cookie in output):
        raise HTTPException(502, "Clearance cannot be represented by the transport contract")
    return output


def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global


async def _validate_public_url(url: str, settings: Settings | None = None) -> None:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower().rstrip(".")
    # URL validation is also a standalone/testable primitive; it must not
    # require the authentication secret merely to apply the default policy.
    settings = settings or Settings(playwright_service_token="x" * 32)
    if (
        parsed.scheme not in {"http", "https"}
        or not host
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise HTTPException(400, "Only public HTTP(S) URLs are allowed")
    if settings.require_https_destination and parsed.scheme != "https":
        raise HTTPException(403, "Destination policy requires HTTPS")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise HTTPException(400, "Destination port is invalid") from exc
    if port not in settings.destination_ports:
        raise HTTPException(403, "Destination port is not allowed")
    if host == "localhost" or host.endswith(".localhost"):
        raise HTTPException(403, "Private destinations are not allowed")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if not _is_public_ip(str(literal)):
            raise HTTPException(403, "Private destinations are not allowed")
        return
    try:
        records = await asyncio.to_thread(socket.getaddrinfo, host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise HTTPException(400, "Destination hostname could not be resolved") from exc
    addresses = {str(record[4][0]).split("%", 1)[0] for record in records}
    if not addresses or not all(_is_public_ip(address) for address in addresses):
        raise HTTPException(403, "Private destinations are not allowed")


def _authorize(
    authorization: str | None = Header(default=None),
    settings: Settings = Depends(get_settings),
) -> None:
    supplied = authorization or ""
    expected = f"Bearer {settings.playwright_service_token}"
    next_expected = f"Bearer {settings.playwright_service_token_next}"
    current_ok = hmac.compare_digest(supplied.encode(), expected.encode())
    next_ok = bool(settings.playwright_service_token_next) and hmac.compare_digest(
        supplied.encode(), next_expected.encode()
    )
    if not (current_ok or next_ok):
        raise HTTPException(401, "Invalid service token")


def _proxy_config(settings: Settings) -> dict[str, str] | None:
    if not settings.browser_proxy_server:
        return None
    config = {"server": settings.browser_proxy_server}
    if settings.browser_proxy_username:
        config["username"] = settings.browser_proxy_username
    if settings.browser_proxy_password:
        config["password"] = settings.browser_proxy_password
    return config


class SolveCapacity:
    def __init__(self, concurrency: int, queue_size: int):
        self.semaphore = asyncio.Semaphore(concurrency)
        self.queue_size = queue_size
        self.active = 0
        self.queued = 0
        self._lock = asyncio.Lock()

    @asynccontextmanager
    async def acquire(self, timeout: float):
        acquired = False
        async with self._lock:
            if self.semaphore.locked() and self.queued >= self.queue_size:
                raise HTTPException(429, "Solve queue is full", headers={"Retry-After": "5"})
            self.queued += 1
        try:
            try:
                await asyncio.wait_for(self.semaphore.acquire(), timeout=timeout)
                acquired = True
            except TimeoutError as exc:
                raise HTTPException(
                    429, "Solve queue wait timed out", headers={"Retry-After": "5"}
                ) from exc
            async with self._lock:
                self.queued -= 1
                self.active += 1
            try:
                yield
            finally:
                async with self._lock:
                    self.active -= 1
                self.semaphore.release()
        finally:
            async with self._lock:
                if not acquired and self.queued > 0:
                    self.queued -= 1


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    playwright = await async_playwright().start()
    app.state.playwright = playwright
    app.state.settings = settings
    app.state.capacity = SolveCapacity(settings.max_concurrent_browsers, settings.max_queue_size)
    app.state.browser_launch_failures = 0
    app.state.shutting_down = False
    yield
    app.state.shutting_down = True
    deadline = time.monotonic() + settings.shutdown_timeout_seconds
    while app.state.capacity.active and time.monotonic() < deadline:
        await asyncio.sleep(0.05)
    await playwright.stop()


app = FastAPI(
    title="Cloudflare Playwright Cookie Service",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)


@app.exception_handler(HTTPException)
async def sanitized_http_error(request: Request, exc: HTTPException):
    request_id = request.headers.get("x-request-id") or uuid4().hex
    detail = str(exc.detail) if isinstance(exc.detail, str) else "Request failed"
    if request.url.path == "/solve":
        logger.warning(
            "solve_failed request_id=%s status=%s category=%s",
            request_id,
            exc.status_code,
            detail,
        )
    return JSONResponse(
        {"detail": detail, "requestId": request_id},
        status_code=exc.status_code,
        headers=exc.headers,
    )


@app.get("/health/live")
async def health_live():
    return {"status": "ok"}


@app.get("/health/ready")
async def health_ready(request: Request):
    if getattr(request.app.state, "shutting_down", True) or not getattr(
        request.app.state, "playwright", None
    ):
        raise HTTPException(503, "Service is not ready")
    return {"status": "ready"}


@app.get("/metrics")
async def service_metrics(request: Request):
    from fastapi.responses import PlainTextResponse

    capacity = request.app.state.capacity
    body = (
        "# TYPE playwright_solve_inflight gauge\n"
        f"playwright_solve_inflight {capacity.active}\n"
        "# TYPE playwright_solve_queued gauge\n"
        f"playwright_solve_queued {capacity.queued}\n"
        "# TYPE playwright_browser_launch_failures_total counter\n"
        f"playwright_browser_launch_failures_total {request.app.state.browser_launch_failures}\n"
    )
    return PlainTextResponse(body)


async def _solve_with_browser(url: str, settings: Settings, browser: Browser) -> dict:
    state = NavigationState.CREATED
    context = await browser.new_context(service_workers="block")
    page = None
    navigation_count = 0
    initial_scheme = urlparse(url).scheme

    async def guard_public_requests(route) -> None:
        nonlocal navigation_count
        request_url = route.request.url
        parsed = urlparse(request_url)
        if parsed.scheme not in {"http", "https"}:
            await route.abort("blockedbyclient")
            return
        if route.request.is_navigation_request():
            navigation_count += 1
            if navigation_count > settings.max_redirects + 1:
                await route.abort("blockedbyclient")
                return
            if initial_scheme == "https" and parsed.scheme != "https":
                await route.abort("blockedbyclient")
                return
        # Re-resolve every request, including repeated URLs and redirects. The
        # browser API does not expose reliable DNS pinning, so this is a
        # mitigation rather than a claim of perfect rebinding prevention.
        try:
            await _validate_public_url(request_url, settings)
        except HTTPException:
            await route.abort("blockedbyclient")
            return
        await route.continue_()

    await context.route("**/*", guard_public_requests)
    try:
        page = await context.new_page()
        state = NavigationState.NAVIGATING
        response = await page.goto(
            url, wait_until="domcontentloaded", timeout=settings.navigation_timeout_seconds * 1000
        )
        if response is None:
            raise HTTPException(502, "Browser navigation did not return a response")
        await _validate_public_url(page.url, settings)
        state = NavigationState.WAITING_FOR_CHALLENGE
        deadline = time.monotonic() + settings.solve_timeout_seconds
        cookies: list[Any] = []
        while time.monotonic() < deadline:
            cookies = await context.cookies([url])
            if any(cookie.get("name") == "cf_clearance" for cookie in cookies):
                state = NavigationState.CLEARANCE_OBSERVED
                break
            await asyncio.sleep(min(0.25, max(0.01, deadline - time.monotonic())))
        if not any(cookie.get("name") == "cf_clearance" for cookie in cookies):
            content = (await page.title()).lower()
            if "captcha" in content or "verify you are human" in content:
                raise HTTPException(409, "Interactive challenge requires manual completion")
            state = NavigationState.TIMED_OUT
            raise HTTPException(504, "Cloudflare did not issue clearance before timeout")
        response_cookies = _transport_cookies(cookies, settings)
        user_agent = await page.evaluate("navigator.userAgent")
        clearance = next(
            cookie for cookie in response_cookies if cookie.get("name") == "cf_clearance"
        )
        clearance_expiry = float(clearance.get("expires") or -1)
        expires_at = clearance_expiry if clearance_expiry > time.time() else None
        state = NavigationState.COMPLETED
        return {
            "schemaVersion": 1,
            "requestId": uuid4().hex,
            "cookies": response_cookies,
            "userAgent": user_agent,
            "expiresAt": expires_at,
        }
    finally:
        if page is not None:
            with suppress(PlaywrightError):
                await page.close()
        with suppress(PlaywrightError):
            await context.close()
        logger.info("solve_cleanup state=%s egress_id_hash=%s", state.value, settings.egress_id)


@app.post("/solve", dependencies=[Depends(_authorize)])
async def solve(request: Request):
    settings: Settings = request.app.state.settings
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > settings.max_request_body_bytes:
                raise HTTPException(413, "Request body is too large")
        except ValueError as exc:
            raise HTTPException(400, "Invalid Content-Length") from exc
    body = await request.body()
    if len(body) > settings.max_request_body_bytes:
        raise HTTPException(413, "Request body is too large")
    try:
        data = SolveInput.model_validate_json(body)
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(400, "Invalid solve request") from exc
    url = str(data.url)
    await _validate_public_url(url, settings)
    async with request.app.state.capacity.acquire(settings.queue_timeout_seconds):
        browser = None
        try:
            try:
                browser = await request.app.state.playwright.chromium.launch(
                    headless=True,
                    proxy=_proxy_config(settings),
                    args=["--disable-dev-shm-usage"],
                )
            except PlaywrightError:
                request.app.state.browser_launch_failures += 1
                raise
            return await asyncio.wait_for(
                _solve_with_browser(url, settings, browser),
                timeout=settings.solve_timeout_seconds + settings.navigation_timeout_seconds + 5,
            )
        except PlaywrightTimeoutError as exc:
            raise HTTPException(504, "Browser navigation timed out") from exc
        except TimeoutError as exc:
            raise HTTPException(504, "Cloudflare solve timed out") from exc
        except PlaywrightError as exc:
            raise HTTPException(502, "Browser operation failed") from exc
        finally:
            if browser is not None:
                with suppress(PlaywrightError):
                    await browser.close()
