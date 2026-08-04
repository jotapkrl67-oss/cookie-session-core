from __future__ import annotations

import asyncio
import inspect
import math
import re
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, replace
from typing import Any, Callable, Protocol, runtime_checkable
from urllib.parse import urlparse

import httpx

from .metrics import metrics

_COOKIE_NAME_RE = re.compile(r"^[^\x00-\x20\x7f()<>@,;:\\\"/\[\]?={}]+$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)
_DEFAULT_PUBLIC_SUFFIXES = frozenset(
    {
        "com",
        "org",
        "net",
        "edu",
        "gov",
        "mil",
        "io",
        "co.uk",
        "org.uk",
        "com.br",
        "com.au",
        "com.mx",
        "co.jp",
        "co.in",
        "co.nz",
        "co.za",
        "com.cn",
        "com.sg",
        "com.tr",
        "com.ar",
        "appspot.com",
        "github.io",
        "gitlab.io",
        "herokuapp.com",
        "netlify.app",
        "onrender.com",
        "pages.dev",
        "railway.app",
        "vercel.app",
        "workers.dev",
    }
)


@dataclass(frozen=True)
class CloudflareCookie:
    name: str
    value: str
    domain: str
    path: str = "/"
    expires_at: float | None = None
    secure: bool = True
    http_only: bool = True
    same_site: str | None = None
    host_only: bool = False


@dataclass(frozen=True)
class CloudflareCookieResult:
    cookies: tuple[CloudflareCookie, ...]
    user_agent: str
    expires_at: float | None = None


@runtime_checkable
class CloudflareCookieProvider(Protocol):
    async def solve(self, url: str) -> CloudflareCookieResult: ...


class CloudflareCookieProviderError(RuntimeError):
    """Base error whose message is safe to expose in operational logs."""


class CloudflareProviderAuthenticationError(CloudflareCookieProviderError):
    pass


class CloudflareProviderValidationError(CloudflareCookieProviderError):
    pass


class CloudflareProviderTimeoutError(CloudflareCookieProviderError):
    pass


class CloudflareProviderUnavailableError(CloudflareCookieProviderError):
    pass


class CloudflareClearanceNotIssuedError(CloudflareCookieProviderError):
    pass


class CloudflareProviderProtocolError(CloudflareCookieProviderError):
    pass


def _origin_key(url: str, egress_identity: str = "direct") -> str:
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower().rstrip(".")
    if scheme not in {"http", "https"} or not host:
        raise ValueError("Cloudflare session URL must be HTTP(S) with a hostname")
    port = parsed.port or (443 if scheme == "https" else 80)
    return f"{scheme}://{host}:{port}|{egress_identity}"


def _domain_matches(host: str, domain: str) -> bool:
    domain = domain.lower().lstrip(".").rstrip(".")
    return host == domain or host.endswith("." + domain)


class HttpCloudflareCookieProvider:
    def __init__(
        self,
        service_url: str,
        token: str,
        *,
        timeout: float = 120.0,
        connect_timeout: float = 10.0,
        max_response_bytes: int = 1_000_000,
        max_retries: int = 2,
        allow_insecure_http: bool = False,
        http_client: httpx.AsyncClient | None = None,
    ):
        parsed = urlparse(service_url)
        if (
            parsed.scheme not in {"https", "http"}
            or not parsed.hostname
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or parsed.username
            or parsed.password
        ):
            raise ValueError("PLAYWRIGHT_SERVICE_URL must be an HTTP(S) origin")
        if parsed.scheme != "https" and not allow_insecure_http:
            raise ValueError("PLAYWRIGHT_SERVICE_URL must use HTTPS")
        token = token.strip()
        if len(token) < 32:
            raise ValueError("PLAYWRIGHT_SERVICE_TOKEN must contain at least 32 characters")
        self._endpoint = service_url.rstrip("/") + "/solve"
        self._token = token
        self._max_response_bytes = max(1024, int(max_response_bytes))
        self._max_retries = max(0, int(max_retries))
        self._circuit_failures = 0
        self._circuit_open_until = 0.0
        self._circuit_threshold = 3
        self._circuit_reset_seconds = 30.0
        self._owns_client = http_client is None
        self._http = http_client or httpx.AsyncClient(
            timeout=httpx.Timeout(timeout, connect=connect_timeout),
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
            follow_redirects=False,
        )

    async def solve(self, url: str) -> CloudflareCookieResult:
        if time.monotonic() < self._circuit_open_until:
            raise CloudflareProviderUnavailableError("Playwright provider circuit is open")
        try:
            result = await self._solve_with_retry(url)
        except CloudflareCookieProviderError as exc:
            self._circuit_failures += 1
            if isinstance(exc, CloudflareProviderAuthenticationError):
                self._circuit_open_until = time.monotonic() + self._circuit_reset_seconds
            elif self._circuit_failures >= self._circuit_threshold:
                self._circuit_open_until = time.monotonic() + self._circuit_reset_seconds
            raise
        self._circuit_failures = 0
        self._circuit_open_until = 0.0
        return result

    @property
    def circuit_state(self) -> str:
        return "open" if time.monotonic() < self._circuit_open_until else "closed"

    async def _solve_with_retry(self, url: str) -> CloudflareCookieResult:
        correlation_id = httpx.Request("GET", url).headers.get("x-request-id")
        for attempt in range(self._max_retries + 1):
            try:
                response = await self._http.post(
                    self._endpoint,
                    json={"url": url},
                    headers={
                        "Authorization": f"Bearer {self._token}",
                        "Accept": "application/json",
                        **({"X-Correlation-ID": correlation_id} if correlation_id else {}),
                    },
                )
            except httpx.TimeoutException as exc:
                error: CloudflareCookieProviderError = CloudflareProviderTimeoutError(
                    "Playwright service timed out"
                )
                if attempt < self._max_retries:
                    await asyncio.sleep(min(0.25 * 2**attempt, 1.0))
                    continue
                raise error from exc
            except httpx.TransportError as exc:
                error = CloudflareProviderUnavailableError("Playwright service is unavailable")
                if attempt < self._max_retries:
                    await asyncio.sleep(min(0.25 * 2**attempt, 1.0))
                    continue
                raise error from exc

            if response.status_code in {401, 403}:
                raise CloudflareProviderAuthenticationError(
                    "Playwright service rejected credentials"
                )
            if response.status_code in {400, 404, 409, 422}:
                raise CloudflareProviderValidationError("Playwright service rejected the request")
            if response.status_code in {408, 504}:
                error = CloudflareProviderTimeoutError("Playwright solve timed out")
            elif response.status_code in {429, 502, 503}:
                error = CloudflareProviderUnavailableError(
                    "Playwright service is temporarily unavailable"
                )
            elif response.status_code != 200:
                raise CloudflareProviderProtocolError(
                    "Playwright service returned an unexpected status"
                )
            else:
                content = response.content
                if len(content) > self._max_response_bytes:
                    raise CloudflareProviderProtocolError(
                        "Playwright response exceeded the size limit"
                    )
                try:
                    payload = response.json()
                except ValueError as exc:
                    raise CloudflareProviderProtocolError(
                        "Playwright service returned invalid JSON"
                    ) from exc
                return self._parse_result(payload, requested_url=url)
            if attempt < self._max_retries:
                await asyncio.sleep(min(0.25 * 2**attempt, 1.0))
                continue
            raise error
        raise CloudflareProviderUnavailableError("Playwright service is unavailable")

    async def aclose(self) -> None:
        if self._owns_client:
            await self._http.aclose()

    @classmethod
    def _parse_result(
        cls, payload: Any, *, requested_url: str | None = None
    ) -> CloudflareCookieResult:
        if not isinstance(payload, dict) or set(payload) - {
            "cookies",
            "userAgent",
            "expiresAt",
            "schemaVersion",
            "requestId",
            "finalOrigin",
            "solveDurationMs",
        }:
            raise CloudflareProviderProtocolError("Playwright service returned an invalid object")
        raw_cookies = payload.get("cookies")
        if not isinstance(raw_cookies, list) or not raw_cookies:
            raise CloudflareClearanceNotIssuedError("Playwright service returned no cookies")
        if len(raw_cookies) > 100:
            raise CloudflareProviderProtocolError("Playwright service returned too many cookies")
        user_agent = payload.get("userAgent")
        if (
            not isinstance(user_agent, str)
            or not user_agent.strip()
            or len(user_agent) > 1024
            or any(ord(char) < 0x20 or ord(char) == 0x7F for char in user_agent)
            or "mozilla/" not in user_agent.lower()
        ):
            raise CloudflareProviderProtocolError(
                "Playwright service returned an invalid userAgent"
            )
        host = (urlparse(requested_url).hostname or "").lower() if requested_url else None
        parsed_cookies = tuple(cls._parse_cookie(item, requested_host=host) for item in raw_cookies)
        now = time.time()
        cookies = tuple(
            cookie
            for cookie in parsed_cookies
            if cookie.expires_at is None or cookie.expires_at > now
        )
        header_size = sum(len(item.name) + len(item.value) + 2 for item in cookies)
        if header_size > 65_536:
            raise CloudflareProviderProtocolError("Playwright cookies exceed the header size limit")
        if not any(cookie.name == "cf_clearance" for cookie in cookies):
            raise CloudflareClearanceNotIssuedError("Playwright service did not issue clearance")
        return CloudflareCookieResult(
            cookies=cookies,
            user_agent=user_agent.strip(),
            expires_at=cls._parse_expiry(payload.get("expiresAt")),
        )

    @classmethod
    def _parse_cookie(cls, raw: Any, *, requested_host: str | None = None) -> CloudflareCookie:
        if not isinstance(raw, dict):
            raise CloudflareProviderProtocolError("Playwright service returned an invalid cookie")
        allowed = {
            "name",
            "value",
            "domain",
            "path",
            "expires",
            "expiresAt",
            "secure",
            "httpOnly",
            "sameSite",
        }
        if set(raw) - allowed:
            raise CloudflareProviderProtocolError("Playwright cookie contained unknown fields")
        name, value = raw.get("name"), raw.get("value")
        raw_domain = str(raw.get("domain") or "").lower().rstrip(".")
        host_only = not raw_domain.startswith(".")
        domain = raw_domain.lstrip(".")
        path = str(raw.get("path") or "/")
        if not isinstance(name, str) or not _COOKIE_NAME_RE.fullmatch(name) or len(name) > 256:
            raise CloudflareProviderProtocolError(
                "Playwright service returned an invalid cookie name"
            )
        if (
            not isinstance(value, str)
            or len(value.encode()) > 8192
            or any(c in value for c in "\r\n\0")
        ):
            raise CloudflareProviderProtocolError(
                "Playwright service returned an invalid cookie value"
            )
        if not _DOMAIN_RE.fullmatch(domain) or domain in _DEFAULT_PUBLIC_SUFFIXES:
            raise CloudflareProviderProtocolError(
                "Playwright service returned an invalid cookie domain"
            )
        if requested_host and (
            not _domain_matches(requested_host, domain) or (host_only and requested_host != domain)
        ):
            raise CloudflareProviderProtocolError(
                "Playwright cookie domain is outside the requested host"
            )
        if not path.startswith("/") or any(c in path for c in "\r\n;"):
            raise CloudflareProviderProtocolError(
                "Playwright service returned an invalid cookie path"
            )
        for field in ("secure", "httpOnly"):
            if field in raw and not isinstance(raw[field], bool):
                raise CloudflareProviderProtocolError(
                    "Playwright service returned invalid cookie flags"
                )
        same_site = raw.get("sameSite")
        if isinstance(same_site, str):
            same_site = {"strict": "Strict", "lax": "Lax", "none": "None"}.get(same_site.lower())
        if same_site not in {None, "Strict", "Lax", "None"}:
            raise CloudflareProviderProtocolError("Playwright service returned invalid SameSite")
        return CloudflareCookie(
            name=name,
            value=value,
            domain=domain,
            path=path,
            expires_at=cls._parse_expiry(raw.get("expiresAt", raw.get("expires"))),
            secure=raw.get("secure", True),
            http_only=raw.get("httpOnly", True),
            same_site=same_site,
            host_only=host_only,
        )

    @staticmethod
    def _parse_expiry(raw: Any) -> float | None:
        if raw in (None, "", -1, -1.0):
            return None
        if isinstance(raw, bool):
            raise CloudflareProviderProtocolError("Playwright service returned an invalid expiry")
        try:
            value = float(raw)
        except (TypeError, ValueError) as exc:
            raise CloudflareProviderProtocolError(
                "Playwright service returned an invalid expiry"
            ) from exc
        if not math.isfinite(value) or value <= 0:
            raise CloudflareProviderProtocolError("Playwright service returned an invalid expiry")
        value = value / 1000.0 if value > 100_000_000_000 else value
        if value > 32_503_680_000:  # year 3000
            raise CloudflareProviderProtocolError(
                "Playwright service returned an implausible expiry"
            )
        return value


@dataclass(frozen=True)
class CloudflareSession:
    origin: str
    cookies: tuple[CloudflareCookie, ...]
    user_agent: str
    created_at: float
    expires_at: float
    last_used_at: float
    egress_identity: str
    generation: int


class CloudflareSessionStore:
    def __init__(
        self,
        default_ttl_seconds: int = 2700,
        *,
        expiry_skew_seconds: int = 15,
        max_ttl_seconds: int = 86400,
        max_entries: int = 1000,
        clock: Callable[[], float] = time.time,
    ):
        if not 1 <= default_ttl_seconds <= max_ttl_seconds:
            raise ValueError("default TTL must be between 1 and max TTL")
        self._default_ttl = int(default_ttl_seconds)
        self._skew = max(0, int(expiry_skew_seconds))
        self._max_ttl = int(max_ttl_seconds)
        self._max_entries = max(1, int(max_entries))
        self._clock = clock
        self._sessions: OrderedDict[str, CloudflareSession] = OrderedDict()
        self._generations: dict[str, int] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _host(url_or_host: str) -> str:
        parsed = urlparse(url_or_host)
        return (parsed.hostname or url_or_host).lower().lstrip(".")

    def _key(self, url: str, egress_identity: str) -> str:
        if "://" not in url:
            url = "https://" + url
        return _origin_key(url, egress_identity)

    def get(self, url_or_host: str, *, egress_identity: str = "direct") -> CloudflareSession | None:
        key = self._key(url_or_host, egress_identity)
        now = self._clock()
        with self._lock:
            session = self._sessions.get(key)
            if session is None:
                metrics.increment("cf_clearance_cache_misses_total")
                return None
            if now >= session.expires_at:
                self._sessions.pop(key, None)
                metrics.increment("cf_clearance_cache_misses_total")
                return None
            metrics.increment("cf_clearance_cache_hits_total")
            session = replace(session, last_used_at=now)
            self._sessions[key] = session
            self._sessions.move_to_end(key)
            return session

    def generation(self, url_or_host: str, *, egress_identity: str = "direct") -> int:
        key = self._key(url_or_host, egress_identity)
        with self._lock:
            return self._generations.get(key, 0)

    def set(
        self, url: str, result: CloudflareCookieResult, *, egress_identity: str = "direct"
    ) -> CloudflareSession:
        now = self._clock()
        future = [c.expires_at for c in result.cookies if c.expires_at and c.expires_at > now]
        clearance = next(
            (
                c.expires_at
                for c in result.cookies
                if c.name == "cf_clearance" and c.expires_at and c.expires_at > now
            ),
            None,
        )
        candidate = result.expires_at if result.expires_at and result.expires_at > now else None
        candidate = candidate or clearance or (min(future) if future else now + self._default_ttl)
        ttl = candidate - now
        if ttl > self._max_ttl:
            candidate = now + self._max_ttl
        expires_at = candidate - self._skew
        if expires_at <= now:
            raise CloudflareProviderValidationError("Clearance expires before the safety margin")
        key = self._key(url, egress_identity)
        origin = key.split("|", 1)[0]
        with self._lock:
            generation = self._generations.get(key, 0) + 1
            self._generations[key] = generation
            session = CloudflareSession(
                origin,
                tuple(result.cookies),
                result.user_agent,
                now,
                expires_at,
                now,
                egress_identity,
                generation,
            )
            self._sessions[key] = session
            self._sessions.move_to_end(key)
            while len(self._sessions) > self._max_entries:
                self._sessions.popitem(last=False)
            return session

    def clear(self, url_or_host: str | None = None, *, egress_identity: str = "direct") -> None:
        with self._lock:
            if url_or_host is None:
                self._sessions.clear()
            else:
                self._sessions.pop(self._key(url_or_host, egress_identity), None)

    def __len__(self) -> int:
        with self._lock:
            return len(self._sessions)

    def cookies_for_url(
        self, url: str, *, egress_identity: str = "direct"
    ) -> tuple[CloudflareCookie, ...]:
        session = self.get(url, egress_identity=egress_identity)
        if session is None:
            return ()
        parsed, now = urlparse(url), self._clock()
        host, path = (parsed.hostname or "").lower(), parsed.path or "/"
        output = [
            cookie
            for cookie in session.cookies
            if _domain_matches(host, cookie.domain)
            and (not cookie.host_only or host == cookie.domain)
            and (not cookie.secure or parsed.scheme == "https")
            and (cookie.expires_at is None or cookie.expires_at > now)
            and (
                path == cookie.path
                or cookie.path == "/"
                or path.startswith(cookie.path.rstrip("/") + "/")
            )
        ]
        output.sort(key=lambda item: len(item.path), reverse=True)
        return tuple(output)


class CloudflareCookieCoordinator:
    def __init__(
        self,
        provider: CloudflareCookieProvider,
        store: CloudflareSessionStore,
        *,
        cooldown_seconds: float = 30,
        negative_cache_seconds: float = 10,
        egress_identity: str = "direct",
        clock: Callable[[], float] = time.monotonic,
    ):
        self.provider, self.store = provider, store
        self._cooldown = max(0.0, cooldown_seconds)
        self._negative_ttl = max(0.0, negative_cache_seconds)
        self._egress = egress_identity
        self._clock = clock
        self._state_lock = asyncio.Lock()
        self._inflight: dict[str, asyncio.Task[CloudflareSession]] = {}
        self._last_started: dict[str, float] = {}
        self._negative: dict[str, tuple[float, CloudflareCookieProviderError]] = {}

    @property
    def inflight_count(self) -> int:
        return len(self._inflight)

    async def refresh(self, url: str, *, observed_generation: int) -> CloudflareSession:
        key = _origin_key(url, self._egress)
        current = self.store.get(url, egress_identity=self._egress)
        if current is not None and current.generation > observed_generation:
            return current
        async with self._state_lock:
            now = self._clock()
            negative = self._negative.get(key)
            if negative and negative[0] > now:
                raise negative[1]
            self._negative.pop(key, None)
            task = self._inflight.get(key)
            if task is None:
                last = self._last_started.get(key)
                if last is not None and now - last < self._cooldown:
                    raise CloudflareProviderUnavailableError("Clearance solve is cooling down")
                self._last_started[key] = now
                task = asyncio.create_task(self._run(key, url, observed_generation))
                self._inflight[key] = task
                metrics.increment("cf_provider_owners")
            else:
                metrics.increment("cf_provider_waiters")
        return await asyncio.shield(task)

    async def _run(self, key: str, url: str, observed_generation: int) -> CloudflareSession:
        try:
            current = self.store.get(url, egress_identity=self._egress)
            if current is not None and current.generation > observed_generation:
                return current
            metrics.increment("cf_provider_calls")
            result = await self.provider.solve(url)
            session = self.store.set(url, result, egress_identity=self._egress)
            metrics.increment("cf_provider_success")
            return session
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            metrics.increment("cf_provider_errors")
            safe = (
                exc
                if isinstance(exc, CloudflareCookieProviderError)
                else CloudflareProviderUnavailableError("Clearance solve failed")
            )
            async with self._state_lock:
                self._negative[key] = (self._clock() + self._negative_ttl, safe)
            if safe is exc:
                raise
            raise safe from exc
        finally:
            async with self._state_lock:
                if self._inflight.get(key) is asyncio.current_task():
                    self._inflight.pop(key, None)

    async def aclose(self) -> None:
        async with self._state_lock:
            tasks = tuple(self._inflight.values())
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        close = getattr(self.provider, "aclose", None)
        if close is not None:
            result = close()
            if inspect.isawaitable(result):
                await result
