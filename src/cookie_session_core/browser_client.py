from __future__ import annotations

import asyncio
import json
import logging
import re
import secrets
import time
import uuid
from collections import OrderedDict
from collections.abc import AsyncIterable, Iterable
from contextlib import suppress as _suppress_ctx
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import urlparse

import httpx
from curl_cffi.requests import AsyncSession as CurlAsyncSession

from .cloudflare_detection import (
    UpstreamClassification,
    classify_upstream_response,
    has_cloudflare_headers,
)
from .cloudflare_provider import (
    CloudflareCookieCoordinator,
    CloudflareCookieProvider,
    CloudflareCookieProviderError,
    CloudflareSessionStore,
)
from .metrics import metrics
from .redaction import install_redaction

if TYPE_CHECKING:
    from .cloudflare_solver import CloudflareSolverOrchestrator
    from .config import Settings

logger = logging.getLogger("cookie_session_core.browser_client")
install_redaction(logger)
_JITTER_RANDOM = secrets.SystemRandom()


_CF_BODY_MARKERS = (
    b"_cf_chl_opt",
    b"cdn-cgi/challenge-platform",
    b"cf-turnstile",
    b"_cf_chl_form",
    b"window.__cf",
    b"jschl_vc",
    b"jschl_answer",
)

_CF_HEADER_MARKER_NAMES = (
    "cf-ray",
    "cf-request-id",
    "cf-cache-status",
)

_TRANSIENT_ERROR_RE = re.compile(
    r"(?:something\s+went\s+wrong|unable\s+to\s+process|rate\s*limit|too\s+many\s+requests)",
    re.IGNORECASE,
)

_CF_HARD_CHALLENGE_DOMAINS: tuple[str, ...] = (
    ".perplexity.ai",
    "perplexity.ai",
    ".pplx.ai",
    "pplx.ai",
)

_PERPLEXITY_LONG_TIMEOUT_PATHS = (
    "/ask",
    "/search",
    "/api/chat",
    "/api/search",
    "/api/ask",
    "/backend-api/conversation",
    "/backend-api/chat",
)

_PERPLEXITY_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/128.0.0.0 Safari/537.36"
)


def _is_hard_protection_domain(domain: str) -> bool:
    d = domain.lower().lstrip(".")
    for suffix in _CF_HARD_CHALLENGE_DOMAINS:
        s = suffix.lower().lstrip(".")
        if d == s or d.endswith("." + s):
            return True
    return False


def _has_any_cf_header(headers: Any) -> bool:
    return has_cloudflare_headers(headers)


def _looks_like_cloudflare_challenge(
    status: int,
    body: bytes | None,
    headers: Any,
    *,
    inspection_limit_bytes: int = 262_144,
) -> bool:
    """Detect both Cloudflare Managed Challenges (HTML interstitial) AND
    403/429/503 responses produced by the Cloudflare edge / WAF / Bot Mgmt
    that ship without the classic <form id=challenge-form> body markers.

    A 429 coming from behind Cloudflare on an origin-protected hostname is
    treated the same as a managed challenge for orchestration purposes:
    it triggers TLS-fingerprint rotation and, if a third-party solver is
    configured, a fresh clearance solve before giving up.
    """
    return (
        classify_upstream_response(
            status, headers, body, inspection_limit_bytes=inspection_limit_bytes
        ).classification
        == UpstreamClassification.CLOUDFLARE_CHALLENGE
    )


def _looks_like_cloudflare_response(status: int, headers: Any) -> bool:
    return status in (403, 429, 503) and _has_any_cf_header(headers)


def _looks_like_transient_upstream(
    status: int,
    headers: Any,
    body: bytes | None = None,
    *,
    reason: object = None,
) -> bool:
    """Matches Cloudflare-originated 502/503/504 (bad gateway / origin
    errors) and generic upstream failures that are worth retrying with a
    different fingerprint or after a short backoff.

    Errors 502/503/504 coming from the upstream's own response are also
    treated as transient; `reason` lets callers tag plain transport errors
    (connect timeouts, TLS resets, DNS blips) the same way.
    """
    if reason is True:
        return True
    if status in (502, 503, 504):
        return True
    if status in (520, 521, 522, 523, 524, 525, 526, 527) and _has_any_cf_header(headers):
        return True
    if status in (403, 500, 502) and body:
        text = body[:256_000].decode("utf-8", errors="replace")
        if _TRANSIENT_ERROR_RE.search(text):
            return True
        try:
            payload = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            payload = None
        if isinstance(payload, dict) and "error" in payload:
            error = payload["error"]
            message = error.get("message", "") if isinstance(error, dict) else str(error)
            if _TRANSIENT_ERROR_RE.search(str(message)):
                return True
    return False


def _is_sse_request(request: httpx.Request) -> bool:
    accept = request.headers.get("accept", "").lower()
    path = request.url.path.rstrip("/").lower()
    if "text/event-stream" in accept:
        return True
    return (
        request.method.upper() == "POST"
        and "*/*" in accept
        and ("/f/conversation" in path or path.endswith("/conversation"))
    )


def _is_streaming_request(request: httpx.Request) -> bool:
    """Detect responses which must reach the browser incrementally.

    Gemini uses a streamed protobuf transport rather than SSE, while media
    players such as ElevenLabs commonly use byte ranges or audio/video Accept
    headers. Buffering those responses either stalls the UI or breaks playback.
    """
    if _is_sse_request(request):
        return True
    if request.headers.get("range"):
        return True
    accept = request.headers.get("accept", "").lower()
    if any(media in accept for media in ("audio/", "video/")):
        return True
    path = request.url.path.rstrip("/").lower()
    if any(
        marker in path
        for marker in (
            "/streamgenerate",
            "/stream-generate",
            "/stream_generate",
            "/stream-input",
            "/stream_input",
            "/stream/",
        )
    ) or path.endswith("/stream"):
        return True
    return path.endswith(
        (
            ".aac",
            ".flac",
            ".m4a",
            ".mp3",
            ".mp4",
            ".oga",
            ".ogg",
            ".opus",
            ".wav",
            ".webm",
        )
    )


def _retry_backoff(base: float, attempt: int, maximum: float) -> float:
    value = min(base * (2**attempt), maximum)
    return max(0.0, value * _JITTER_RANDOM.uniform(0.8, 1.2))


def _parse_retry_after(headers: Any) -> float | None:
    get_header = getattr(headers, "get", None)
    if not callable(get_header):
        return None
    value = str(get_header("retry-after") or "").strip()
    if not value:
        for alt in (
            "x-rate-limit-reset",
            "x-ratelimit-reset",
            "rate-limit-reset",
            "x-http-rate-limit-reset",
        ):
            alt_value = str(get_header(alt) or "").strip()
            if alt_value:
                value = alt_value
                break
    if not value:
        return None
    if value.isdigit():
        try:
            seconds = int(value)
            import time as _t

            if seconds > 1_000_000_000_000:
                seconds = seconds // 1000
            if seconds > 1_000_000_000:
                delta = float(seconds) - _t.time()
                return float(max(1, min(delta, 300))) if delta > 0 else 1.0
            return float(max(1, min(seconds, 300)))
        except ValueError:
            pass
    try:
        seconds = float(value)
        return float(max(1, min(seconds, 300)))
    except ValueError:
        pass
    from email.utils import parsedate_to_datetime

    try:
        then = parsedate_to_datetime(value)
        now = getattr(then.__class__, "now", None)
        if now and hasattr(then, "timestamp"):
            import time as _t

            delta = then.timestamp() - _t.time()
            if delta > 0:
                return float(min(delta, 300.0))
    except Exception:
        return None
    return None


@dataclass
class _ClearanceRecord:
    value: str
    expires_at: float


@dataclass
class _OaiSessionState:
    stable_device_id: str
    current_session_id: str
    request_count: int = 0
    consecutive_failures: int = 0
    last_success_at: float = 0.0
    last_rotated_at: float = 0.0


class ClearanceCache:
    def __init__(self, ttl_seconds: int = 2700):
        self._ttl = ttl_seconds
        self._data: dict[str, _ClearanceRecord] = {}

    def get(self, domain: str) -> str | None:
        key = domain.lower().lstrip(".")
        item = self._data.get(key)
        if item is None:
            return None
        if time.time() > item.expires_at:
            self._data.pop(key, None)
            return None
        return item.value

    def set(self, domain: str, value: str, ttl: int | None = None) -> None:
        key = domain.lower().lstrip(".")
        used_ttl = ttl if ttl and ttl > 0 else self._ttl
        self._data[key] = _ClearanceRecord(
            value=value,
            expires_at=time.time() + used_ttl,
        )

    def clear(self, domain: str | None = None) -> None:
        if domain is None:
            self._data.clear()
        else:
            self._data.pop(domain.lower().lstrip("."), None)


class _CurlResponseStream(httpx.AsyncByteStream):
    def __init__(self, response: Any):
        self.response = response

    async def __aiter__(self):
        async for chunk in self.response.aiter_content():
            yield chunk

    async def aclose(self) -> None:
        await self.response.aclose()


def _coerce_bytes_body(body: Any) -> bytes:
    if body is None:
        return b""
    if isinstance(body, (bytes, bytearray, memoryview)):
        return bytes(body)
    if isinstance(body, str):
        return body.encode("utf-8")
    if isinstance(body, Iterable) and not isinstance(body, (str, AsyncIterable)):
        out = bytearray()
        try:
            for chunk in body:
                if chunk is None:
                    continue
                if isinstance(chunk, (bytes, bytearray, memoryview)):
                    out += bytes(chunk)
                elif isinstance(chunk, str):
                    out += chunk.encode("utf-8")
                else:
                    raise TypeError
            return bytes(out)
        except Exception as exc:
            logger.debug("Could not coerce iterable request body: %s", type(exc).__name__)
    raise TypeError(
        f"Unsupported HTTP body type: {type(body).__name__!r}. "
        f"Must be bytes/str/or a sync iterable of chunks; async streams must be "
        f"materialized before sending."
    )


async def _materialize_async_body(body: Any) -> bytes:
    if body is None:
        return b""
    if isinstance(body, (bytes, bytearray, memoryview)):
        return bytes(body)
    if isinstance(body, str):
        return body.encode("utf-8")
    if isinstance(body, AsyncIterable):
        out = bytearray()
        async for chunk in body:
            if chunk is None:
                continue
            if isinstance(chunk, (bytes, bytearray, memoryview)):
                out += bytes(chunk)
            elif isinstance(chunk, str):
                out += chunk.encode("utf-8")
            else:
                raise TypeError(f"Unsupported async body chunk: {type(chunk).__name__!r}")
        return bytes(out)
    if isinstance(body, Iterable):
        return _coerce_bytes_body(body)
    raise TypeError(f"Unsupported HTTP body type: {type(body).__name__!r}")


def _clear_set_cookie_duplicates(raw_list: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for raw in raw_list:
        # Only byte-equivalent duplicates are redundant. Two cookies with the
        # same name/value but different Path or Domain are distinct RFC 6265
        # records and must both reach the vault.
        key = raw
        if key in seen:
            continue
        seen.add(key)
        out.append(raw)
    return out


def _merge_cookie_header(existing: str, replacements: list[tuple[str, str]]) -> str:
    replacement_names = {name for name, _value in replacements}
    parts = []
    for raw in existing.split(";"):
        item = raw.strip()
        if not item or "=" not in item:
            continue
        name = item.split("=", 1)[0].strip()
        if name not in replacement_names:
            parts.append(item)
    parts.extend(f"{name}={value}" for name, value in replacements)
    return "; ".join(parts)


def _replace_header(headers: dict[str, str], name: str, value: str) -> None:
    for key in list(headers):
        if key.lower() == name.lower():
            headers.pop(key)
    headers[name] = value


def _generate_uuid4() -> str:
    return str(uuid.uuid4())


def _has_oai_headers(headers: Any) -> bool:
    get_header = getattr(headers, "get", None)
    if callable(get_header):
        if get_header("oai-device-id") or get_header("Oai-Device-Id"):
            return True
        if get_header("oai-session-id") or get_header("Oai-Session-Id"):
            return True
    items = getattr(headers, "items", None)
    if callable(items):
        for k, _v in items():
            if str(k).lower().startswith("oai-"):
                return True
    return False


_OAI_DID_COOKIE_SUFFIXES = ("_oai-did", "-oai-did")


def _sync_oai_did_cookie(cookie_header: str, new_device_id: str) -> str:
    parts = [p.strip() for p in cookie_header.split(";") if p.strip()]
    updated: list[str] = []
    replaced = False
    for part in parts:
        if "=" not in part:
            updated.append(part)
            continue
        name, value = part.split("=", 1)
        if any(name.endswith(suffix) for suffix in _OAI_DID_COOKIE_SUFFIXES):
            updated.append(f"{name}={new_device_id}")
            replaced = True
        else:
            updated.append(part)
    result = "; ".join(updated)
    if not replaced and result:
        result = result + f"; __Secure-oai-did={new_device_id}"
    elif not replaced:
        result = f"__Secure-oai-did={new_device_id}"
    return result


def _has_oai_sentinel_headers(headers: Any) -> bool:
    items = getattr(headers, "items", None)
    if callable(items):
        for k, _v in items():
            if str(k).lower().startswith("openai-sentinel-"):
                return True
    get_header = getattr(headers, "get", None)
    if callable(get_header):
        for prefix in (
            "openai-sentinel-chat-requirements-token",
            "openai-sentinel-proof-token",
            "openai-sentinel-turnstile-token",
        ):
            if get_header(prefix) or get_header(prefix.title()):
                return True
    return False


class BrowserLikeClient:
    """TLS-impersonating HTTP client with OAI and Cloudflare resilience."""

    def __init__(
        self,
        *,
        impersonate: str = "chrome124",
        timeout: float = 60.0,
        max_connections: int = 100,
        clearance_ttl_seconds: int = 2700,
        settings: "Settings | None" = None,
        cloudflare_cookie_provider: CloudflareCookieProvider | None = None,
    ):
        self.impersonate = impersonate
        self.timeout = float(timeout)
        self._curl: CurlAsyncSession | None = None
        self._httpx_fallback: httpx.AsyncClient | None = None
        self._curl_lock = asyncio.Lock()
        self.clearance = ClearanceCache(ttl_seconds=clearance_ttl_seconds)
        self.cloudflare_sessions = CloudflareSessionStore(
            default_ttl_seconds=(
                settings.cf_clearance_default_ttl_seconds if settings else clearance_ttl_seconds
            ),
            expiry_skew_seconds=(settings.cf_clearance_expiry_skew_seconds if settings else 15),
            max_ttl_seconds=(settings.cf_clearance_max_ttl_seconds if settings else 86400),
            max_entries=(settings.cf_clearance_store_max_entries if settings else 1000),
        )
        self._cookie_coordinator = (
            CloudflareCookieCoordinator(
                cloudflare_cookie_provider,
                self.cloudflare_sessions,
                cooldown_seconds=(settings.cf_solve_cooldown_seconds if settings else 30),
                negative_cache_seconds=(
                    settings.cf_solve_negative_cache_seconds if settings else 10
                ),
            )
            if cloudflare_cookie_provider is not None
            else None
        )
        self._max_connections = max(1, int(max_connections))
        self._settings = settings
        self._solver: "CloudflareSolverOrchestrator | None" = None
        self._solver_lock = asyncio.Lock()
        self._impersonation_rotation: list[str] | None = None
        self._rotation_idx: int = 0
        self._oai_sessions: OrderedDict[tuple[str, str], _OaiSessionState] = OrderedDict()
        self._oai_cache_limit = 1024
        if settings is not None:
            targets = list(getattr(settings, "cf_solver_impersonate_targets", []) or [])
            if targets:
                if impersonate not in targets:
                    targets.insert(0, impersonate)
                self._impersonation_rotation = targets
                try:
                    self._rotation_idx = targets.index(impersonate)
                except ValueError:
                    self._rotation_idx = 0

    async def _ensure_sessions(self) -> None:
        async with self._curl_lock:
            if self._curl is None:
                self._curl = CurlAsyncSession(
                    impersonate=cast(Any, self.impersonate),
                    timeout=self.timeout,
                    allow_redirects=False,
                    verify=True,
                    max_clients=max(1, self._max_connections // 4),
                )
            if self._httpx_fallback is None:
                self._httpx_fallback = httpx.AsyncClient(
                    follow_redirects=False,
                    http2=True,
                    timeout=httpx.Timeout(self.timeout),
                    limits=httpx.Limits(
                        max_connections=self._max_connections,
                        max_keepalive_connections=20,
                    ),
                )

    async def aclose(self) -> None:
        async with self._curl_lock:
            if self._curl is not None:
                with _suppress_ctx(Exception):
                    await self._curl.close()
                self._curl = None
            if self._httpx_fallback is not None:
                with _suppress_ctx(Exception):
                    await self._httpx_fallback.aclose()
                self._httpx_fallback = None
        async with self._solver_lock:
            if self._solver is not None:
                with _suppress_ctx(Exception):
                    await self._solver.aclose()
                self._solver = None
        if self._cookie_coordinator is not None:
            with _suppress_ctx(Exception):
                await self._cookie_coordinator.aclose()

    async def close(self) -> None:
        await self.aclose()

    async def _get_solver(self) -> "CloudflareSolverOrchestrator | None":
        if self._settings is None:
            return None
        providers = self._settings.solver_provider_list
        if not providers:
            return None
        async with self._solver_lock:
            if self._solver is None:
                from .cloudflare_solver import CloudflareSolverOrchestrator

                self._solver = CloudflareSolverOrchestrator(self._settings, self.clearance)
            return self._solver

    async def _rotate_impersonation(self) -> bool:
        if not self._impersonation_rotation or len(self._impersonation_rotation) < 2:
            return False
        self._rotation_idx = (self._rotation_idx + 1) % len(self._impersonation_rotation)
        new_target = self._impersonation_rotation[self._rotation_idx]
        if new_target == self.impersonate:
            return False
        logger.info(
            "Cloudflare challenge — rotating TLS impersonation: %s -> %s",
            self.impersonate,
            new_target,
        )
        self.impersonate = new_target
        async with self._curl_lock:
            if self._curl is not None:
                with _suppress_ctx(Exception):
                    await self._curl.close()
                self._curl = None
        return True

    def _oai_cache_key(self, request: httpx.Request) -> tuple[str, str]:
        user_id = str(request.extensions.get("cookie_core_user_id") or "anonymous")
        host = (request.url.host or "").lower()
        return user_id, host

    @staticmethod
    def _replace_oai_headers(request: httpx.Request, device_id: str, session_id: str) -> None:
        for existing_key in list(request.headers.keys()):
            if existing_key.lower() in ("oai-device-id", "oai-session-id"):
                del request.headers[existing_key]
        request.headers["oai-device-id"] = device_id
        request.headers["oai-session-id"] = session_id
        existing_cookie = request.headers.get("cookie")
        if existing_cookie:
            request.headers["Cookie"] = _sync_oai_did_cookie(existing_cookie, device_id)

    def _apply_oai_session(self, request: httpx.Request) -> None:
        if not _has_oai_headers(request.headers) or _has_oai_sentinel_headers(request.headers):
            return
        key = self._oai_cache_key(request)
        state = self._oai_sessions.get(key)
        if state is None:
            state = _OaiSessionState(
                stable_device_id=request.headers.get("oai-device-id") or _generate_uuid4(),
                current_session_id=request.headers.get("oai-session-id") or _generate_uuid4(),
            )
            self._oai_sessions[key] = state
            if len(self._oai_sessions) > self._oai_cache_limit:
                self._oai_sessions.popitem(last=False)
        else:
            self._oai_sessions.move_to_end(key)
        state.request_count += 1
        if state.request_count % 3 == 0:
            state.current_session_id = _generate_uuid4()
        self._replace_oai_headers(request, state.stable_device_id, state.current_session_id)

    def _record_oai_result(self, request: httpx.Request, status: int) -> bool:
        if not _has_oai_headers(request.headers) or _has_oai_sentinel_headers(request.headers):
            return False
        state = self._oai_sessions.get(self._oai_cache_key(request))
        if state is None:
            return False
        if status < 400:
            state.consecutive_failures = 0
            state.last_success_at = time.monotonic()
            return False
        if status in (429, 502):
            state.consecutive_failures += 1
            return state.consecutive_failures >= 2
        state.consecutive_failures = 0
        return False

    def _rotate_oai_headers(self, request: httpx.Request) -> bool:
        if not _has_oai_headers(request.headers):
            return False
        if _has_oai_sentinel_headers(request.headers):
            metrics.increment("oai_sentinel_skipped_rotations")
            logger.info(
                "OpenAI — skipping oai-device-id/session-id rotation: request carries "
                "openai-sentinel-* tokens which are cryptographically bound to the "
                "current oai-device-id. Rotating would invalidate signatures."
            )
            return False
        state = self._oai_sessions.get(self._oai_cache_key(request))
        new_device_id = _generate_uuid4()
        new_session_id = _generate_uuid4()
        if state is not None:
            state.stable_device_id = new_device_id
            state.current_session_id = new_session_id
            state.consecutive_failures = 0
            state.last_rotated_at = time.monotonic()
        self._replace_oai_headers(request, new_device_id, new_session_id)
        metrics.increment("oai_id_rotations_total")
        logger.info(
            "OpenAI 502/429 — rotating oai headers: device/session refreshed. "
            "new_device_id=%s new_session_id=%s",
            new_device_id[:8] + "...",
            new_session_id[:8] + "...",
        )
        return True

    async def _send_once(
        self,
        request: httpx.Request,
        *,
        stream: bool = False,
        materialized_body: bytes,
    ) -> tuple[httpx.Response, dict[str, str], str]:
        await self._ensure_sessions()
        domain = (urlparse(str(request.url)).hostname or "").lower()
        curl_session = self._curl
        if curl_session is None:
            raise httpx.TransportError("curl transport was not initialized")
        curl_args = self._prepare_curl_request(request, body_bytes=materialized_body)
        use_stream = stream and _is_streaming_request(request)
        if use_stream:
            curl_args["stream"] = True
        sent_headers: dict[str, str] = dict(curl_args.get("headers", {}) or {})
        try:
            curl_resp = await curl_session.request(**curl_args)
        except httpx.HTTPError:
            raise
        except Exception as exc:
            logger.warning("curl_cffi transport failed, fallback to httpx: %s", exc)
            fallback = self._httpx_fallback
            if fallback is None:
                raise httpx.TransportError("HTTP fallback transport was not initialized") from exc
            fallback_request = self.build_request(
                request.method,
                str(request.url),
                headers=sent_headers,
                content=materialized_body,
            )
            try:
                fallback_resp = await fallback.send(fallback_request, stream=use_stream)
            except Exception as exc2:
                logger.error("httpx fallback also failed: %s", exc2)
                raise httpx.TransportError(
                    f"Upstream transport failed: {exc}; fallback failed: {exc2}"
                ) from exc2
            return fallback_resp, sent_headers, domain
        try:
            self._extract_clearance(curl_resp, domain)
        except Exception as exc:
            logger.debug("Could not extract Cloudflare clearance: %s", type(exc).__name__)
        resp = self._build_httpx_response(
            curl_resp,
            request_method=request.method,
            request_url=str(request.url),
            request_headers=sent_headers,
            stream=use_stream,
        )
        return resp, sent_headers, domain

    def build_request(
        self,
        method: str,
        url: str,
        *,
        headers: Any = None,
        content: Any = None,
        data: Any = None,
        files: Any = None,
        json: Any = None,
        params: Any = None,
        cookies: Any = None,
        **kwargs: Any,
    ) -> httpx.Request:
        return httpx.Request(
            method=method,
            url=url,
            headers=headers,
            content=content,
            data=data,
            files=files,
            json=json,
            params=params,
            cookies=cookies,
            **kwargs,
        )

    @staticmethod
    def _headers_to_httpx(curl_headers: Any) -> httpx.Headers:
        raw_items: list[tuple[str, str]] = []
        try:
            source = (
                curl_headers.multi_items()
                if callable(getattr(curl_headers, "multi_items", None))
                else curl_headers.items()
            )
            for key, value in source:
                if isinstance(value, list):
                    for v in value:
                        raw_items.append((str(key), str(v)))
                else:
                    raw_items.append((str(key), str(value)))
        except Exception:
            try:
                raw_items = list(dict(curl_headers.items()).items())
            except Exception:
                raw_items = []
        return httpx.Headers(raw_items)

    @staticmethod
    def _get_request_stream(request: httpx.Request):
        stream_attr = getattr(request, "stream", None)
        if stream_attr is None:
            return None
        if callable(stream_attr):
            try:
                return stream_attr()
            except Exception:
                return None
        return stream_attr

    async def _materialize_request_body(self, request: httpx.Request) -> bytes:
        sync_body: Any = None
        try:
            sync_body = request.content
        except httpx.RequestNotRead:
            sync_body = None
        except Exception:
            sync_body = None
        if sync_body is not None:
            try:
                return _coerce_bytes_body(sync_body)
            except TypeError:
                pass

        raw_stream = self._get_request_stream(request)
        if isinstance(raw_stream, AsyncIterable):
            return await _materialize_async_body(raw_stream)
        if isinstance(raw_stream, Iterable):
            return _coerce_bytes_body(raw_stream)

        content_attr = getattr(request, "_content", None)
        if content_attr is not None:
            try:
                return _coerce_bytes_body(content_attr)
            except TypeError:
                pass

        raise TypeError(
            "Could not materialize request body: not bytes, sync iterable, or async iterable."
        )

    def _prepare_curl_request(
        self,
        request: httpx.Request,
        *,
        body_bytes: bytes,
    ) -> dict[str, Any]:
        headers: dict[str, str] = {}
        has_accept_encoding = False
        oai_device_id: str | None = None
        for key, value in request.headers.items():
            lk = key.lower()
            if lk.startswith(":") or lk == "x-force-oai-rotate":
                continue
            headers[key] = value
            if lk == "accept-encoding":
                has_accept_encoding = True
            if lk == "oai-device-id":
                oai_device_id = value

        parsed = urlparse(str(request.url))
        domain = parsed.hostname or ""
        clearance = self.clearance.get(domain)
        provider_cookies = self.cloudflare_sessions.cookies_for_url(str(request.url))
        replacements = [(cookie.name, cookie.value) for cookie in provider_cookies]
        if clearance and not any(name == "cf_clearance" for name, _value in replacements):
            replacements.insert(0, ("cf_clearance", clearance))
        if replacements:
            existing = headers.get("Cookie") or headers.get("cookie") or ""
            _replace_header(headers, "Cookie", _merge_cookie_header(existing, replacements))
        provider_session = self.cloudflare_sessions.get(str(request.url))
        if provider_session is not None:
            _replace_header(headers, "User-Agent", provider_session.user_agent)

        if oai_device_id is not None:
            cookie_keys_to_check: list[str] = [k for k in ("Cookie", "cookie") if k in headers]
            if cookie_keys_to_check:
                ck = cookie_keys_to_check[0]
                existing_cookie = headers[ck]
                if ck != "Cookie":
                    del headers[ck]
                else:
                    del headers["Cookie"]
                headers["Cookie"] = _sync_oai_did_cookie(existing_cookie, oai_device_id)

        path = parsed.path.rstrip("/").lower()
        timeout = float(request.extensions.get("cookie_core_timeout") or self.timeout)
        domain_for_check = domain.lower().lstrip(".")
        is_perplexity_domain = _is_hard_protection_domain(domain_for_check)

        if is_perplexity_domain:
            ua_missing = "user-agent" not in {k.lower() for k in headers}
            if ua_missing:
                headers["User-Agent"] = _PERPLEXITY_USER_AGENT
            sec_ch_ua_present = any(k.lower().startswith("sec-ch-ua") for k in headers)
            if not sec_ch_ua_present:
                headers["Sec-CH-UA"] = (
                    '"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"'
                )
                headers["Sec-CH-UA-Mobile"] = "?0"
                headers["Sec-CH-UA-Platform"] = '"Windows"'
            accept_language_missing = "accept-language" not in {k.lower() for k in headers}
            if accept_language_missing:
                headers["Accept-Language"] = "en-US,en;q=0.9"
            priority_missing = "priority" not in {k.lower() for k in headers}
            if priority_missing and request.method.upper() in ("GET", "HEAD"):
                headers["Priority"] = "u=0, i"
        if request.method.upper() == "POST" and path.endswith("/f/conversation"):
            timeout = 600.0
        elif request.method.upper() == "GET" and path.endswith("/conversations"):
            timeout = 30.0
        elif request.method.upper() == "POST" and path.endswith(
            "/sentinel/chat-requirements/finalize"
        ):
            timeout = 20.0
        elif "/cdn-cgi/challenge-platform/" in path:
            timeout = 120.0
        elif is_perplexity_domain:
            for pp in _PERPLEXITY_LONG_TIMEOUT_PATHS:
                if path == pp.rstrip("/").lower() or path.endswith(pp.lower()):
                    if request.method.upper() == "POST":
                        timeout = 300.0
                    else:
                        timeout = 60.0
                    break
        curl_args: dict[str, Any] = {
            "method": request.method,
            "url": str(request.url),
            "headers": headers,
            "timeout": timeout,
        }
        if not has_accept_encoding:
            curl_args["accept_encoding"] = "gzip, deflate, br, zstd"
        if body_bytes:
            curl_args["data"] = body_bytes
        return curl_args

    def _build_httpx_response(
        self,
        curl_resp: Any,
        *,
        request_method: str,
        request_url: str,
        request_headers: dict[str, str] | None = None,
        stream: bool = False,
    ) -> httpx.Response:
        headers = self._headers_to_httpx(curl_resp.headers)

        if stream:
            fake_request = httpx.Request(
                request_method,
                request_url,
                headers=dict(request_headers) if request_headers else None,
            )
            return httpx.Response(
                status_code=curl_resp.status_code,
                headers=headers,
                stream=_CurlResponseStream(curl_resp),
                request=fake_request,
            )

        content = getattr(curl_resp, "content", None) or b""
        if not isinstance(content, (bytes, bytearray, memoryview)):
            content = b""
        content = bytes(content)

        decompressed_by_curl = "content-encoding" in {
            k.lower() for k in dict(headers).keys()
        } and not bool(content.startswith(b"\x1f\x8b") or content[:2] == b"\x1f\x8b")
        if decompressed_by_curl and len(content) > 0:
            has_magic_gzip = content[:2] == b"\x1f\x8b"
            has_magic_brotli = content[:4] == b"\xce\xb2\xcf\x81"
            has_magic_zstd = content[:4] in (
                b"\x28\xb5\x2f\xfd",
                b"\x2c\xb5\x2f\xfd",
            )
            if not (has_magic_gzip or has_magic_brotli or has_magic_zstd):
                new_headers: list[tuple[str, str]] = []
                enc_removed = False
                for k, v in headers.items():
                    if k.lower() == "content-encoding" and not enc_removed:
                        enc_removed = True
                        continue
                    if k.lower() == "content-length":
                        new_headers.append((k, str(len(content))))
                    else:
                        new_headers.append((k, v))
                headers = httpx.Headers(new_headers)

        try:
            set_cookies = headers.get_list("set-cookie")
            if set_cookies:
                deduped = _clear_set_cookie_duplicates(set_cookies)
                if deduped != set_cookies:
                    new_headers = [
                        (key, value)
                        for key, value in headers.multi_items()
                        if key.lower() != "set-cookie"
                    ]
                    new_headers.extend(("set-cookie", raw) for raw in deduped)
                    headers = httpx.Headers(new_headers)
        except Exception as exc:
            logger.debug("Could not normalize repeated response cookies: %s", type(exc).__name__)

        encoding = getattr(curl_resp, "encoding", None) or "utf-8"
        fake_request = httpx.Request(
            request_method,
            request_url,
            headers=dict(request_headers) if request_headers else None,
        )
        response = httpx.Response(
            status_code=curl_resp.status_code,
            headers=headers,
            content=content,
            request=fake_request,
            default_encoding=encoding,
        )
        response._content = content
        return response

    def _extract_clearance(self, curl_resp: Any, domain: str) -> None:
        try:
            items = list(curl_resp.headers.items())
        except Exception:
            return
        for k, v in items:
            if str(k).lower() != "set-cookie":
                continue
            values = v if isinstance(v, (list, tuple)) else [v]
            for raw in values:
                raw_s = str(raw)
                if "cf_clearance=" not in raw_s:
                    continue
                m = re.search(r"cf_clearance=([^;\s]+)", raw_s)
                if not m:
                    continue
                value = m.group(1)
                ttl = 1800
                mm = re.search(r"max-age=(\d+)", raw_s, flags=re.IGNORECASE)
                if mm:
                    try:
                        ttl = int(mm.group(1))
                    except ValueError:
                        ttl = 1800
                else:
                    expires = re.search(r"expires=([^;]+)", raw_s, flags=re.IGNORECASE)
                    if expires:
                        from email.utils import parsedate_to_datetime

                        try:
                            ttl = max(
                                1,
                                int(
                                    parsedate_to_datetime(expires.group(1).strip()).timestamp()
                                    - time.time()
                                    - 30
                                ),
                            )
                        except (TypeError, ValueError, OverflowError):
                            ttl = 1800
                self.clearance.set(domain, value, ttl=ttl)
                logger.info("cf_clearance cached for %s (ttl=%ss)", domain, ttl)

    async def send(
        self,
        request: httpx.Request,
        *,
        stream: bool = False,
        **kwargs: Any,
    ) -> httpx.Response:
        req_id = str(uuid.uuid4())
        started_at = time.monotonic()
        force_oai_rotate = request.headers.get("x-force-oai-rotate") == "1"
        if "x-force-oai-rotate" in request.headers:
            del request.headers["x-force-oai-rotate"]
        self._apply_oai_session(request)
        if force_oai_rotate:
            self._rotate_oai_headers(request)
        is_streaming = _is_streaming_request(request)
        try:
            body_bytes = await self._materialize_request_body(request)
        except (httpx.RequestNotRead, TypeError) as exc:
            logger.error(
                "Failed to materialize request body for %s %s: %s",
                request.method,
                request.url,
                exc,
            )
            raise httpx.StreamError(str(exc)) from exc
        replay_limit = (
            self._settings.cf_request_replay_buffer_limit_bytes
            if self._settings is not None
            else 2_000_000
        )
        method = request.method.upper()
        request_replayable = (
            method in {"GET", "HEAD", "OPTIONS"}
            or not body_bytes
            or bool(request.headers.get("idempotency-key"))
        ) and len(body_bytes) <= replay_limit
        inspection_limit = (
            self._settings.cf_challenge_body_inspection_limit_bytes
            if self._settings is not None
            else 262_144
        )

        url_str = str(request.url)
        parsed_url = urlparse(url_str)
        domain = (parsed_url.hostname or "").lower()
        display_host = f"[{domain}]" if ":" in domain else domain
        display_port = f":{parsed_url.port}" if parsed_url.port else ""
        log_url = f"{parsed_url.scheme}://{display_host}{display_port}{parsed_url.path or '/'}"
        hard_domain = _is_hard_protection_domain(domain)
        base_attempts = 5 if hard_domain else 3
        rotation_extra = (
            len(self._impersonation_rotation)
            if self._impersonation_rotation and len(self._impersonation_rotation) > 1
            else 0
        )
        if hard_domain:
            rotation_extra = max(rotation_extra, len(self._impersonation_rotation or []))
        max_attempts = base_attempts + rotation_extra
        last_resp: httpx.Response | None = None
        last_exc: BaseException | None = None
        clearance_was_used = False
        rotate_oai_next = False
        saw_managed_challenge = False
        observed_provider_generation = self.cloudflare_sessions.generation(url_str)
        provider_refresh_attempted = False

        for attempt in range(max_attempts):
            if attempt > 0:
                metrics.increment("retries_total")
                if rotate_oai_next:
                    self._rotate_oai_headers(request)
                    rotate_oai_next = False
                existing = self.clearance.get(domain)
                if existing and not clearance_was_used:
                    clearance_was_used = True
                else:
                    force_rotate = saw_managed_challenge or (
                        last_resp is not None and _has_any_cf_header(last_resp.headers)
                    )
                    if force_rotate:
                        rotated = await self._rotate_impersonation()
                        if not rotated and attempt >= base_attempts:
                            if hard_domain and attempt < max_attempts - 1:
                                pass
                            else:
                                break
                    elif attempt >= base_attempts and not hard_domain:
                        break

            try:
                resp, _sent_headers, _dom = await self._send_once(
                    request, stream=stream, materialized_body=body_bytes
                )
            except (httpx.TransportError, httpx.HTTPError, OSError) as exc:
                last_exc = exc
                backoff = _retry_backoff(0.8, attempt, 6.0)
                logger.info(
                    "Upstream transport error on %s (%s) — backoff=%.1fs "
                    "attempt=%s/%s impersonate=%s",
                    log_url,
                    type(exc).__name__,
                    backoff,
                    attempt + 1,
                    max_attempts,
                    self.impersonate,
                )
                if attempt < max_attempts - 1:
                    await asyncio.sleep(backoff)
                continue

            last_resp = resp

            status = resp.status_code
            if status == 502:
                metrics.increment("responses_502_total")
            elif status == 429:
                metrics.increment("responses_429_total")
            body_for_check = None if is_streaming else (resp.content or b"")

            is_challenge = _looks_like_cloudflare_challenge(
                status,
                body_for_check,
                resp.headers,
                inspection_limit_bytes=inspection_limit,
            )
            mitigated_hdr = str(
                getattr(resp.headers, "get", lambda _k: "")("cf-mitigated") or ""
            ).lower()
            is_managed_challenge = mitigated_hdr == "challenge"
            if is_managed_challenge and not saw_managed_challenge:
                saw_managed_challenge = True
            is_cf_429 = status == 429 and _has_any_cf_header(resp.headers)
            is_transient = _looks_like_transient_upstream(status, resp.headers, body_for_check)
            has_oai = _has_oai_headers(request.headers)
            is_oai_429 = has_oai and status == 429
            is_oai_5xx = has_oai and status in (500, 502, 520)
            is_any_429 = status == 429
            if not (
                is_challenge or is_cf_429 or is_transient or is_oai_429 or is_oai_5xx or is_any_429
            ):
                self._record_oai_result(request, status)
                logger.info(
                    "request_complete req_id=%s upstream=%s attempt=%s status=%s dur_ms=%s",
                    req_id,
                    domain,
                    attempt + 1,
                    status,
                    int((time.monotonic() - started_at) * 1000),
                )
                return resp

            if not request_replayable:
                metrics.increment("cf_replay_rejected_total")
                await resp.aclose()
                raise httpx.StreamError(
                    "Upstream retry was blocked because the request is not safely replayable"
                )

            rotate_oai_next = self._record_oai_result(request, status)

            retry_after = _parse_retry_after(resp.headers)
            backoff: float = 0.0
            has_oai_sentinel = has_oai and _has_oai_sentinel_headers(request.headers)
            if retry_after is not None:
                backoff = retry_after
                logger.info(
                    "Upstream Retry-After=%.1fs on %s (status=%s) attempt=%s/%s",
                    backoff,
                    log_url,
                    status,
                    attempt + 1,
                    max_attempts,
                )
            elif status == 429:
                metrics.increment("cf_rate_limited_total")
                backoff = _retry_backoff(1.2, attempt, 15.0 if hard_domain else 10.0)
                if has_oai:
                    if has_oai_sentinel:
                        logger.info(
                            "OpenAI 429 on %s (sentinel-bound) — backoff=%.1fs "
                            "(oai-* ids NOT rotated; would invalidate openai-sentinel-* "
                            "signatures) attempt=%s/%s impersonate=%s",
                            log_url,
                            backoff,
                            attempt + 1,
                            max_attempts,
                            self.impersonate,
                        )
                    else:
                        logger.info(
                            "OpenAI 429 Too Many Requests on %s — rotating oai-* ids, "
                            "backoff=%.1fs attempt=%s/%s impersonate=%s",
                            log_url,
                            backoff,
                            attempt + 1,
                            max_attempts,
                            self.impersonate,
                        )
                else:
                    logger.info(
                        "429 Too Many Requests on %s — backoff=%.1fs attempt=%s/%s impersonate=%s",
                        log_url,
                        backoff,
                        attempt + 1,
                        max_attempts,
                        self.impersonate,
                    )
            elif is_managed_challenge:
                backoff = _retry_backoff(2.0, attempt, 12.0 if hard_domain else 8.0)
                logger.info(
                    "Cloudflare MANAGED CHALLENGE on %s (domain=%s hard=%s ray=%s) — "
                    "backoff=%.1fs attempt=%s/%s impersonate=%s",
                    log_url,
                    domain,
                    hard_domain,
                    str(getattr(resp.headers, "get", lambda _k: "")("cf-ray") or ""),
                    backoff,
                    attempt + 1,
                    max_attempts,
                    self.impersonate,
                )
            elif is_transient or is_oai_5xx:
                backoff = _retry_backoff(0.8, attempt, 8.0 if hard_domain else 6.0)
                if has_oai and status in (500, 502, 520):
                    if has_oai_sentinel:
                        logger.info(
                            "OpenAI upstream status=%s on %s (sentinel-bound, e.g. "
                            "/backend-api/f/conversation or sentinel/finalize) — "
                            "backoff=%.1fs (oai-* ids preserved) attempt=%s/%s "
                            "impersonate=%s",
                            status,
                            log_url,
                            backoff,
                            attempt + 1,
                            max_attempts,
                            self.impersonate,
                        )
                    else:
                        logger.info(
                            "OpenAI upstream status=%s on %s — rotating oai-* ids, "
                            "backoff=%.1fs attempt=%s/%s impersonate=%s",
                            status,
                            log_url,
                            backoff,
                            attempt + 1,
                            max_attempts,
                            self.impersonate,
                        )
                else:
                    logger.info(
                        "Transient upstream status=%s on %s — backoff=%.1fs "
                        "attempt=%s/%s impersonate=%s",
                        status,
                        log_url,
                        backoff,
                        attempt + 1,
                        max_attempts,
                        self.impersonate,
                    )
            if is_challenge or is_managed_challenge:
                metrics.increment("cf_challenges_seen")
                if not is_managed_challenge:
                    logger.info(
                        "Cloudflare challenge detected on %s (status=%s) attempt=%s/%s impersonate=%s",
                        log_url,
                        status,
                        attempt + 1,
                        max_attempts,
                        self.impersonate,
                    )

            if is_streaming and attempt < max_attempts - 1:
                await resp.aclose()
            if backoff > 0 and attempt < max_attempts - 1:
                await asyncio.sleep(backoff)

            should_refresh_cookies = is_challenge or is_managed_challenge
            if (
                should_refresh_cookies
                and self._cookie_coordinator is not None
                and not provider_refresh_attempted
            ):
                provider_refresh_attempted = True
                try:
                    session = await self._cookie_coordinator.refresh(
                        log_url,
                        observed_generation=observed_provider_generation,
                    )
                except Exception as exc:
                    detail = (
                        str(exc)
                        if isinstance(exc, CloudflareCookieProviderError)
                        else "Clearance solve failed"
                    )
                    logger.warning(
                        "Cloudflare cookie provider failed domain=%s category=%s detail=%s",
                        domain,
                        type(exc).__name__,
                        detail,
                    )
                else:
                    observed_provider_generation = session.generation
                    clearance_cookie = next(
                        (cookie for cookie in session.cookies if cookie.name == "cf_clearance"),
                        None,
                    )
                    if clearance_cookie is not None:
                        ttl = max(1, int(session.expires_at - time.time()))
                        self.clearance.set(domain, clearance_cookie.value, ttl=ttl)
                    logger.info(
                        "Cloudflare cookies refreshed — replaying %s %s",
                        request.method,
                        log_url,
                    )
                    try:
                        provider_resp, _provider_headers, _provider_domain = await self._send_once(
                            request,
                            stream=stream,
                            materialized_body=body_bytes,
                        )
                    except (httpx.HTTPError, OSError) as provider_exc:
                        last_exc = provider_exc
                    else:
                        last_resp = provider_resp
                        provider_body = None if is_streaming else (provider_resp.content or b"")
                        provider_blocked = (
                            _looks_like_cloudflare_challenge(
                                provider_resp.status_code,
                                provider_body,
                                provider_resp.headers,
                                inspection_limit_bytes=inspection_limit,
                            )
                            or (
                                provider_resp.status_code == 429
                                and _has_any_cf_header(provider_resp.headers)
                            )
                            or _looks_like_transient_upstream(
                                provider_resp.status_code,
                                provider_resp.headers,
                                provider_body,
                            )
                            or provider_resp.status_code == 429
                        )
                        if not provider_blocked:
                            self._record_oai_result(request, provider_resp.status_code)
                            return provider_resp
                        if is_streaming:
                            await provider_resp.aclose()

            solver = await self._get_solver()
            should_solve = is_challenge or is_managed_challenge
            if should_solve and solver is not None:
                try:
                    solve_result = await solver.try_solve(
                        url_str,
                        status,
                        body_for_check or b"",
                        resp.headers,
                    )
                except Exception as exc:
                    logger.warning("Solver raised unexpectedly: %s", exc)
                    solve_result = None
                if solve_result is not None and solve_result.success:
                    if solve_result.cf_clearance or self.clearance.get(domain):
                        logger.info(
                            "Solver completed — replaying %s %s with cf_clearance",
                            request.method,
                            log_url,
                        )
                        try:
                            resp2, _sh, _d = await self._send_once(
                                request, stream=stream, materialized_body=body_bytes
                            )
                        except (httpx.HTTPError, OSError) as exc2:
                            last_exc = exc2
                        else:
                            last_resp = resp2
                            status2 = resp2.status_code
                            body2 = None if is_streaming else (resp2.content or b"")
                            still_blocked = (
                                _looks_like_cloudflare_challenge(
                                    status2,
                                    body2,
                                    resp2.headers,
                                    inspection_limit_bytes=inspection_limit,
                                )
                                or (status2 == 429 and _has_any_cf_header(resp2.headers))
                                or _looks_like_transient_upstream(status2, resp2.headers, body2)
                                or (_has_oai_headers(request.headers) and status2 == 429)
                                or (
                                    _has_oai_headers(request.headers) and status2 in (500, 502, 520)
                                )
                                or status2 == 429
                            )
                            if not still_blocked:
                                self._record_oai_result(request, status2)
                                return resp2

        if last_resp is None:
            if last_exc is not None and isinstance(last_exc, httpx.HTTPError):
                raise last_exc
            if last_exc is not None:
                raise httpx.TransportError(
                    f"Upstream transport failed after {max_attempts} attempts: {last_exc}"
                ) from last_exc
            raise httpx.TransportError("No response obtained from upstream transport")

        status = last_resp.status_code
        body_last = None if is_streaming else (last_resp.content or b"")
        has_oai_final = _has_oai_headers(request.headers)
        if (
            _looks_like_cloudflare_challenge(
                status,
                body_last,
                last_resp.headers,
                inspection_limit_bytes=inspection_limit,
            )
            or (status == 429 and _has_any_cf_header(last_resp.headers))
            or _looks_like_transient_upstream(status, last_resp.headers, body_last)
            or (has_oai_final and status == 429)
            or (has_oai_final and status in (500, 502, 520))
            or status == 429
        ):
            logger.info(
                "Cloudflare challenge/429/transient persists on %s after %s attempt(s) "
                "impersonate=%s. Delegating to reverse_proxy relaying / fallback path.",
                log_url,
                max_attempts,
                self.impersonate,
            )

        return last_resp
