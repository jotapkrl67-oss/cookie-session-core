from __future__ import annotations

import asyncio
import logging
import re
import time
import uuid
from collections.abc import AsyncIterable, Iterable
from contextlib import suppress as _suppress_ctx
from dataclasses import dataclass
from typing import Any, TYPE_CHECKING
from urllib.parse import urlparse

import httpx
from curl_cffi.requests import AsyncSession as CurlAsyncSession

if TYPE_CHECKING:
    from .config import Settings
    from .cloudflare_solver import CloudflareSolverOrchestrator

logger = logging.getLogger("cookie_session_core.browser_client")


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


def _has_any_cf_header(headers: Any) -> bool:
    get_header = getattr(headers, "get", None)
    if not callable(get_header):
        return False
    server = str(get_header("server", "") or "").lower()
    if "cloudflare" in server:
        return True
    items = getattr(headers, "items", None)
    if callable(items):
        header_names = {str(k).lower() for k, _v in items()}
    else:
        header_names = set()
        for name in (
            "cf-ray",
            "cf-request-id",
            "cf-cache-status",
            "cf-mitigated",
            "cf-connecting-ip",
        ):
            if get_header(name, ""):
                return True
        return False
    return any(name.startswith("cf-") for name in header_names)


def _looks_like_cloudflare_challenge(
    status: int, body: bytes | None, headers: Any
) -> bool:
    """Detect both Cloudflare Managed Challenges (HTML interstitial) AND
    403/429/503 responses produced by the Cloudflare edge / WAF / Bot Mgmt
    that ship without the classic <form id=challenge-form> body markers.

    A 429 coming from behind Cloudflare on an origin-protected hostname is
    treated the same as a managed challenge for orchestration purposes:
    it triggers TLS-fingerprint rotation and, if a third-party solver is
    configured, a fresh clearance solve before giving up.
    """
    if status not in (403, 503, 429):
        return False
    get_header = getattr(headers, "get", None)
    if callable(get_header):
        mitigated = get_header("cf-mitigated", "") or ""
        if str(mitigated).lower() == "challenge":
            return True
        server = str(get_header("server", "") or "").lower()
        if "cloudflare" in server:
            if body and any(m in body for m in _CF_BODY_MARKERS):
                return True
            if status == 429 and _has_any_cf_header(headers):
                return True
            if status == 403 and any(
                header in {str(k).lower() for k, _v in headers.items()}
                if hasattr(headers, "items")
                else bool(get_header(header))
                for header in _CF_HEADER_MARKER_NAMES
            ):
                return True
    if body and any(m in body for m in _CF_BODY_MARKERS):
        return True
    return False


def _looks_like_transient_upstream(status: int, headers: Any, *, reason: object = None) -> bool:
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
    return False


def _parse_retry_after(headers: Any) -> float | None:
    get_header = getattr(headers, "get", None)
    if not callable(get_header):
        return None
    value = str(get_header("retry-after") or "").strip()
    if not value:
        return None
    if value.isdigit():
        try:
            seconds = int(value)
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
        except Exception:
            pass
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
                raise TypeError(
                    f"Unsupported async body chunk: {type(chunk).__name__!r}"
                )
        return bytes(out)
    if isinstance(body, Iterable):
        return _coerce_bytes_body(body)
    raise TypeError(f"Unsupported HTTP body type: {type(body).__name__!r}")


def _clear_set_cookie_duplicates(raw_list: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for raw in raw_list:
        m = re.match(r"\s*([^=;]+)=([^;]*)", raw)
        key = (m.group(1).lower() + "=" + m.group(2)) if m else raw
        if key in seen:
            continue
        seen.add(key)
        out.append(raw)
    return out


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


class BrowserLikeClient:
    """
    HTTP client with:
      * curl_cffi TLS impersonation (defaults to Chrome 124) so the TLS/JA3
        fingerprint matches a real browser.
      * Automatic, lossless materialization of async request bodies
        (``request.stream()`` generators) before passing bytes to curl_cffi,
        so ``httpx.RequestNotRead`` / 500-causing errors can never occur
        between the reverse_proxy stream=True path and the transport.
      * ``cf_clearance`` cache keyed by host. Any ``Set-Cookie`` containing
        ``cf_clearance=...`` from any response is extracted and reused on
        every subsequent request to the same domain.
      * **Optional third-party challenge solving** (CapSolver, AntiCaptcha,
        YesCaptcha, 2Captcha, custom endpoint) triggered automatically when a
        Cloudflare challenge page is detected. This runs entirely over pure
        HTTP APIs — no browser, no Playwright, no JS runtime in this process.
        If a provider is configured and solving succeeds, the resulting
        ``cf_clearance`` is placed into the cache and the original request is
        transparently retried.
      * **TLS impersonation profile rotation** across a configured list.
        When a challenge is seen and the current profile keeps failing, the
        client silently switches to the next impersonation target (e.g.
        chrome124 → chrome120 → safari17_2_ios) between solve attempts.
    """

    def __init__(
        self,
        *,
        impersonate: str = "chrome124",
        timeout: float = 60.0,
        max_connections: int = 100,
        clearance_ttl_seconds: int = 2700,
        settings: "Settings | None" = None,
    ):
        self.impersonate = impersonate
        self.timeout = float(timeout)
        self._curl: CurlAsyncSession | None = None
        self._httpx_fallback: httpx.AsyncClient | None = None
        self._curl_lock = asyncio.Lock()
        self.clearance = ClearanceCache(ttl_seconds=clearance_ttl_seconds)
        self._max_connections = max(1, int(max_connections))
        self._settings = settings
        self._solver: "CloudflareSolverOrchestrator | None" = None
        self._solver_lock = asyncio.Lock()
        self._impersonation_rotation: list[str] | None = None
        self._rotation_idx: int = 0
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
                    impersonate=self.impersonate,
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

    async def close(self) -> None:
        await self.aclose()

    async def _get_solver(self) -> "CloudflareSolverOrchestrator | None":
        if self._settings is None:
            return None
        from .config import CfSolverProvider

        provider = getattr(self._settings, "cf_solver_provider", CfSolverProvider.NONE)
        api_key = getattr(self._settings, "cf_solver_api_key", "") or ""
        if provider == CfSolverProvider.NONE:
            return None
        if provider != CfSolverProvider.CUSTOM and not api_key:
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

    def _rotate_oai_headers(self, request: httpx.Request) -> bool:
        if not _has_oai_headers(request.headers):
            return False
        new_device_id = _generate_uuid4()
        new_session_id = _generate_uuid4()
        for existing_key in list(request.headers.keys()):
            lk = existing_key.lower()
            if lk in ("oai-device-id", "oai-session-id"):
                del request.headers[existing_key]
        request.headers["oai-device-id"] = new_device_id
        request.headers["oai-session-id"] = new_session_id
        for ck in ("Cookie", "cookie"):
            existing_cookie = request.headers.get(ck)
            if existing_cookie:
                updated = _sync_oai_did_cookie(existing_cookie, new_device_id)
                del request.headers[ck]
                request.headers["Cookie"] = updated
                break
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
        assert self._curl is not None
        curl_args = self._prepare_curl_request(request, body_bytes=materialized_body)
        sent_headers: dict[str, str] = dict(curl_args.get("headers", {}) or {})
        try:
            curl_resp = await self._curl.request(**curl_args)
        except httpx.HTTPError:
            raise
        except Exception as exc:
            logger.warning("curl_cffi transport failed, fallback to httpx: %s", exc)
            assert self._httpx_fallback is not None
            fallback_request = self.build_request(
                request.method,
                str(request.url),
                headers=dict(request.headers.items()),
                content=materialized_body,
            )
            try:
                fallback_resp = await self._httpx_fallback.send(
                    fallback_request, stream=False
                )
            except Exception as exc2:
                logger.error("httpx fallback also failed: %s", exc2)
                raise httpx.TransportError(
                    f"Upstream transport failed: {exc}; fallback failed: {exc2}"
                ) from exc2
            return fallback_resp, sent_headers, domain
        try:
            self._extract_clearance(curl_resp, domain)
        except Exception:
            pass
        resp = self._build_httpx_response(
            curl_resp,
            request_method=request.method,
            request_url=str(request.url),
            request_headers=sent_headers,
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
            for key, value in curl_headers.items():
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
            "Could not materialize request body: not bytes, sync iterable, "
            "or async iterable."
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
            if lk.startswith(":"):
                continue
            headers[key] = value
            if lk == "accept-encoding":
                has_accept_encoding = True
            if lk == "oai-device-id":
                oai_device_id = value

        parsed = urlparse(str(request.url))
        domain = parsed.hostname or ""
        clearance = self.clearance.get(domain)
        if clearance:
            existing = headers.get("Cookie") or headers.get("cookie") or ""
            token = f"cf_clearance={clearance}"
            headers["Cookie"] = f"{existing}; {token}" if existing else token

        if oai_device_id is not None:
            cookie_keys_to_check: list[str] = [
                k for k in ("Cookie", "cookie") if k in headers
            ]
            if cookie_keys_to_check:
                ck = cookie_keys_to_check[0]
                existing_cookie = headers[ck]
                if ck != "Cookie":
                    del headers[ck]
                else:
                    del headers["Cookie"]
                headers["Cookie"] = _sync_oai_did_cookie(existing_cookie, oai_device_id)

        curl_args: dict[str, Any] = {
            "method": request.method,
            "url": str(request.url),
            "headers": headers,
            "timeout": self.timeout,
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
    ) -> httpx.Response:
        headers = self._headers_to_httpx(curl_resp.headers)

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
                    new_headers = []
                    wrote_cookies = False
                    for k, v in headers.items():
                        if k.lower() == "set-cookie":
                            if wrote_cookies:
                                continue
                            continue
                        new_headers.append((k, v))
                    rebuilt = httpx.Headers(new_headers)
                    for raw in deduped:
                        raw_value = raw
                        try:
                            rebuilt = rebuilt.add("set-cookie", raw_value)
                        except Exception:
                            pass
                    headers = rebuilt
        except Exception:
            pass

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
                self.clearance.set(domain, value, ttl=ttl)
                logger.info("cf_clearance cached for %s (ttl=%ss)", domain, ttl)

    async def send(
        self,
        request: httpx.Request,
        *,
        stream: bool = False,
        **kwargs: Any,
    ) -> httpx.Response:
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

        base_attempts = 3
        rotation_extra = (
            len(self._impersonation_rotation)
            if self._impersonation_rotation and len(self._impersonation_rotation) > 1
            else 0
        )
        max_attempts = base_attempts + rotation_extra
        last_resp: httpx.Response | None = None
        last_exc: BaseException | None = None
        clearance_was_used = False
        url_str = str(request.url)
        domain = (urlparse(url_str).hostname or "").lower()

        for attempt in range(max_attempts):
            if attempt > 0:
                self._rotate_oai_headers(request)
                existing = self.clearance.get(domain)
                if existing and not clearance_was_used:
                    clearance_was_used = True
                else:
                    rotated = await self._rotate_impersonation()
                    if not rotated and attempt >= base_attempts:
                        break

            try:
                resp, _sent_headers, _dom = await self._send_once(
                    request, stream=stream, materialized_body=body_bytes
                )
            except (httpx.TransportError, httpx.HTTPError, OSError) as exc:
                last_exc = exc
                backoff = min(0.8 * (2**attempt), 6.0)
                logger.info(
                    "Upstream transport error on %s (%s) — backoff=%.1fs "
                    "attempt=%s/%s impersonate=%s",
                    url_str,
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
            body_for_check = resp.content or b""

            is_challenge = _looks_like_cloudflare_challenge(
                status, body_for_check, resp.headers
            )
            is_cf_429 = (
                status == 429 and _has_any_cf_header(resp.headers)
            )
            is_transient = _looks_like_transient_upstream(status, resp.headers)
            has_oai = _has_oai_headers(request.headers)
            is_oai_429 = has_oai and status == 429
            is_oai_5xx = has_oai and status in (500, 502, 520)
            if not (is_challenge or is_cf_429 or is_transient or is_oai_429 or is_oai_5xx):
                return resp

            retry_after = _parse_retry_after(resp.headers)
            backoff: float = 0.0
            if retry_after is not None:
                backoff = retry_after
                logger.info(
                    "Upstream Retry-After=%.1fs on %s (status=%s) attempt=%s/%s",
                    backoff,
                    url_str,
                    status,
                    attempt + 1,
                    max_attempts,
                )
            elif status == 429:
                backoff = min(1.2 * (2**attempt), 10.0)
                if has_oai:
                    logger.info(
                        "OpenAI 429 Too Many Requests on %s — rotating oai-* ids, "
                        "backoff=%.1fs attempt=%s/%s impersonate=%s",
                        url_str,
                        backoff,
                        attempt + 1,
                        max_attempts,
                        self.impersonate,
                    )
                else:
                    logger.info(
                        "429 Too Many Requests on %s — backoff=%.1fs "
                        "attempt=%s/%s impersonate=%s",
                        url_str,
                        backoff,
                        attempt + 1,
                        max_attempts,
                        self.impersonate,
                    )
            elif is_transient or is_oai_5xx:
                backoff = min(0.8 * (2**attempt), 6.0)
                if has_oai and status in (500, 502, 520):
                    logger.info(
                        "OpenAI upstream status=%s on %s — rotating oai-* ids, "
                        "backoff=%.1fs attempt=%s/%s impersonate=%s",
                        status,
                        url_str,
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
                        url_str,
                        backoff,
                        attempt + 1,
                        max_attempts,
                        self.impersonate,
                    )
            if is_challenge:
                logger.info(
                    "Cloudflare challenge detected on %s (status=%s) "
                    "attempt=%s/%s impersonate=%s",
                    url_str,
                    status,
                    attempt + 1,
                    max_attempts,
                    self.impersonate,
                )

            if backoff > 0 and attempt < max_attempts - 1:
                await asyncio.sleep(backoff)

            solver = await self._get_solver()
            should_solve = is_challenge or (
                is_cf_429 and solver is not None and attempt >= 1
            )
            if should_solve and solver is not None:
                try:
                    solve_result = await solver.try_solve(
                        url_str,
                        status,
                        body_for_check,
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
                            url_str,
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
                            body2 = resp2.content or b""
                            still_blocked = (
                                _looks_like_cloudflare_challenge(
                                    status2, body2, resp2.headers
                                )
                                or (status2 == 429 and _has_any_cf_header(resp2.headers))
                                or _looks_like_transient_upstream(status2, resp2.headers)
                                or (_has_oai_headers(request.headers) and status2 == 429)
                                or (_has_oai_headers(request.headers) and status2 in (500, 502, 520))
                            )
                            if not still_blocked:
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
        body_last = last_resp.content or b""
        has_oai_final = _has_oai_headers(request.headers)
        if (
            _looks_like_cloudflare_challenge(
                status, body_last, last_resp.headers
            )
            or (status == 429 and _has_any_cf_header(last_resp.headers))
            or _looks_like_transient_upstream(status, last_resp.headers)
            or (has_oai_final and status == 429)
            or (has_oai_final and status in (500, 502, 520))
        ):
            logger.info(
                "Cloudflare challenge/429/transient persists on %s after %s attempt(s) "
                "impersonate=%s. Delegating to reverse_proxy relaying / fallback path.",
                url_str,
                max_attempts,
                self.impersonate,
            )

        return last_resp
