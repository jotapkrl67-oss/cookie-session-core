from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from cookie_session_core.browser_client import (
    BrowserLikeClient,
    ClearanceCache,
    _looks_like_transient_upstream,
    _parse_retry_after,
)
from cookie_session_core.cloudflare_provider import CloudflareCookie, CloudflareCookieResult
from cookie_session_core.cloudflare_solver import (
    CfSolveResult,
    CloudflareSolverOrchestrator,
)
from cookie_session_core.config import CfSolverProvider


def _oai_request(path: str, **extra_headers: str) -> httpx.Request:
    headers = {
        "oai-device-id": "11111111-1111-4111-8111-111111111111",
        "oai-session-id": "22222222-2222-4222-8222-222222222222",
        **extra_headers,
    }
    return httpx.Request("GET", f"https://chatgpt.com{path}", headers=headers)


@pytest.mark.parametrize(
    "sentinel_header",
    [
        "openai-sentinel-chat-requirements-token",
        "openai-sentinel-proof-token",
        "openai-sentinel-turnstile-token",
    ],
)
def test_oai_rotation_skipped_with_sentinel_tokens(sentinel_header: str):
    client = BrowserLikeClient()
    request = _oai_request("/backend-api/f/conversation", **{sentinel_header: "signed-token"})
    original = request.headers["oai-device-id"]
    assert client._rotate_oai_headers(request) is False
    assert request.headers["oai-device-id"] == original


def test_oai_rotation_applied_without_sentinel():
    client = BrowserLikeClient()
    request = _oai_request("/backend-api/conversations")
    original = request.headers["oai-device-id"]
    assert client._rotate_oai_headers(request) is True
    assert request.headers["oai-device-id"] != original


def test_oai_device_rotates_only_after_two_consecutive_failures():
    client = BrowserLikeClient()
    request = _oai_request("/backend-api/conversations")
    client._apply_oai_session(request)
    stable = request.headers["oai-device-id"]
    assert client._record_oai_result(request, 502) is False
    assert client._record_oai_result(request, 502) is True
    client._rotate_oai_headers(request)
    assert request.headers["oai-device-id"] != stable


@pytest.mark.asyncio
async def test_sse_streaming_no_body_materialization():
    class StreamingResponse:
        status_code = 200
        headers = httpx.Headers({"content-type": "text/event-stream"})

        @property
        def content(self):
            raise AssertionError("SSE response body was materialized")

    client = BrowserLikeClient()
    client._send_once = AsyncMock(return_value=(StreamingResponse(), {}, "chatgpt.com"))
    request = httpx.Request(
        "POST",
        "https://chatgpt.com/backend-api/f/conversation",
        headers={"accept": "text/event-stream"},
        content=b"{}",
    )
    response = await client.send(request, stream=True)
    assert response.status_code == 200


def test_cloudflare_transient_detects_error_text():
    assert _looks_like_transient_upstream(
        502,
        httpx.Headers({"content-type": "application/json"}),
        b'{"error":{"message":"Something went wrong"}}',
    )
    assert _looks_like_transient_upstream(
        403,
        httpx.Headers({"content-type": "text/html"}),
        b"<h1>Unable to process this request</h1>",
    )


def test_request_specific_timeouts():
    client = BrowserLikeClient(timeout=60)
    cases = [
        ("POST", "/backend-api/f/conversation", 600.0),
        ("GET", "/backend-api/conversations", 30.0),
        ("POST", "/backend-api/sentinel/chat-requirements/finalize", 20.0),
        ("POST", "/cdn-cgi/challenge-platform/relay", 120.0),
    ]
    for method, path, expected in cases:
        request = httpx.Request(method, f"https://chatgpt.com{path}")
        assert client._prepare_curl_request(request, body_bytes=b"")["timeout"] == expected
    custom = httpx.Request("GET", "https://example.com/slow")
    custom.extensions["cookie_core_timeout"] = 145.0
    assert client._prepare_curl_request(custom, body_bytes=b"")["timeout"] == 145.0


def test_curl_header_conversion_preserves_repeated_values():
    class CurlHeaders:
        def multi_items(self):
            return [
                ("location", "https://first.example/"),
                ("location", "https://second.example/"),
            ]

    headers = BrowserLikeClient._headers_to_httpx(CurlHeaders())
    assert headers.get_list("location") == [
        "https://first.example/",
        "https://second.example/",
    ]


def test_response_keeps_distinct_scoped_cookies_while_deduplicating_exact_repeats():
    class CurlResponse:
        status_code = 200
        content = b"ok"
        encoding = "utf-8"
        headers = httpx.Headers(
            [
                ("content-type", "text/plain"),
                ("set-cookie", "session=same; Path=/"),
                ("set-cookie", "session=same; Path=/admin"),
                ("set-cookie", "session=same; Path=/"),
            ]
        )

    response = BrowserLikeClient()._build_httpx_response(
        CurlResponse(),
        request_method="GET",
        request_url="https://app.example.com/",
    )

    assert response.headers.get_list("set-cookie") == [
        "session=same; Path=/",
        "session=same; Path=/admin",
    ]


@pytest.mark.asyncio
async def test_cloudflare_solver_cascade_and_parallel_deduplication():
    settings = SimpleNamespace(
        solver_provider_list=[CfSolverProvider.YESCAPTCHA, CfSolverProvider.CAPSOLVER],
        cf_solver_provider=CfSolverProvider.YESCAPTCHA,
        cf_solver_api_keys={},
        cf_solver_api_key="key",
        cf_solver_api_endpoint=None,
        cf_solver_provider_timeouts={},
        cf_solver_timeout_seconds=5,
        cf_solver_max_retries=1,
    )
    orchestrator = CloudflareSolverOrchestrator(settings, ClearanceCache())

    class Solver:
        def __init__(self, provider, success):
            self.provider = provider
            self.success = success
            self.calls = 0

        async def solve(self, _info, *, timeout):
            self.calls += 1
            await asyncio.sleep(0)
            return CfSolveResult(
                success=self.success,
                provider=self.provider,
                cf_clearance="clearance" if self.success else None,
                error=None if self.success else "no balance",
            )

    first = Solver(CfSolverProvider.YESCAPTCHA, False)
    second = Solver(CfSolverProvider.CAPSOLVER, True)

    async def get_solver(provider):
        return first if provider == CfSolverProvider.YESCAPTCHA else second

    orchestrator._get_solver = get_solver
    args = (
        "https://example.com/",
        403,
        b"challenge",
        httpx.Headers({"cf-ray": "abc-CGR"}),
    )
    results = await asyncio.gather(orchestrator.try_solve(*args), orchestrator.try_solve(*args))
    assert all(result.success for result in results)
    assert first.calls == 1
    assert second.calls == 1


def test_provider_session_replaces_cookie_and_user_agent_for_matching_domain():
    client = BrowserLikeClient()
    client.cloudflare_sessions.set(
        "https://app.example.com/",
        CloudflareCookieResult(
            cookies=(
                CloudflareCookie("cf_clearance", "fresh", "example.com"),
                CloudflareCookie("__cf_bm", "browser", "app.example.com"),
            ),
            user_agent="Playwright Browser/1.0",
        ),
    )
    request = httpx.Request(
        "GET",
        "https://app.example.com/private",
        headers={
            "Cookie": "session=user; cf_clearance=stale",
            "User-Agent": "Original Browser/1.0",
        },
    )

    prepared = client._prepare_curl_request(request, body_bytes=b"")

    assert prepared["headers"]["Cookie"] == ("session=user; cf_clearance=fresh; __cf_bm=browser")
    assert prepared["headers"]["User-Agent"] == "Playwright Browser/1.0"


@pytest.mark.asyncio
async def test_cloudflare_challenge_calls_provider_and_replays_original_request():
    class Provider:
        def __init__(self):
            self.calls = 0

        async def solve(self, url: str) -> CloudflareCookieResult:
            self.calls += 1
            return CloudflareCookieResult(
                cookies=(CloudflareCookie("cf_clearance", "fresh", "example.com"),),
                user_agent="Playwright Browser/1.0",
            )

    provider = Provider()
    client = BrowserLikeClient(cloudflare_cookie_provider=provider)
    request = httpx.Request("GET", "https://example.com/protected")
    blocked = httpx.Response(
        403,
        headers={"server": "cloudflare", "cf-ray": "abc-CGR"},
        content=b"cdn-cgi/challenge-platform",
        request=request,
    )
    success = httpx.Response(200, content=b"ok", request=request)
    client._send_once = AsyncMock(
        side_effect=[(blocked, {}, "example.com"), (success, {}, "example.com")]
    )

    response = await client.send(request)

    assert response.status_code == 200
    assert provider.calls == 1
    assert client._send_once.await_count == 2


def test_retry_after_supports_seconds_and_http_date():
    assert _parse_retry_after(httpx.Headers({"Retry-After": "12"})) == 12.0
    future = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=30))
    parsed = _parse_retry_after(httpx.Headers({"Retry-After": future}))
    assert parsed is not None and 1 <= parsed <= 30


@pytest.mark.asyncio
async def test_rate_limit_never_calls_clearance_provider(monkeypatch):
    class Provider:
        calls = 0

        async def solve(self, url: str) -> CloudflareCookieResult:
            self.calls += 1
            raise AssertionError("429 must not initiate a solve")

    provider = Provider()
    client = BrowserLikeClient(cloudflare_cookie_provider=provider)
    request = httpx.Request("GET", "https://example.com/limited")
    limited = httpx.Response(
        429,
        headers={"server": "cloudflare", "cf-ray": "abc", "retry-after": "1"},
        content=b"rate limited",
        request=request,
    )
    client._send_once = AsyncMock(return_value=(limited, {}, "example.com"))
    monkeypatch.setattr("cookie_session_core.browser_client.asyncio.sleep", AsyncMock())

    response = await client.send(request)

    assert response.status_code == 429
    assert provider.calls == 0


@pytest.mark.asyncio
async def test_non_idempotent_request_is_not_replayed_after_challenge():
    client = BrowserLikeClient()
    request = httpx.Request("POST", "https://example.com/action", content=b'{"do":"once"}')
    blocked = httpx.Response(
        403,
        headers={"server": "cloudflare"},
        content=b"cdn-cgi/challenge-platform",
        request=request,
    )
    client._send_once = AsyncMock(return_value=(blocked, {}, "example.com"))

    with pytest.raises(httpx.StreamError, match="not safely replayable"):
        await client.send(request)
    assert client._send_once.await_count == 1
