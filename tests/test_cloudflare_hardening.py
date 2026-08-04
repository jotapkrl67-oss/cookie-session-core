from __future__ import annotations

import asyncio
import gzip
import logging

import pytest

from cookie_session_core import (
    CloudflareCookie,
    CloudflareCookieCoordinator,
    CloudflareCookieResult,
    CloudflareProviderProtocolError,
    CloudflareProviderUnavailableError,
    CloudflareSessionStore,
    HttpCloudflareCookieProvider,
    UpstreamClassification,
    classify_upstream_response,
)
from cookie_session_core.redaction import SecretRedactionFilter


@pytest.mark.parametrize(
    ("status", "headers", "body", "expected"),
    [
        (200, {}, b"normal page", UpstreamClassification.NOT_BLOCKED),
        (403, {}, b"access denied", UpstreamClassification.UPSTREAM_FORBIDDEN),
        (
            403,
            {"server": "cloudflare", "cf-ray": "x"},
            b"access denied",
            UpstreamClassification.UNKNOWN_BLOCK,
        ),
        (429, {"cf-mitigated": "challenge"}, b"_cf_chl_opt", UpstreamClassification.RATE_LIMITED),
        (503, {}, b"maintenance", UpstreamClassification.TRANSIENT_UPSTREAM_FAILURE),
        (
            403,
            {"server": "cloudflare"},
            b"<script>_cf_chl_opt={}</script>",
            UpstreamClassification.CLOUDFLARE_CHALLENGE,
        ),
    ],
)
def test_response_classification(status, headers, body, expected):
    assert classify_upstream_response(status, headers, body).classification == expected


def test_classifier_handles_gzip_and_bounded_false_positive():
    body = gzip.compress(b"<html>cdn-cgi/challenge-platform</html>")
    result = classify_upstream_response(
        403, {"server": "cloudflare", "content-encoding": "gzip"}, body
    )
    assert result.classification == UpstreamClassification.CLOUDFLARE_CHALLENGE
    assert (
        classify_upstream_response(200, {}, b"article about cf-turnstile").classification
        == UpstreamClassification.NOT_BLOCKED
    )


def test_store_normalizes_expiry_scope_skew_and_eviction():
    now = [1_700_000_000.0]
    store = CloudflareSessionStore(
        default_ttl_seconds=100,
        expiry_skew_seconds=15,
        max_ttl_seconds=200,
        max_entries=1,
        clock=lambda: now[0],
    )
    first = store.set(
        "https://app.example.com/path",
        CloudflareCookieResult(
            cookies=(
                CloudflareCookie("cf_clearance", "x", "example.com", expires_at=1_700_001_000),
            ),
            user_agent="Mozilla/5.0 Test/1",
            expires_at=1_700_001_000_000,
        ),
    )
    assert first.expires_at == now[0] + 200 - 15
    assert store.cookies_for_url("http://app.example.com/") == ()
    store.set(
        "https://other.example/",
        CloudflareCookieResult(
            cookies=(CloudflareCookie("cf_clearance", "y", "other.example"),),
            user_agent="Mozilla/5.0 Test/1",
        ),
    )
    assert store.get("https://app.example.com/") is None


def test_provider_rejects_origin_credentials_public_suffix_and_non_finite_expiry():
    with pytest.raises(ValueError):
        HttpCloudflareCookieProvider("https://user:pass@example.com", "t" * 32)
    payload = {
        "cookies": [{"name": "cf_clearance", "value": "x", "domain": "com"}],
        "userAgent": "Mozilla/5.0 Test/1",
    }
    with pytest.raises(CloudflareProviderProtocolError):
        HttpCloudflareCookieProvider._parse_result(payload, requested_url="https://example.com")
    with pytest.raises(CloudflareProviderProtocolError):
        HttpCloudflareCookieProvider._parse_expiry(float("nan"))


@pytest.mark.asyncio
async def test_waiter_cancellation_does_not_cancel_shared_solve_and_map_is_cleaned():
    started = asyncio.Event()
    release = asyncio.Event()

    class Provider:
        async def solve(self, url: str) -> CloudflareCookieResult:
            started.set()
            await release.wait()
            return CloudflareCookieResult(
                cookies=(CloudflareCookie("cf_clearance", "x", "example.com"),),
                user_agent="Mozilla/5.0 Test/1",
            )

    coordinator = CloudflareCookieCoordinator(
        Provider(), CloudflareSessionStore(), cooldown_seconds=0
    )
    owner = asyncio.create_task(coordinator.refresh("https://example.com/a", observed_generation=0))
    await started.wait()
    waiter = asyncio.create_task(
        coordinator.refresh("https://example.com/b", observed_generation=0)
    )
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter
    release.set()
    assert (await owner).generation == 1
    await asyncio.sleep(0)
    assert not coordinator._inflight


@pytest.mark.asyncio
async def test_negative_cache_prevents_failure_storm():
    class Provider:
        calls = 0

        async def solve(self, url: str) -> CloudflareCookieResult:
            self.calls += 1
            raise CloudflareProviderUnavailableError("unavailable")

    provider = Provider()
    coordinator = CloudflareCookieCoordinator(
        provider, CloudflareSessionStore(), cooldown_seconds=0, negative_cache_seconds=60
    )
    for _ in range(2):
        with pytest.raises(CloudflareProviderUnavailableError):
            await coordinator.refresh("https://example.com", observed_generation=0)
    assert provider.calls == 1


@pytest.mark.asyncio
async def test_coordinator_cooldown_prevents_repeat_solves():
    clock = [10.0]

    class Provider:
        calls = 0

        async def solve(self, url: str) -> CloudflareCookieResult:
            self.calls += 1
            return CloudflareCookieResult(
                cookies=(CloudflareCookie("cf_clearance", "x", "example.com"),),
                user_agent="Mozilla/5.0 Test/1",
            )

    provider = Provider()
    store = CloudflareSessionStore()
    coordinator = CloudflareCookieCoordinator(
        provider, store, cooldown_seconds=30, clock=lambda: clock[0]
    )
    await coordinator.refresh("https://example.com", observed_generation=0)
    store.clear("https://example.com")
    with pytest.raises(CloudflareProviderUnavailableError, match="cooling down"):
        await coordinator.refresh("https://example.com", observed_generation=1)
    clock[0] += 31
    await coordinator.refresh("https://example.com", observed_generation=1)
    assert provider.calls == 2


def test_log_filter_redacts_headers_cookies_tokens_and_query(caplog):
    logger = logging.getLogger("test.cloudflare.redaction")
    logger.addFilter(SecretRedactionFilter())
    with caplog.at_level(logging.INFO, logger=logger.name):
        logger.info(
            "url=%s Authorization: Bearer secret Cookie: cf_clearance=value token=abc",
            "https://example.com/path?sensitive=yes",
        )
    output = caplog.text
    assert "secret" not in output
    assert "value" not in output
    assert "sensitive=yes" not in output
    assert "abc" not in output
    assert "[REDACTED]" in output
