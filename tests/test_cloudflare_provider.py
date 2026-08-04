from __future__ import annotations

import asyncio

import httpx
import pytest

from cookie_session_core import (
    CloudflareCookie,
    CloudflareCookieCoordinator,
    CloudflareCookieProvider,
    CloudflareCookieProviderError,
    CloudflareCookieResult,
    CloudflareSessionStore,
    HttpCloudflareCookieProvider,
)


def test_cloudflare_provider_contract_is_structural():
    class Provider:
        async def solve(self, url: str) -> CloudflareCookieResult:
            return CloudflareCookieResult(
                cookies=(
                    CloudflareCookie(
                        name="cf_clearance",
                        value="clearance",
                        domain="example.com",
                        expires_at=1_800_000_000,
                        same_site="None",
                    ),
                ),
                user_agent="Mozilla/5.0 TestBrowser/1.0",
                expires_at=1_800_000_000,
            )

    assert isinstance(Provider(), CloudflareCookieProvider)


def test_cloudflare_cookie_defaults_match_browser_cookie_semantics():
    cookie = CloudflareCookie(name="session", value="value", domain="example.com")

    assert cookie.path == "/"
    assert cookie.expires_at is None
    assert cookie.secure is True
    assert cookie.http_only is True
    assert cookie.same_site is None


@pytest.mark.asyncio
async def test_http_provider_posts_solve_and_normalizes_playwright_response():
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == "https://playwright.example.com/solve"
        assert request.headers["authorization"] == f"Bearer {'t' * 32}"
        assert request.content == b'{"url":"https://example.com/protected"}'
        return httpx.Response(
            200,
            json={
                "cookies": [
                    {
                        "name": "cf_clearance",
                        "value": "clearance",
                        "domain": ".example.com",
                        "path": "/",
                        "expires": 1_800_000_000,
                        "secure": True,
                        "httpOnly": True,
                        "sameSite": "None",
                    }
                ],
                "userAgent": "Mozilla/5.0 Browser/1.0",
                "expiresAt": 1_800_000_000_000,
            },
        )

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = HttpCloudflareCookieProvider(
        "https://playwright.example.com/", "t" * 32, http_client=http
    )

    result = await provider.solve("https://example.com/protected")

    assert result.user_agent == "Mozilla/5.0 Browser/1.0"
    assert result.expires_at == 1_800_000_000
    assert result.cookies[0].domain == "example.com"
    assert result.cookies[0].name == "cf_clearance"
    await http.aclose()


@pytest.mark.asyncio
async def test_http_provider_rejects_malformed_or_header_injecting_responses():
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "cookies": [{"name": "bad;name", "value": "x", "domain": "example.com"}],
                "userAgent": "Browser\r\nInjected: yes",
            },
        )

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = HttpCloudflareCookieProvider(
        "https://playwright.example.com", "t" * 32, http_client=http
    )
    with pytest.raises(CloudflareCookieProviderError):
        await provider.solve("https://example.com/")
    await http.aclose()


@pytest.mark.asyncio
async def test_coordinator_deduplicates_same_host_and_parallelizes_different_hosts():
    class Provider:
        def __init__(self):
            self.calls = 0
            self.active = 0
            self.max_active = 0

        async def solve(self, url: str) -> CloudflareCookieResult:
            self.calls += 1
            self.active += 1
            self.max_active = max(self.max_active, self.active)
            await asyncio.sleep(0.01)
            host = httpx.URL(url).host
            self.active -= 1
            return CloudflareCookieResult(
                cookies=(CloudflareCookie("cf_clearance", host, host),),
                user_agent="Test Browser",
            )

    provider = Provider()
    store = CloudflareSessionStore()
    coordinator = CloudflareCookieCoordinator(provider, store)

    first, second = await asyncio.gather(
        coordinator.refresh("https://one.example/", observed_generation=0),
        coordinator.refresh("https://one.example/path", observed_generation=0),
    )
    assert first.generation == second.generation
    assert provider.calls == 1

    await asyncio.gather(
        coordinator.refresh("https://two.example/", observed_generation=0),
        coordinator.refresh("https://three.example/", observed_generation=0),
    )
    assert provider.calls == 3
    assert provider.max_active == 2


def test_session_store_applies_cookie_scope_and_expiry():
    store = CloudflareSessionStore()
    store.set(
        "https://app.example.com/login",
        CloudflareCookieResult(
            cookies=(
                CloudflareCookie("root", "one", "example.com"),
                CloudflareCookie("admin", "two", "app.example.com", path="/admin"),
                CloudflareCookie("other", "three", "other.example.com"),
            ),
            user_agent="Test Browser",
        ),
    )

    assert [item.name for item in store.cookies_for_url("https://app.example.com/admin/page")] == [
        "admin",
        "root",
    ]
