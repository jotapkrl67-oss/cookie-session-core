from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Awaitable, Callable
from urllib.parse import urlparse

from playwright.async_api import Browser, BrowserContext

from .core import ConsumedLaunch


def _allowed(host: str, domains: tuple[str, ...]) -> bool:
    host = host.lower().rstrip(".")
    return any(
        host == item.lower().lstrip(".")
        or host.endswith("." + item.lower().lstrip("."))
        for item in domains
    )


@asynccontextmanager
async def isolated_cookie_session(
    browser: Browser,
    launch: ConsumedLaunch,
    on_cookie_sync: Callable[[ConsumedLaunch, list[dict]], Awaitable[object]] | None = None,
):
    """One incognito context per launch. Never reuse this context for another user."""
    context: BrowserContext = await browser.new_context(
        accept_downloads=False,
        service_workers="block",
    )

    async def route_guard(route):
        parsed = urlparse(route.request.url)
        if parsed.scheme not in {"https", "wss"} or not _allowed(
            parsed.hostname or "", launch.allowed_domains
        ):
            await route.abort("blockedbyclient")
        else:
            await route.continue_()

    try:
        await context.route("**/*", route_guard)
        await context.add_cookies(launch.cookies)
        page = await context.new_page()
        await page.goto(launch.upstream_url, wait_until="domcontentloaded", timeout=45_000)
        yield context, page
    finally:
        if on_cookie_sync is not None:
            await on_cookie_sync(launch, await context.cookies())
        await context.close()
