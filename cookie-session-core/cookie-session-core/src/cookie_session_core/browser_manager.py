from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import secrets
import time
from contextlib import suppress
from dataclasses import dataclass, field
from urllib.parse import urlparse
from uuid import uuid4

from fastapi import HTTPException, WebSocket, WebSocketDisconnect
from playwright.async_api import (
    Browser,
    BrowserContext,
    CDPSession,
    Page,
    Playwright,
    async_playwright,
)

from .config import Settings
from .core import ConsumedLaunch, CookieSessionCore

logger = logging.getLogger("cookie_session_core.browser")
DEFAULT_VIEWPORT = {"width": 1440, "height": 900}
MAX_VIEWPORT = {"width": 2560, "height": 1440}


@dataclass
class ManagedBrowserSession:
    id: str
    grant_hash: str
    launch: ConsumedLaunch
    context: BrowserContext
    page: Page
    cdp: CDPSession
    frames: asyncio.Queue[bytes]
    expires_at: float
    last_seen: float = field(default_factory=time.monotonic)
    sync_task: asyncio.Task | None = None
    connected_clients: int = 0
    disconnect_task: asyncio.Task | None = None


def _domain_allowed(domain: str, allowed: tuple[str, ...]) -> bool:
    normalized = domain.lower().lstrip(".")
    return any(
        normalized == item.lower().lstrip(".")
        or normalized.endswith("." + item.lower().lstrip("."))
        for item in allowed
    )


def _request_is_public_https(url: str) -> bool:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower().rstrip(".")
    if parsed.scheme not in {"https", "wss"} or not host or "." not in host:
        return False
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
        return False
    if host in {"metadata.google.internal", "instance-data.ec2.internal"}:
        return False
    try:
        return not (
            ipaddress.ip_address(host).is_private
            or ipaddress.ip_address(host).is_loopback
            or ipaddress.ip_address(host).is_link_local
            or ipaddress.ip_address(host).is_reserved
        )
    except ValueError:
        return True


class BrowserSessionManager:
    def __init__(self, settings: Settings, core: CookieSessionCore):
        self.settings = settings
        self.core = core
        self.playwright: Playwright | None = None
        self.browser: Browser | None = None
        self.sessions: dict[str, ManagedBrowserSession] = {}
        self.reaper_task: asyncio.Task | None = None

    async def start(self) -> None:
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(
            headless=self.settings.browser_headless,
            args=[
                "--disable-crash-reporter",
                "--disable-crashpad",
                "--disable-dev-shm-usage",
                "--no-sandbox",
            ],
        )
        self.reaper_task = asyncio.create_task(self._reap())

    async def stop(self) -> None:
        if self.reaper_task:
            self.reaper_task.cancel()
            with suppress(asyncio.CancelledError):
                await self.reaper_task
        for session_id in list(self.sessions):
            await self.close(session_id)
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()

    async def create(self, launch: ConsumedLaunch) -> tuple[str, str]:
        if not self.browser or not self.browser.is_connected():
            raise HTTPException(503, "Remote browser is unavailable")
        if len(self.sessions) >= self.settings.max_browser_sessions:
            raise HTTPException(503, "Remote browser capacity reached")
        if any(
            item.launch.user_id == launch.user_id
            and item.launch.service_id == launch.service_id
            and item.launch.profile_id == launch.profile_id
            for item in self.sessions.values()
        ):
            raise HTTPException(409, "This account already has an active session")
        context = await self.browser.new_context(
            viewport=DEFAULT_VIEWPORT,
            locale="pt-BR",
            color_scheme="dark",
            accept_downloads=False,
            service_workers="block",
        )
        session_id = str(uuid4())
        grant = secrets.token_urlsafe(32)
        try:
            async def route_guard(route):
                if _request_is_public_https(route.request.url):
                    await route.continue_()
                else:
                    await route.abort("blockedbyclient")

            await context.route("**/*", route_guard)
            await context.add_cookies(launch.cookies)
            page = await context.new_page()
            await page.goto(
                launch.upstream_url,
                wait_until="domcontentloaded",
                timeout=45_000,
            )
            cdp = await context.new_cdp_session(page)
            frames: asyncio.Queue[bytes] = asyncio.Queue(maxsize=1)

            async def receive_frame(event: dict) -> None:
                with suppress(Exception):
                    await cdp.send(
                        "Page.screencastFrameAck", {"sessionId": event["sessionId"]}
                    )
                try:
                    frame = base64.b64decode(event["data"], validate=True)
                    if frames.full():
                        with suppress(asyncio.QueueEmpty):
                            frames.get_nowait()
                    frames.put_nowait(frame)
                except (KeyError, ValueError, asyncio.QueueFull):
                    pass

            cdp.on("Page.screencastFrame", receive_frame)
            await cdp.send(
                "Page.startScreencast",
                {
                    "format": "png",
                    "maxWidth": MAX_VIEWPORT["width"],
                    "maxHeight": MAX_VIEWPORT["height"],
                    "everyNthFrame": 1,
                },
            )
            item = ManagedBrowserSession(
                id=session_id,
                grant_hash=hashlib.sha256(grant.encode()).hexdigest(),
                launch=launch,
                context=context,
                page=page,
                cdp=cdp,
                frames=frames,
                expires_at=time.monotonic() + self.settings.browser_session_ttl_seconds,
            )
            item.sync_task = asyncio.create_task(self._sync_loop(item))
            self.sessions[session_id] = item
            return session_id, grant
        except Exception:
            await context.close()
            raise

    def authorized(self, session_id: str, grant: str | None) -> ManagedBrowserSession | None:
        item = self.sessions.get(session_id)
        if (
            not item
            or not grant
            or item.expires_at <= time.monotonic()
            or not hmac.compare_digest(
                hashlib.sha256(grant.encode()).hexdigest(), item.grant_hash
            )
        ):
            return None
        item.last_seen = time.monotonic()
        return item

    async def close(self, session_id: str) -> None:
        item = self.sessions.pop(session_id, None)
        if not item:
            return
        current_task = asyncio.current_task()
        if item.disconnect_task and item.disconnect_task is not current_task:
            item.disconnect_task.cancel()
            with suppress(asyncio.CancelledError):
                await item.disconnect_task
        if item.sync_task:
            item.sync_task.cancel()
            with suppress(asyncio.CancelledError):
                await item.sync_task
        with suppress(Exception):
            cookies = await item.context.cookies()
            await self.core.sync_browser_cookies(item.launch, cookies)
        with suppress(Exception):
            await item.cdp.send("Page.stopScreencast")
        with suppress(Exception):
            await item.context.close()

    async def close_profile(self, user_id: str, service_id: str, profile_id: str) -> None:
        matching = [
            item.id
            for item in self.sessions.values()
            if item.launch.user_id == user_id
            and item.launch.service_id == service_id
            and item.launch.profile_id == profile_id
        ]
        for session_id in matching:
            await self.close(session_id)

    async def websocket(self, websocket: WebSocket, session_id: str) -> None:
        item = self.authorized(
            session_id, websocket.cookies.get("__Secure-cookie_core_grant")
        )
        expected_origin = str(self.settings.public_base_url).rstrip("/")
        if not item or websocket.headers.get("origin", "").rstrip("/") != expected_origin:
            await websocket.close(code=4401)
            return
        if item.disconnect_task:
            item.disconnect_task.cancel()
            with suppress(asyncio.CancelledError):
                await item.disconnect_task
            item.disconnect_task = None
        item.connected_clients += 1
        await websocket.accept()

        async def send_frames() -> None:
            await websocket.send_text(
                json.dumps(
                    {"type": "state", "title": await item.page.title(), "url": item.page.url}
                )
            )
            last_state = time.monotonic()
            while True:
                frame = await item.frames.get()
                while not item.frames.empty():
                    frame = item.frames.get_nowait()
                await websocket.send_bytes(frame)
                item.last_seen = time.monotonic()
                if item.last_seen - last_state >= 2:
                    await websocket.send_text(
                        json.dumps(
                            {
                                "type": "state",
                                "title": await item.page.title(),
                                "url": item.page.url,
                            }
                        )
                    )
                    last_state = item.last_seen

        async def receive_events() -> None:
            while True:
                try:
                    event = json.loads(await websocket.receive_text())
                    if isinstance(event, dict) and not await self._handle_event(item, event):
                        return
                except WebSocketDisconnect:
                    return
                except (json.JSONDecodeError, TypeError, ValueError):
                    continue
                except Exception as exc:
                    logger.warning(
                        "remote_input_ignored session=%s error=%s",
                        item.id,
                        type(exc).__name__,
                    )

        sender = asyncio.create_task(send_frames())
        receiver = asyncio.create_task(receive_events())
        done, pending = await asyncio.wait(
            {sender, receiver}, return_when=asyncio.FIRST_COMPLETED
        )
        for task in pending:
            task.cancel()
        await asyncio.gather(*done, *pending, return_exceptions=True)
        if item.expires_at <= time.monotonic():
            await self.close(item.id)
        elif item.id in self.sessions:
            item.connected_clients = max(0, item.connected_clients - 1)
            if item.connected_clients == 0:
                item.disconnect_task = asyncio.create_task(
                    self._close_after_disconnect(item.id)
                )
        with suppress(Exception):
            await websocket.close()

    async def _close_after_disconnect(self, session_id: str) -> None:
        await asyncio.sleep(10)
        item = self.sessions.get(session_id)
        if item and item.connected_clients == 0:
            await self.close(session_id)

    async def _handle_event(self, item: ManagedBrowserSession, event: dict) -> bool:
        kind = event.get("type")
        if kind == "click":
            buttons = {0: "left", 1: "middle", 2: "right"}
            await item.page.mouse.click(
                float(event.get("x", 0)),
                float(event.get("y", 0)),
                button=buttons.get(int(event.get("button", 0)), "left"),
                click_count=max(1, min(int(event.get("count", 1)), 2)),
            )
        elif kind == "move":
            await item.page.mouse.move(float(event.get("x", 0)), float(event.get("y", 0)))
        elif kind == "wheel":
            await item.page.mouse.wheel(
                float(event.get("deltaX", 0)), float(event.get("deltaY", 0))
            )
        elif kind == "resize":
            width = max(640, min(int(event.get("width", 1440)), 2560))
            height = max(480, min(int(event.get("height", 900)), 1440))
            await item.page.set_viewport_size({"width": width, "height": height})
        elif kind == "text":
            await item.page.keyboard.insert_text(str(event.get("text", ""))[:20_000])
        elif kind == "key":
            key = str(event.get("key", ""))[:40]
            modifiers = [
                label
                for field, label in (
                    ("ctrl", "Control"),
                    ("alt", "Alt"),
                    ("shift", "Shift"),
                    ("meta", "Meta"),
                )
                if event.get(field)
            ]
            if len(key) == 1 and not modifiers:
                await item.page.keyboard.insert_text(key)
            elif key:
                await item.page.keyboard.press("+".join(modifiers + [key]))
        elif kind == "back":
            await item.page.go_back(wait_until="domcontentloaded", timeout=30_000)
        elif kind == "reload":
            await item.page.reload(wait_until="domcontentloaded", timeout=30_000)
        elif kind == "close":
            item.expires_at = 0
            return False
        return True

    async def _sync_loop(self, item: ManagedBrowserSession) -> None:
        while True:
            await asyncio.sleep(15)
            try:
                cookies = [
                    cookie
                    for cookie in await item.context.cookies()
                    if _domain_allowed(cookie["domain"], item.launch.allowed_domains)
                ]
                await self.core.sync_browser_cookies(item.launch, cookies)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning(
                    "cookie_sync_failed session=%s error=%s",
                    item.id,
                    type(exc).__name__,
                )

    async def _reap(self) -> None:
        while True:
            await asyncio.sleep(15)
            current = time.monotonic()
            for session_id, item in list(self.sessions.items()):
                if item.expires_at <= current:
                    await self.close(session_id)