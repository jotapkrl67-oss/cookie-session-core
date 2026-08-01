from __future__ import annotations

import asyncio
import json
import re
from contextlib import suppress
from urllib.parse import urlencode, urljoin, urlparse, urlunparse

import httpx
from fastapi import HTTPException, Request, WebSocket
from fastapi.responses import RedirectResponse, Response, StreamingResponse
from websockets.asyncio.client import connect
from websockets.exceptions import WebSocketException

from .core import ConsumedLaunch, CookieSessionCore

HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "cookie",
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
}
DROP_RESPONSE_HEADERS = HOP_HEADERS | {
    "set-cookie",
    "content-length",
    "content-security-policy",
    "content-security-policy-report-only",
}
REWRITABLE_TYPES = (
    "text/html",
    "text/css",
    "text/javascript",
    "application/javascript",
    "application/x-javascript",
    "application/json",
    "application/manifest+json",
    "application/xml",
    "text/xml",
    "image/svg+xml",
)
URL_ATTRIBUTE = re.compile(
    r"(?P<prefix>\b(?:href|src|action|poster|data|formaction)\s*=\s*)"
    r"(?P<quote>['\"])(?P<url>.*?)(?P=quote)",
    re.IGNORECASE | re.DOTALL,
)
CSS_URL = re.compile(
    r"(?P<prefix>url\(\s*)(?P<quote>['\"]?)(?P<url>[^)'\"]+)"
    r"(?P=quote)(?P<suffix>\s*\))",
    re.IGNORECASE,
)
SRCSET_ATTRIBUTE = re.compile(
    r"(?P<prefix>\bsrcset\s*=\s*)(?P<quote>['\"])(?P<value>.*?)(?P=quote)",
    re.IGNORECASE | re.DOTALL,
)
META_CSP = re.compile(
    r"<meta\b(?=[^>]*\bhttp-equiv\s*=\s*['\"]?content-security-policy['\"]?)[^>]*>",
    re.IGNORECASE,
)


def _host_allowed(host: str, allowed: tuple[str, ...]) -> bool:
    normalized = host.lower().rstrip(".")
    return any(
        normalized == item.lower().lstrip(".").rstrip(".")
        or normalized.endswith("." + item.lower().lstrip(".").rstrip("."))
        for item in allowed
    )


def _cookie_header(launch: ConsumedLaunch, target: str) -> str:
    parsed = urlparse(target)
    host = (parsed.hostname or "").lower()
    path = parsed.path or "/"
    values = []
    for cookie in launch.cookies:
        domain = str(cookie["domain"]).lower().lstrip(".")
        if host != domain and not host.endswith("." + domain):
            continue
        if not path.startswith(str(cookie.get("path") or "/")):
            continue
        values.append(f"{cookie['name']}={cookie['value']}")
    return "; ".join(values)


def resolve_target(launch: ConsumedLaunch, path: str, query: str = "") -> str:
    """Maps a proxy path to one allowlisted HTTPS upstream URL."""
    upstream = urlparse(launch.upstream_url)
    if path.startswith("_host/"):
        parts = path.split("/", 2)
        if len(parts) < 2 or not _host_allowed(parts[1], launch.allowed_domains):
            raise HTTPException(403, "Proxy destination is not allowed")
        host = parts[1].lower()
        netloc = host
        target_path = "/" + (parts[2] if len(parts) == 3 else "")
    else:
        host = (upstream.hostname or "").lower()
        netloc = upstream.netloc
        target_path = "/" + path.lstrip("/")
    if not host or not _host_allowed(host, launch.allowed_domains):
        raise HTTPException(403, "Proxy destination is not allowed")
    if not any(target_path.startswith(prefix) for prefix in launch.allowed_paths):
        raise HTTPException(403, "Proxy path is not allowed")
    return urlunparse(("https", netloc, target_path, "", query, ""))


def browser_url(
    raw_url: str,
    *,
    current_target: str,
    launch: ConsumedLaunch,
    proxy_prefix: str,
    public_base_url: str,
) -> str:
    value = raw_url.strip()
    if not value or value.startswith(("#", "data:", "blob:", "javascript:", "mailto:", "tel:")):
        return raw_url
    absolute = urljoin(current_target, value)
    parsed = urlparse(absolute)
    if parsed.scheme not in {"http", "https", "ws", "wss"}:
        return raw_url
    host = (parsed.hostname or "").lower()
    if not _host_allowed(host, launch.allowed_domains):
        return raw_url
    main_host = (urlparse(launch.upstream_url).hostname or "").lower()
    host_part = "" if host == main_host else f"/_host/{host}"
    proxied_path = f"{proxy_prefix}{host_part}{parsed.path or '/'}"
    if parsed.query:
        proxied_path += "?" + parsed.query
    if parsed.fragment:
        proxied_path += "#" + parsed.fragment
    if parsed.scheme in {"ws", "wss"}:
        public = urlparse(public_base_url)
        return "wss://" + public.netloc + proxied_path
    return proxied_path


def _runtime_script(launch: ConsumedLaunch, prefix: str, public_base_url: str) -> str:
    hosts = [item.lower().lstrip(".") for item in launch.allowed_domains]
    payload = json.dumps(
        {"prefix": prefix, "proxyOrigin": public_base_url.rstrip("/"), "hosts": hosts},
        separators=(",", ":"),
    ).replace("</", "<\\/")
    return f"""<script>(function(){{const C={payload};
const ok=h=>C.hosts.some(x=>h===x||h.endsWith('.'+x));
const map=(v,ws=false)=>{{if(typeof v!=='string')return v;if(v.startsWith(C.prefix))return v;
try{{const u=new URL(v,location.href);if(u.origin===location.origin){{
if(!u.pathname.startsWith(C.prefix))u.pathname=C.prefix+u.pathname;}}
else if(ok(u.hostname)){{
const main=new URL({json.dumps(launch.upstream_url)}).hostname;const h=u.hostname;
u.protocol=ws?'wss:':'https:';u.host=new URL(C.proxyOrigin).host;
u.pathname=C.prefix+(h===main?'':'/_host/'+h)+u.pathname;}}
return ws?u.href.replace(/^https:/,'wss:'):u.href;}}catch(_e){{return v;}}}};
const f=window.fetch;window.fetch=(v,o)=>f.call(window,typeof v==='string'?map(v):v,o);
const xo=XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open=function(m,u,...a){{return xo.call(this,m,map(u),...a)}};
const W=window.WebSocket;
window.WebSocket=function(u,p){{
return p===undefined?new W(map(u,true)):new W(map(u,true),p)}};
window.WebSocket.prototype=W.prototype;
const E=window.EventSource;
window.EventSource=function(u,o){{return new E(map(u),o)}};
window.EventSource.prototype=E.prototype;
}})();</script>"""


def rewrite_text(
    body: bytes,
    content_type: str,
    *,
    current_target: str,
    launch: ConsumedLaunch,
    proxy_prefix: str,
    public_base_url: str,
) -> bytes:
    match = re.search(r"charset=([^;\s]+)", content_type, re.IGNORECASE)
    encoding = match.group(1).strip("\"'") if match else "utf-8"
    try:
        text = body.decode(encoding)
    except (LookupError, UnicodeDecodeError):
        text = body.decode("utf-8", errors="replace")
        encoding = "utf-8"

    def replace_url(value: str) -> str:
        return browser_url(
            value,
            current_target=current_target,
            launch=launch,
            proxy_prefix=proxy_prefix,
            public_base_url=public_base_url,
        )

    def replace_srcset(match: re.Match) -> str:
        value = match.group("value")
        if "data:" in value.lower():
            return match.group(0)
        items = []
        for item in value.split(","):
            parts = item.strip().split()
            if parts:
                items.append(" ".join([replace_url(parts[0]), *parts[1:]]))
        return (
            f"{match.group('prefix')}{match.group('quote')}{', '.join(items)}{match.group('quote')}"
        )

    if content_type.lower().startswith("text/html"):
        text = META_CSP.sub("", text)
        text = URL_ATTRIBUTE.sub(
            lambda m: (
                f"{m.group('prefix')}{m.group('quote')}"
                f"{replace_url(m.group('url'))}{m.group('quote')}"
            ),
            text,
        )
        text = SRCSET_ATTRIBUTE.sub(replace_srcset, text)
    if "css" in content_type.lower() or "html" in content_type.lower():
        text = CSS_URL.sub(
            lambda m: (
                f"{m.group('prefix')}{m.group('quote')}"
                f"{replace_url(m.group('url'))}{m.group('quote')}{m.group('suffix')}"
            ),
            text,
        )

    # Absolute URLs also occur inside JSON and JavaScript configuration objects.
    for allowed in sorted(launch.allowed_domains, key=len, reverse=True):
        host = allowed.lower().lstrip(".")
        main = (urlparse(launch.upstream_url).hostname or "").lower()
        host_part = "" if host == main else f"/_host/{host}"
        replacement = f"{public_base_url.rstrip('/')}{proxy_prefix}{host_part}"
        text = re.sub(
            rf"https?://{re.escape(host)}(?::\d+)?(?=[/\"'])",
            replacement,
            text,
            flags=re.I,
        )
        ws_replacement = replacement.replace("https://", "wss://").replace("http://", "ws://")
        text = re.sub(
            rf"wss?://{re.escape(host)}(?::\d+)?(?=[/\"'])",
            ws_replacement,
            text,
            flags=re.I,
        )

    if content_type.lower().startswith("text/html"):
        script = _runtime_script(launch, proxy_prefix, public_base_url)
        head = re.search(r"<head(?:\s[^>]*)?>", text, re.IGNORECASE)
        if head:
            text = text[: head.end()] + script + text[head.end() :]
        else:
            text = script + text
    return text.encode(encoding, errors="replace")


def proxy_csp() -> str:
    return (
        "default-src 'self' data: blob:; base-uri 'self'; object-src 'none'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' blob:; "
        "style-src 'self' 'unsafe-inline' data:; img-src 'self' data: blob:; "
        "font-src 'self' data:; media-src 'self' data: blob:; "
        "connect-src 'self' wss:; frame-src 'self' blob:; form-action 'self'"
    )


class ReverseProxy:
    def __init__(self, core: CookieSessionCore, settings, client: httpx.AsyncClient):
        self.core = core
        self.settings = settings
        self.client = client

    async def http(self, service_id: str, path: str, request: Request) -> Response:
        prefix = f"/proxy/{service_id}"
        launch_token = request.query_params.get("launch")
        if launch_token:
            try:
                launch = await self.core.consume_launch(raw_token=launch_token)
                if launch.service_id != service_id:
                    raise ValueError("Service mismatch")
                grant = await self.core.create_proxy_grant(
                    launch, self.settings.proxy_grant_ttl_seconds
                )
            except ValueError:
                raise HTTPException(401, "Launch link is invalid, expired, or already used")
            clean = [(k, v) for k, v in request.query_params.multi_items() if k != "launch"]
            destination = request.url.path + ("?" + urlencode(clean) if clean else "")
            response = RedirectResponse(destination, status_code=303)
            response.set_cookie(
                "__Secure-cookie_core_proxy",
                grant,
                max_age=self.settings.proxy_grant_ttl_seconds,
                secure=self.settings.secure_cookies,
                httponly=True,
                samesite="lax",
                path=prefix + "/",
            )
            return response

        raw_grant = request.cookies.get("__Secure-cookie_core_proxy")
        if not raw_grant:
            raise HTTPException(401, "Proxy session is missing")
        try:
            launch = await self.core.proxy_grant(raw_grant=raw_grant, service_id=service_id)
        except (ValueError, TypeError):
            raise HTTPException(401, "Proxy session is invalid or expired")
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            origin = request.headers.get("origin")
            expected = str(self.settings.public_base_url).rstrip("/")
            if origin and origin.rstrip("/") != expected:
                raise HTTPException(403, "Request origin is not allowed")
        query = urlencode([(k, v) for k, v in request.query_params.multi_items() if k != "launch"])
        target = resolve_target(launch, path, query)
        target_parts = urlparse(target)
        headers = {
            key: value
            for key, value in request.headers.items()
            if key.lower() not in HOP_HEADERS
            and key.lower() not in {"content-length", "origin", "referer", "accept-encoding"}
        }
        headers["Accept-Encoding"] = "identity"
        if request.headers.get("origin"):
            headers["Origin"] = f"https://{target_parts.netloc}"
        if browser_referer := request.headers.get("referer"):
            referer = urlparse(browser_referer)
            marker = prefix + "/"
            if referer.path.startswith(marker):
                with suppress(HTTPException):
                    headers["Referer"] = resolve_target(
                        launch, referer.path[len(marker) :], referer.query
                    )
        cookies = _cookie_header(launch, target)
        if cookies:
            headers["Cookie"] = cookies
        upstream_request = self.client.build_request(
            request.method, target, headers=headers, content=request.stream()
        )
        try:
            upstream = await self.client.send(upstream_request, stream=True)
        except httpx.HTTPError:
            raise HTTPException(502, "Upstream service is unavailable")
        try:
            for raw_cookie in upstream.headers.get_list("set-cookie"):
                await self.core.capture_set_cookie(launch, raw_cookie, target_parts.hostname or "")
            response_headers = {
                key: value
                for key, value in upstream.headers.items()
                if key.lower() not in DROP_RESPONSE_HEADERS
            }
            location = upstream.headers.get("location")
            if location:
                response_headers["Location"] = browser_url(
                    location,
                    current_target=target,
                    launch=launch,
                    proxy_prefix=prefix,
                    public_base_url=str(self.settings.public_base_url),
                )
            cors_origin = upstream.headers.get("access-control-allow-origin")
            if cors_origin and _host_allowed(
                urlparse(cors_origin).hostname or "", launch.allowed_domains
            ):
                response_headers["access-control-allow-origin"] = str(
                    self.settings.public_base_url
                ).rstrip("/")
            refresh = upstream.headers.get("refresh")
            if refresh and "url=" in refresh.lower():
                delay, raw_location = re.split(r"url=", refresh, maxsplit=1, flags=re.I)
                response_headers["refresh"] = (
                    delay
                    + "url="
                    + browser_url(
                        raw_location.strip(" '\""),
                        current_target=target,
                        launch=launch,
                        proxy_prefix=prefix,
                        public_base_url=str(self.settings.public_base_url),
                    )
                )
            content_type = upstream.headers.get("content-type", "")
            content_length = int(upstream.headers.get("content-length", "0") or 0)
            rewritable = any(content_type.lower().startswith(item) for item in REWRITABLE_TYPES)
            if rewritable and content_length <= self.settings.proxy_max_rewrite_bytes:
                body = await upstream.aread()
                if len(body) <= self.settings.proxy_max_rewrite_bytes:
                    body = rewrite_text(
                        body,
                        content_type,
                        current_target=target,
                        launch=launch,
                        proxy_prefix=prefix,
                        public_base_url=str(self.settings.public_base_url),
                    )
                    response_headers.pop("content-encoding", None)
                    response_headers.pop("etag", None)
                    response_headers["Content-Security-Policy"] = proxy_csp()
                    await upstream.aclose()
                    return Response(
                        body,
                        status_code=upstream.status_code,
                        headers=response_headers,
                        media_type=None,
                    )
                response_headers.pop("content-encoding", None)
                response_headers.pop("etag", None)
                response_headers["Content-Security-Policy"] = proxy_csp()
                await upstream.aclose()
                return Response(
                    body,
                    status_code=upstream.status_code,
                    headers=response_headers,
                    media_type=None,
                )

            async def stream():
                try:
                    async for chunk in upstream.aiter_raw():
                        yield chunk
                finally:
                    await upstream.aclose()

            response_headers["Content-Security-Policy"] = proxy_csp()
            return StreamingResponse(
                stream(),
                status_code=upstream.status_code,
                headers=response_headers,
                media_type=None,
            )
        except Exception:
            await upstream.aclose()
            raise

    async def websocket(self, websocket: WebSocket, service_id: str, path: str) -> None:
        expected = str(self.settings.public_base_url).rstrip("/")
        if websocket.headers.get("origin", "").rstrip("/") != expected:
            await websocket.close(code=4403)
            return
        raw_grant = websocket.cookies.get("__Secure-cookie_core_proxy")
        try:
            if not raw_grant:
                raise ValueError
            launch = await self.core.proxy_grant(raw_grant=raw_grant, service_id=service_id)
            target = resolve_target(launch, path, websocket.url.query)
        except (ValueError, TypeError, HTTPException):
            await websocket.close(code=4401)
            return
        target = target.replace("https://", "wss://", 1)
        parsed = urlparse(target)
        headers = {}
        cookie = _cookie_header(launch, target)
        if cookie:
            headers["Cookie"] = cookie
        protocols = [
            item.strip()
            for item in websocket.headers.get("sec-websocket-protocol", "").split(",")
            if item.strip()
        ]
        try:
            async with connect(
                target,
                origin=f"https://{parsed.netloc}",
                additional_headers=headers,
                subprotocols=protocols or None,
                open_timeout=self.settings.proxy_timeout_seconds,
                max_size=None,
            ) as upstream:
                response_headers = getattr(getattr(upstream, "response", None), "headers", None)
                if response_headers:
                    for raw_cookie in response_headers.get_all("Set-Cookie"):
                        await self.core.capture_set_cookie(
                            launch, raw_cookie, parsed.hostname or ""
                        )
                await websocket.accept(subprotocol=upstream.subprotocol)

                async def browser_to_upstream():
                    while True:
                        message = await websocket.receive()
                        if message["type"] == "websocket.disconnect":
                            return
                        data = message.get("bytes")
                        await upstream.send(data if data is not None else message.get("text", ""))

                async def upstream_to_browser():
                    async for message in upstream:
                        if isinstance(message, bytes):
                            await websocket.send_bytes(message)
                        else:
                            await websocket.send_text(message)

                tasks = {
                    asyncio.create_task(browser_to_upstream()),
                    asyncio.create_task(upstream_to_browser()),
                }
                done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for task in pending:
                    task.cancel()
                await asyncio.gather(*done, *pending, return_exceptions=True)
        except (OSError, WebSocketException, asyncio.TimeoutError):
            with suppress(Exception):
                await websocket.close(code=1011)
        else:
            with suppress(Exception):
                await websocket.close()
