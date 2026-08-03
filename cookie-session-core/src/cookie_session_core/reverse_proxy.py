from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from collections.abc import Mapping
from contextlib import suppress
from datetime import datetime
from html import escape
from typing import Any
from urllib.parse import quote, unquote, urlencode, urljoin, urlparse, urlunparse

import httpx
from fastapi import HTTPException, Request, WebSocket
from fastapi.responses import HTMLResponse, RedirectResponse, Response, StreamingResponse
from websockets.asyncio.client import connect
from websockets.exceptions import WebSocketException

from .browser_client import _is_streaming_request
from .core import ConsumedLaunch, CookieSessionCore

logger = logging.getLogger("cookie_session_core.reverse_proxy")

AnyHttpClient = object

PRIVATE_HOSTING_SUFFIXES = frozenset(
    {
        "appspot.com",
        "fly.dev",
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
    "content-md5",
    "digest",
    "content-security-policy",
    "content-security-policy-report-only",
    "cross-origin-embedder-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "clear-site-data",
    "origin-agent-cluster",
    "alt-svc",
    "nel",
    "report-to",
    "permissions-policy",
    "feature-policy",
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
    "application/json+protobuf",
    "text/x-component",
)
CHALLENGE_PLATFORM_PATHS = (
    "/cdn-cgi/challenge-platform/",
    "/cdn-cgi/speculation",
    "/cdn-cgi/styles/",
    "/cdn-cgi/scripts/",
    "/cdn-cgi/images/",
)
CHALLENGE_SCRIPT_ORIGINS = (
    "https://challenges.cloudflare.com",
    "https://www.google.com",
    "https://www.gstatic.com",
    "https://hcaptcha.com",
    "https://*.hcaptcha.com",
)
DIRECT_BROWSER_PATHS = (
    ("accounts.google.com", "/gsi/"),
    ("www.google.com", "/gsi/"),
)
DIRECT_BROWSER_HOSTS = frozenset(
    {
        # Turnstile validates the URL of the <script> element that loaded
        # api.js. Relaying that file through Cookie Core makes the otherwise
        # valid tag look like an unsupported self-hosted copy.
        "challenges.cloudflare.com",
        "www.google.com",
        "www.gstatic.com",
        "hcaptcha.com",
        "js.hcaptcha.com",
        "newassets.hcaptcha.com",
    }
)
CORE_RESERVED_PATHS = (
    "/proxy/",
    "/v1/",
    "/health/",
    "/metrics",
)
DIRECT_PUBLIC_ASSET_HOSTS = frozenset(
    {
        "cdnseo.dreamfaceapp.com",
        "static.cloudflareinsights.com",
    }
)
DIRECT_PUBLIC_ASSET_SUFFIXES = (
    ".cloudfront.net",
    ".akamaihd.net",
    ".fastly.net",
    ".edgecastcdn.net",
    ".cdn77.org",
    ".keycdn.com",
    ".stackpathdns.com",
    ".b-cdn.net",
    ".googleapis.com",
    ".gstatic.com",
)
MIME_OVERRIDE_BY_EXTENSION = {
    ".js": "application/javascript; charset=utf-8",
    ".mjs": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".ico": "image/x-icon",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".ttf": "font/ttf",
    ".otf": "font/otf",
    ".eot": "application/vnd.ms-fontobject",
    ".map": "application/json; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".htm": "text/html; charset=utf-8",
}
URL_ATTRIBUTE = re.compile(
    r"(?P<prefix>\b(?:href|src|action|poster|data|formaction)\s*=\s*)"
    r"(?P<quote>['\"])(?P<url>.*?)(?P=quote)",
    re.IGNORECASE | re.DOTALL,
)
UNQUOTED_URL_ATTRIBUTE = re.compile(
    r"(?P<prefix>\b(?:href|src|action|poster|data|formaction)\s*=\s*)"
    r"(?!['\"])(?P<url>[^\s>]+)",
    re.IGNORECASE,
)
CSS_URL = re.compile(
    r"(?P<prefix>url\(\s*)(?P<quote>['\"]?)(?P<url>[^)'\"]+)"
    r"(?P=quote)(?P<suffix>\s*\))",
    re.IGNORECASE,
)
CSS_IMPORT = re.compile(
    r"(?P<prefix>@import\s+)(?P<quote>['\"])(?P<url>.*?)(?P=quote)",
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
META_REFRESH = re.compile(
    r"(?P<prefix><meta\b(?=[^>]*\bhttp-equiv\s*=\s*['\"]?refresh['\"]?)[^>]*"
    r"\bcontent\s*=\s*)(?P<quote>['\"])(?P<value>.*?)(?P=quote)",
    re.IGNORECASE | re.DOTALL,
)
SCRIPT_BLOCK = re.compile(
    r"(?P<open><script\b[^>]*>)(?P<body>.*?)(?P<close></script\s*>)",
    re.IGNORECASE | re.DOTALL,
)
STYLE_BLOCK = re.compile(
    r"(?P<open><style\b[^>]*>)(?P<css>.*?)(?P<close></style\s*>)",
    re.IGNORECASE | re.DOTALL,
)
STYLE_ATTRIBUTE = re.compile(
    r"(?P<prefix>\bstyle\s*=\s*)(?P<quote>['\"])(?P<css>.*?)(?P=quote)",
    re.IGNORECASE | re.DOTALL,
)
LINK_URL = re.compile(r"<(?P<url>[^<>]+)>")
ROOT_ASSET_STRING = re.compile(
    r"(?P<quote>['\"`])(?P<url>/(?:"
    r"(?:_next|assets|static|cdn-cgi)/[^'\"`\\\s]*|"
    r"(?:manifest(?:\.json|\.webmanifest)|favicon(?:\.ico|\.png|\.svg)|"
    r"apple-touch-icon(?:\.png)?|robots\.txt|sitemap\.xml|[a-f0-9]{4,}/)"
    r"))",
    re.IGNORECASE,
)
SCRIPT_OR_LINK_TAG = re.compile(r"<(?:script|link)\b[^>]*>", re.IGNORECASE | re.DOTALL)
INTEGRITY_ATTRIBUTE = re.compile(
    r"\s+integrity\s*=\s*(?P<quote>['\"]).*?(?P=quote)",
    re.IGNORECASE | re.DOTALL,
)


def _host_allowed(host: str, allowed: tuple[str, ...]) -> bool:
    normalized = host.lower().rstrip(".")
    if any(
        normalized == item.lower().lstrip(".").rstrip(".")
        or normalized.endswith("." + item.lower().lstrip(".").rstrip("."))
        for item in allowed
    ):
        return True
    site = _registrable_domain(normalized)
    return "." in site and any(
        _registrable_domain(item.lower().lstrip(".").rstrip(".")) == site for item in allowed
    )


def _registrable_domain(host: str) -> str:
    """Conservative eTLD+1 approximation for same-site app/account redirects."""
    normalized = host.lower().rstrip(".")
    for suffix in PRIVATE_HOSTING_SUFFIXES:
        if normalized.endswith("." + suffix):
            prefix = normalized[: -(len(suffix) + 1)]
            return prefix.rsplit(".", 1)[-1] + "." + suffix
    labels = normalized.split(".")
    if len(labels) < 2:
        return host.lower().rstrip(".")
    common_second_level = {"ac", "co", "com", "edu", "gov", "net", "org"}
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in common_second_level:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _url_origin(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))


def proxy_hostname_candidates(headers: Mapping[str, str], fallback: str | None) -> tuple[str, ...]:
    """Return configured-host candidates as seen through Caddy or Cloudflare."""
    values = [headers.get("x-forwarded-host", "").split(",", 1)[0], fallback or ""]
    output: list[str] = []
    for raw in values:
        value = raw.strip().lower().rstrip(".")
        if value.count(":") == 1:
            value = value.split(":", 1)[0]
        if value and value not in output:
            output.append(value)
    return tuple(output)


def upstream_initiator_url(
    launch: ConsumedLaunch, browser_referer: str | None, proxy_prefix: str
) -> str:
    """Recover the logical upstream page that initiated a proxied request.

    Every page has the public proxy as its browser origin. For upstream CORS and
    authentication, however, a request from chatgpt.com to auth.openai.com must
    retain chatgpt.com as its Origin/Referer rather than pretending it originated
    at auth.openai.com.
    """
    fallback = launch.upstream_url
    if not browser_referer:
        return fallback
    referer = urlparse(browser_referer)
    marker = proxy_prefix + "/"
    if not referer.path.startswith(marker):
        return fallback
    try:
        return resolve_target(
            launch,
            referer.path[len(marker) :],
            referer.query,
        )
    except HTTPException:
        return fallback


def upstream_fetch_site(initiator_url: str, target_url: str) -> str:
    initiator = urlparse(initiator_url)
    target = urlparse(target_url)
    if (
        initiator.scheme == target.scheme
        and initiator.hostname == target.hostname
        and (initiator.port or 443) == (target.port or 443)
    ):
        return "same-origin"
    initiator_host = (initiator.hostname or "").lower()
    target_host = (target.hostname or "").lower()
    if (
        initiator_host
        and target_host
        and (_registrable_domain(initiator_host) == _registrable_domain(target_host))
    ):
        return "same-site"
    return "cross-site"


def _cookie_recency(cookie: dict) -> float:
    value = cookie.get("updated_at") or cookie.get("created_at")
    if isinstance(value, datetime):
        return value.timestamp()
    if isinstance(value, (int, float)):
        return float(value)
    return 0.0


def _matching_cookies(launch: ConsumedLaunch, target: str) -> list[dict]:
    parsed = urlparse(target)
    host = (parsed.hostname or "").lower()
    path = parsed.path or "/"
    selected: dict[tuple[str, str, str], dict] = {}
    for cookie in launch.cookies:
        domain = str(cookie["domain"]).lower().lstrip(".")
        # Preserve the browser's real cookie scope. A host-only cookie for
        # account.example.com must never be sent to api.example.com merely
        # because both hosts share an eTLD+1; duplicate session names can make
        # SSR appear logged out while a later client request looks authenticated.
        if host != domain and not host.endswith("." + domain):
            continue
        cookie_path = str(cookie.get("path") or "/")
        # RFC 6265 path-match: /admin matches /admin and /admin/x, not
        # /administrator. More specific cookies must be sent first.
        if not (
            path == cookie_path
            or path.startswith(cookie_path.rstrip("/") + "/")
            or cookie_path == "/"
        ):
            continue
        # Leading dots have no matching meaning in current cookie semantics.
        # Old imports could therefore create two effective copies of one cookie.
        key = (str(cookie["name"]), domain, cookie_path)
        existing = selected.get(key)
        if existing is None or _cookie_recency(cookie) >= _cookie_recency(existing):
            selected[key] = cookie

    values = list(selected.values())
    values.sort(
        key=lambda cookie: (
            len(str(cookie.get("path") or "/")),
            len(str(cookie["domain"]).lstrip(".")),
            _cookie_recency(cookie),
        ),
        reverse=True,
    )
    return values


def _cookie_header(launch: ConsumedLaunch, target: str) -> str:
    return "; ".join(
        f"{cookie['name']}={cookie['value']}" for cookie in _matching_cookies(launch, target)
    )


def _client_cookie_namespace(service_id: str) -> str:
    return f"__Secure-cookie_core_client_{service_id}_"


def _root_grant_cookie_name(service_id: str) -> str:
    return f"__Secure-cookie_core_proxy_{service_id}"


def escaped_proxy_service_id(
    path: str,
    browser_referer: str | None,
    browser_cookies: Mapping[str, str],
    public_hostname: str | None = None,
) -> str | None:
    """Recover any root URL that escaped a path-based service proxy.

    Framework routers, location assignments, workers and third-party loaders
    can bypass JavaScript monkey-patches. The same-origin Referer identifies the
    owning service and a per-service root cookie proves that its grant was
    issued to this browser. Core API routes are deliberately never recovered.
    """
    if not path.startswith("/") or any(
        path == root.rstrip("/") or path.startswith(root) for root in CORE_RESERVED_PATHS
    ):
        return None
    if not browser_referer:
        return None
    referer = urlparse(browser_referer)
    if public_hostname and (referer.hostname or "").lower().rstrip(".") != public_hostname.lower().rstrip(
        "."
    ):
        return None
    referer_path = referer.path
    match = re.match(r"^/proxy/([^/]+)(?:/|$)", referer_path)
    if not match:
        return None
    service_id = unquote(match.group(1))
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", service_id):
        return None
    return service_id if browser_cookies.get(_root_grant_cookie_name(service_id)) else None


def _expire_stale_client_cookies(
    response: Response,
    browser_cookies: dict[str, str],
    *,
    service_id: str,
    proxy_prefix: str,
    secure: bool,
) -> int:
    """Remove JS-originated cookies before starting from a fresh vault copy.

    Client-side cookies intentionally override stored cookies during an active
    session. Without this reset, values left by an older/logged-out session keep
    winning after a new launch, even when the administrator imported valid
    cookies into the vault.
    """
    namespace = _client_cookie_namespace(service_id)
    cookie_paths = {"/", proxy_prefix + "/"}
    expired = 0
    for raw_name in browser_cookies:
        if not raw_name.startswith(namespace):
            continue
        expired += 1
        for cookie_path in cookie_paths:
            response.delete_cookie(
                raw_name,
                path=cookie_path,
                secure=secure,
                samesite="lax",
            )
    return expired


def _seed_script_visible_cookies(
    response: Response,
    launch: ConsumedLaunch,
    target: str,
    *,
    proxy_prefix: str,
    secure: bool,
) -> int:
    """Expose only originally non-HttpOnly cookies under the proxy namespace.

    A real browser makes these values available to ``document.cookie``. Keeping
    them exclusively in the server vault breaks CSRF and client-state logic,
    leaving authenticated pages visible but their actions non-functional.
    """
    namespace = _client_cookie_namespace(launch.service_id)
    seeded = 0
    visible: dict[str, dict] = {}
    for cookie in _matching_cookies(launch, target):
        if bool(cookie.get("httpOnly", True)):
            continue
        visible.setdefault(str(cookie["name"]), cookie)

    for cookie in visible.values():
        response.set_cookie(
            namespace + quote(str(cookie["name"]), safe=""),
            str(cookie["value"]),
            secure=secure,
            httponly=False,
            samesite="lax",
            path=proxy_prefix + "/",
        )
        seeded += 1
    return seeded


def _upstream_cookie_header(
    launch: ConsumedLaunch, target: str, browser_cookies: dict[str, str]
) -> str:
    """Merge only JS-originated, service-namespaced browser cookies.

    Upstream Set-Cookie values never enter this jar; they remain in the vault.
    """
    namespace = _client_cookie_namespace(launch.service_id)
    client_values: dict[str, str] = {}
    for raw_name, value in browser_cookies.items():
        if not raw_name.startswith(namespace):
            continue
        name = unquote(raw_name[len(namespace) :])
        if (
            not name
            or len(name) > 250
            or any(char in name for char in " \t\r\n;,=")
            or any(char in value for char in "\r\n;")
            or (launch.allowed_cookie_names and name not in launch.allowed_cookie_names)
        ):
            continue
        client_values[name] = value

    stored = _cookie_header(launch, target)
    stored_parts = []
    for item in stored.split("; ") if stored else []:
        name = item.split("=", 1)[0]
        if name not in client_values:
            stored_parts.append(item)
    stored_parts.extend(f"{name}={value}" for name, value in client_values.items())
    return "; ".join(stored_parts)


def _path_allowed(path: str, allowed: tuple[str, ...]) -> bool:
    # These are static/orchestration endpoints, not application endpoints. A
    # restricted service still needs them to complete a Cloudflare challenge.
    if any(path.startswith(prefix) for prefix in CHALLENGE_PLATFORM_PATHS):
        return True
    return any(
        prefix == "/" or path == prefix or path.startswith(prefix.rstrip("/") + "/")
        for prefix in allowed
    )


def _is_public_asset_host(host: str) -> bool:
    normalized = host.lower().rstrip(".")
    if normalized in DIRECT_PUBLIC_ASSET_HOSTS:
        return True
    return any(normalized.endswith(suffix) for suffix in DIRECT_PUBLIC_ASSET_SUFFIXES)


def _must_stay_in_browser(host: str, path: str) -> bool:
    normalized_host = host.lower().rstrip(".")
    normalized_path = path or "/"
    if normalized_host in DIRECT_BROWSER_HOSTS:
        return True
    return any(
        normalized_host == direct_host
        and (normalized_path == direct_path.rstrip("/") or normalized_path.startswith(direct_path))
        for direct_host, direct_path in DIRECT_BROWSER_PATHS
    )


def _is_optional_telemetry_path(path: str) -> bool:
    return "/" + path.lstrip("/").rstrip("/") == "/cdn-cgi/rum"


def _is_localstorage_sync_path(path: str) -> bool:
    """Match only the proxy-owned endpoint, never a similarly named upstream path."""
    return path.strip("/") == "__localstorage/sync"


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
    if not _path_allowed(target_path, launch.allowed_paths):
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
    if _must_stay_in_browser(host, parsed.path):
        return raw_url
    # DreamFace publishes immutable Nuxt bundles on a public CDN. Relaying
    # hundreds of these files through one server IP triggers its CDN rate
    # limiter; browsers should fetch them directly as the original page does.
    if _is_public_asset_host(host):
        return absolute
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
    main_host = (urlparse(launch.upstream_url).hostname or "").lower()
    payload = json.dumps(
        {
            "prefix": prefix,
            "proxyOrigin": public_base_url.rstrip("/"),
            "hosts": hosts,
            "cookieNamespace": _client_cookie_namespace(launch.service_id),
            "directBrowserPaths": DIRECT_BROWSER_PATHS,
            "directBrowserHosts": list(DIRECT_BROWSER_HOSTS),
            "directAssetHosts": list(DIRECT_PUBLIC_ASSET_HOSTS),
            "directAssetSuffixes": list(DIRECT_PUBLIC_ASSET_SUFFIXES),
            "lockAccountProfile": main_host in {"chatgpt.com", "chat.openai.com"},
            "upstreamOrigin": _url_origin(launch.upstream_url),
            "localStorage": launch.local_storage_items,
        },
        separators=(",", ":"),
    ).replace("</", "<\\/")
    upstream_json = json.dumps(launch.upstream_url)
    return (
        "<script>(function(){"
        f"const C={payload};"
        "if(typeof window.process==='undefined')window.process={env:{NODE_ENV:'production'}};"
        "const site=h=>{const p=h.toLowerCase().replace(/\\.$/,'').split('.');"
        "const s=new Set(['ac','co','com','edu','gov','net','org']);"
        "return p.length>2&&p.at(-1).length===2&&s.has(p.at(-2))?p.slice(-3).join('.'):p.slice(-2).join('.')};"
        "const ok=h=>C.hosts.some(x=>h===x||h.endsWith('.'+x)||site(h)===site(x));"
        "const direct=u=>C.directBrowserHosts.indexOf(u.hostname.toLowerCase())>=0||"
        "C.directBrowserPaths.some(([h,p])=>u.hostname===h&&"
        "(u.pathname===p.replace(/\\/$/,'')||u.pathname.startsWith(p)));"
        "const assetHost=h=>{"
        "const n=h.toLowerCase().replace(/\\.$/,'');"
        "return C.directAssetHosts.indexOf(n)>=0||"
        "C.directAssetSuffixes.some(s=>n.endsWith(s))};"
        "const map=(v,ws=false)=>{if(typeof v!=='string')return v;"
        "if(C.prefix&&v.startsWith(C.prefix))return v;"
        "try{const u=new URL(v,location.href);if(direct(u))return u.href;"
        "if(u.origin===location.origin){"
        "if(!u.pathname.startsWith(C.prefix))u.pathname=C.prefix+u.pathname;}"
        "else if(assetHost(u.hostname)){return u.href;}"
        "else if(ok(u.hostname)){"
        f"const main=new URL({upstream_json}).hostname;const h=u.hostname;"
        "u.protocol=ws?'wss:':'https:';u.host=new URL(C.proxyOrigin).host;"
        "u.pathname=C.prefix+(h===main?'':'/_host/'+h)+u.pathname;}"
        "return ws?u.href.replace(/^https:/,'wss:'):u.href;}catch(_e){return v;}};"
        "try{Object.defineProperty(window,'__cookieCoreMappedOrigin',{"
        "value:C.upstreamOrigin,writable:false,configurable:true});}catch(_e){}"
        "try{const orig=Object.getOwnPropertyDescriptor(navigator,'userAgent');"
        "if(!orig||orig.configurable){Object.defineProperty(navigator,'userAgentData',{get(){return undefined},configurable:true});}}"
        "catch(_e){}"
        "const f=window.fetch;if(f)window.fetch=(v,o)=>{"
        "if(typeof Request!=='undefined'&&v instanceof Request)"
        "return f.call(window,new Request(map(v.url),v),o);"
        "return f.call(window,v instanceof URL?map(v.href):map(v),o)};"
        "const X=window.XMLHttpRequest;if(X){const xo=XMLHttpRequest.prototype.open;"
        "XMLHttpRequest.prototype.open=function(m,u,...a){return xo.call(this,m,map(u),...a)}};"
        "const sb=navigator.sendBeacon&&navigator.sendBeacon.bind(navigator);"
        "if(sb)navigator.sendBeacon=(u,d)=>sb(map(u),d);"
        "const W=window.WebSocket;if(W){window.WebSocket=function(u,p){"
        "return p===undefined?new W(map(u,true)):new W(map(u,true),p)};"
        "window.WebSocket.prototype=W.prototype;"
        "try{Object.setPrototypeOf(window.WebSocket,W)}catch(_e){}};"
        "const E=window.EventSource;if(E){window.EventSource=function(u,o){return new E(map(u),o)};"
        "window.EventSource.prototype=E.prototype;"
        "try{Object.setPrototypeOf(window.EventSource,E)}catch(_e){}};"
        "for(const k of ['Worker','SharedWorker']){"
        "const O=window[k];if(!O)continue;window[k]=function(u,o){return new O(map(u),o)};"
        "window[k].prototype=O.prototype;try{Object.setPrototypeOf(window[k],O)}catch(_e){}}"
        "const sa=Element.prototype.setAttribute;"
        "const cssUrlRe=/url\\(\\s*(['\"]?)([^)'\"]+?)\\1\\s*\\)/g;"
        "const rewriteCss=function(v){"
        "if(typeof v!=='string'||v.indexOf('url(')<0)return v;"
        "return v.replace(cssUrlRe,function(m,q,u){const r=map(u);return r===u?m:'url('+(q||'')+r+(q||'')+')'})"
        "};"
        "const mapSrcset=function(v){if(typeof v!=='string'||/data:/i.test(v))return v;"
        "return v.split(',').map(function(x){const m=x.trim().match(/^(\\S+)(.*)$/);"
        "return m?map(m[1])+m[2]:x}).join(', ')};"
        "Element.prototype.setAttribute=function(n,v){"
        "if(/^(?:href|src|action|poster|data|formaction)$/i.test(n))v=map(v);"
        "else if(/^srcset$/i.test(n))v=mapSrcset(v);"
        "else if(/^style$/i.test(n))v=rewriteCss(v);"
        "return sa.call(this,n,v)};"
        "for(const [name,prop,mapper] of [['HTMLAnchorElement','href',map],"
        "['HTMLAreaElement','href',map],['HTMLImageElement','src',map],"
        "['HTMLImageElement','srcset',mapSrcset],['HTMLScriptElement','src',map],"
        "['HTMLIFrameElement','src',map],['HTMLLinkElement','href',map],"
        "['HTMLFormElement','action',map],['HTMLSourceElement','src',map],"
        "['HTMLSourceElement','srcset',mapSrcset],['HTMLVideoElement','src',map],"
        "['HTMLAudioElement','src',map]]){const ctor=window[name];if(!ctor)continue;"
        "const d=Object.getOwnPropertyDescriptor(ctor.prototype,prop);"
        "if(d&&d.configurable&&d.set&&d.get)Object.defineProperty(ctor.prototype,prop,{configurable:true,"
        "enumerable:d.enumerable,get:d.get,set(v){d.set.call(this,mapper(v))}});}"
        "const wo=window.open;if(wo)window.open=(u,...a)=>wo.call(window,map(u),...a);"
        "const ps=history.pushState.bind(history),rs=history.replaceState.bind(history);"
        "history.pushState=(s,t,u)=>ps(s,t,u==null?u:map(u));"
        "history.replaceState=(s,t,u)=>rs(s,t,u==null?u:map(u));"
        "if(window.Storage){try{const S=Storage.prototype,raw=window.localStorage,p=C.cookieNamespace+'store:';"
        "const gi=S.getItem,si=S.setItem,ri=S.removeItem,ci=S.clear,ki=S.key;"
        "const ld=Object.getOwnPropertyDescriptor(S,'length'),ln=ld&&ld.get;"
        "const pendingUps=Object.create(null),pendingDel=new Set();let flushTimer=0,flushing=false;"
        "const keys=function(){const out=[];for(let i=0;i<(ln?ln.call(raw):0);i++){const k=ki.call(raw,i);"
        "if(typeof k==='string'&&k.startsWith(p))out.push(k.slice(p.length))}return out};"
        "const apply=function(snap){if(!snap||typeof snap!=='object'||Array.isArray(snap))return;const seen=new Set();"
        "for(const k of Object.keys(snap)){seen.add(k);if(Object.prototype.hasOwnProperty.call(pendingUps,k)||pendingDel.has(k))continue;"
        "const v=String(snap[k]);if(gi.call(raw,p+k)!==v)try{si.call(raw,p+k,v)}catch(_e){}}"
        "for(const k of keys()){if(!seen.has(k)&&!Object.prototype.hasOwnProperty.call(pendingUps,k)&&!pendingDel.has(k))"
        "try{ri.call(raw,p+k)}catch(_e){}}};"
        "apply(C.localStorage&&typeof C.localStorage==='object'?C.localStorage:{});"
        "const syncUrl=function(){return C.prefix+'/__localstorage/sync'};"
        "const hasPending=function(){return Object.keys(pendingUps).length>0||pendingDel.size>0};"
        "const schedule=function(delay=600){if(flushTimer)return;flushTimer=setTimeout(function(){flushTimer=0;flush()},delay)};"
        "const restore=function(ups,del){for(const k of Object.keys(ups)){if(!Object.prototype.hasOwnProperty.call(pendingUps,k)&&!pendingDel.has(k))pendingUps[k]=ups[k]}"
        "for(const k of del){if(!Object.prototype.hasOwnProperty.call(pendingUps,k)&&!pendingDel.has(k))pendingDel.add(k)}};"
        "const flush=function(){if(flushing){if(hasPending())schedule();return}"
        "const ups=Object.assign(Object.create(null),pendingUps),del=Array.from(pendingDel);"
        "if(!Object.keys(ups).length&&!del.length)return;for(const k of Object.keys(ups))delete pendingUps[k];pendingDel.clear();flushing=true;"
        "const body=JSON.stringify({upserts:Object.keys(ups).length?ups:undefined,deletes:del.length?del:undefined});"
        "const f=window.fetch;if(!f){flushing=false;restore(ups,del);schedule(2000);return}"
        "f.call(window,syncUrl(),{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},"
        "cache:'no-store',keepalive:true,body}).then(function(r){if(!r.ok)throw new Error();return r.json()})"
        ".then(function(d){flushing=false;apply(d&&d.snapshot);if(hasPending())schedule()})"
        ".catch(function(){flushing=false;restore(ups,del);schedule(2000)})};"
        "const api={getItem(k){return gi.call(raw,p+String(k))},setItem(k,v){k=String(k);v=String(v);"
        "si.call(raw,p+k,v);pendingUps[k]=v;pendingDel.delete(k);schedule()},removeItem(k){k=String(k);"
        "ri.call(raw,p+k);delete pendingUps[k];pendingDel.add(k);schedule()},clear(){for(const k of keys()){"
        "ri.call(raw,p+k);delete pendingUps[k];pendingDel.add(k)}if(pendingDel.size)schedule()},key(n){return keys()[Number(n)]??null}};"
        "const target=Object.create(S),facade=new Proxy(target,{get(_t,k){if(k==='length')return keys().length;"
        "if(k===Symbol.toStringTag)return 'Storage';if(typeof k==='string'&&Object.prototype.hasOwnProperty.call(api,k))return api[k].bind(api);"
        "if(typeof k==='string'){const v=api.getItem(k);return v===null?undefined:v}return Reflect.get(target,k)},"
        "set(_t,k,v){if(typeof k==='string'){api.setItem(k,v);return true}return false},deleteProperty(_t,k){if(typeof k==='string'){api.removeItem(k);return true}return false},"
        "ownKeys(){return keys()},has(_t,k){return typeof k==='string'&&api.getItem(k)!==null},"
        "getOwnPropertyDescriptor(_t,k){if(typeof k==='string'&&api.getItem(k)!==null)return{configurable:true,enumerable:true,writable:true,value:api.getItem(k)}},"
        "defineProperty(_t,k,d){if(typeof k==='string'&&'value'in d){api.setItem(k,d.value);return true}return false}});"
        "let facadeInstalled=false;try{Object.defineProperty(window,'localStorage',{configurable:true,get:function(){return facade}});"
        "facadeInstalled=window.localStorage===facade}catch(_e){}"
        "if(!facadeInstalled){S.getItem=function(k){return this===raw?api.getItem(k):gi.call(this,k)};"
        "S.setItem=function(k,v){return this===raw?api.setItem(k,v):si.call(this,k,v)};"
        "S.removeItem=function(k){return this===raw?api.removeItem(k):ri.call(this,k)};"
        "S.clear=function(){return this===raw?api.clear():ci.call(this)};S.key=function(n){return this===raw?api.key(n):ki.call(this,n)};"
        "if(ld&&ld.configurable)Object.defineProperty(S,'length',{configurable:true,enumerable:ld.enumerable,"
        "get:function(){return this===raw?keys().length:ln.call(this)}})}"
        "if(window.StorageEvent&&window.dispatchEvent)addEventListener('storage',function(e){try{"
        "if(e.storageArea!==raw||typeof e.key!=='string'||!e.key.startsWith(p))return;e.stopImmediatePropagation();"
        "dispatchEvent(new StorageEvent('storage',{key:e.key.slice(p.length),oldValue:e.oldValue,newValue:e.newValue,"
        "url:e.url,storageArea:facade}))}catch(_e){}},{capture:true});"
        "addEventListener('pagehide',flush,{capture:true,passive:true});"
        "document.addEventListener('visibilitychange',function(){if(document.visibilityState==='hidden')flush()},{capture:true,passive:true});"
        "if(window.indexedDB){const io=indexedDB.open.bind(indexedDB),"
        "id=indexedDB.deleteDatabase.bind(indexedDB);indexedDB.open=(n,...a)=>io(p+n,...a);"
        "indexedDB.deleteDatabase=n=>id(p+n)}"
        "const BC=window.BroadcastChannel;if(BC){window.BroadcastChannel=function(n){return new BC(p+n)};"
        "window.BroadcastChannel.prototype=BC.prototype;Object.setPrototypeOf(window.BroadcastChannel,BC)}"
        "}catch(_e){}}"
        "if(navigator.serviceWorker&&navigator.serviceWorker.register){try{"
        "const sr=navigator.serviceWorker.register.bind(navigator.serviceWorker);"
        "navigator.serviceWorker.register=function(u,o){const x=Object.assign({},o||{});"
        "if(x.scope)x.scope=map(x.scope);return sr(map(u),x)}}catch(_e){}}"
        "if(C.lockAccountProfile){"
        "const sel='[data-testid=\"accounts-profile-button\"]';"
        "const blocked=function(e){const t=e.target;return t instanceof Element&&!!t.closest(sel)};"
        "const stop=function(e){if(!blocked(e))return;e.preventDefault();e.stopPropagation();"
        "e.stopImmediatePropagation();const b=e.target.closest(sel);if(b&&b.blur)b.blur()};"
        "for(const ev of ['pointerdown','mousedown','touchstart','click','dblclick','contextmenu'])"
        "document.addEventListener(ev,stop,{capture:true,passive:false});"
        "document.addEventListener('keydown',function(e){"
        "if(blocked(e)||((e.ctrlKey||e.metaKey)&&e.key===',')){e.preventDefault();"
        "e.stopPropagation();e.stopImmediatePropagation()}},{capture:true});"
        "const style=document.createElement('style');style.dataset.jbtoolsProfileLock='';"
        "style.textContent=sel+'{cursor:not-allowed!important;position:relative!important;user-select:none!important}'"
        "+sel+' .jbtools-profile-lock{display:grid!important;place-items:center!important;flex:0 0 auto!important;'"
        "+'width:28px!important;height:28px!important;margin-inline-start:auto!important;border-radius:9px!important;'"
        "+'color:#c4b5fd!important;background:rgba(124,58,237,.14)!important;'"
        "+'border:1px solid rgba(167,139,250,.25)!important;box-shadow:0 0 16px rgba(124,58,237,.12)!important}'"
        "+sel+' .jbtools-profile-lock svg{width:15px!important;height:15px!important}'"
        "+sel+':hover .jbtools-profile-lock{background:rgba(124,58,237,.2)!important}';"
        "(document.head||document.documentElement).appendChild(style);"
        "const lock=function(){document.querySelectorAll(sel).forEach(function(b){"
        "b.setAttribute('aria-disabled','true');b.setAttribute('aria-expanded','false');"
        "b.setAttribute('aria-label','Perfil protegido pela JBTools');b.tabIndex=-1;"
        "if(b.querySelector('.jbtools-profile-lock'))return;const badge=document.createElement('span');"
        "badge.className='jbtools-profile-lock';badge.setAttribute('aria-hidden','true');"
        'badge.innerHTML=\'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" \''
        '+\'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">\''
        '+\'<rect width="14" height="11" x="5" y="10" rx="2"/>\''
        "+'<path d=\"M8 10V7a4 4 0 0 1 8 0v3\"/></svg>';b.appendChild(badge)})};"
        "lock();new MutationObserver(lock).observe(document.documentElement,{childList:true,subtree:true});"
        "}"
        "let dc=Object.getOwnPropertyDescriptor(Document.prototype,'cookie');"
        "if(dc&&dc.configurable&&dc.get&&dc.set)Object.defineProperty(Document.prototype,'cookie',{"
        "configurable:dc.configurable,enumerable:dc.enumerable,"
        "get:function(){return dc.get.call(this).split(/;\\s*/).filter(Boolean).flatMap(function(x){"
        "const i=x.indexOf('=');if(i<0||!x.slice(0,i).startsWith(C.cookieNamespace))return [];"
        "try{return [decodeURIComponent(x.slice(C.cookieNamespace.length,i))+x.slice(i)]}"
        "catch(_e){return []}}).join('; ')},"
        "set:function(v){if(typeof v!=='string')return;const p=v.split(';'),i=p[0].indexOf('=');if(i<=0)return;"
        "const n=p[0].slice(0,i).trim(),value=p[0].slice(i+1);"
        "const attrs=p.slice(1).map(function(x){return x.trim()}).filter(function(x){return /^(?:expires|max-age)=/i.test(x)});"
        "dc.set.call(this,C.cookieNamespace+encodeURIComponent(n)+'='+value+'; Path='+C.prefix+"
        "'/; Secure; SameSite=Lax'+(attrs.length?'; '+attrs.join('; '):''));}"
        "});"
        "})();</script>"
    )


def challenge_can_be_relayed(
    current_target: str, public_base_url: str, *, transparent: bool = False
) -> bool:
    """Only relay a managed challenge on the exact protected origin.

    A transparent/path-preserving proxy is still a different web origin when its
    hostname differs from the upstream. Cloudflare challenge tokens and clearance
    cookies are scoped to the protected hostname, so replaying that HTML on a
    vanity hostname cannot complete successfully.

    ``transparent`` remains in the signature for compatibility with callers, but
    deliberately does not weaken the same-origin requirement.
    """
    target = urlparse(current_target)
    public = urlparse(public_base_url)
    return (
        target.scheme == "https"
        and public.scheme == "https"
        and (target.hostname or "").lower() == (public.hostname or "").lower()
        and (target.port or 443) == (public.port or 443)
    )


def rewrite_cloudflare_challenge(
    body: bytes,
    content_type: str,
    *,
    current_target: str,
    launch: ConsumedLaunch,
    proxy_prefix: str,
    public_base_url: str,
) -> bytes:
    """Route Cloudflare's root-relative orchestration URLs through this proxy.

    Challenge HTML is deliberately not given the normal runtime adapter: its
    scripts are integrity-sensitive and ship their own CSP/nonces.
    """
    match = re.search(r"charset=([^;\s]+)", content_type, re.IGNORECASE)
    encoding = match.group(1).strip("\"'") if match else "utf-8"
    try:
        text = body.decode(encoding)
    except (LookupError, UnicodeDecodeError):
        text = body.decode("utf-8", errors="replace")
        encoding = "utf-8"

    def map_url(value: str) -> str:
        return browser_url(
            value,
            current_target=current_target,
            launch=launch,
            proxy_prefix=proxy_prefix,
            public_base_url=public_base_url,
        )

    text = URL_ATTRIBUTE.sub(
        lambda item: (
            f"{item.group('prefix')}{item.group('quote')}"
            f"{map_url(item.group('url'))}{item.group('quote')}"
        ),
        text,
    )
    # The orchestrator creates script URLs from JS string literals instead of
    # HTML attributes. Only touch Cloudflare-owned infrastructure paths.
    challenge_root = map_url("/cdn-cgi/").rstrip("/") + "/"
    text = re.sub(
        r"(?P<quote>['\"`])/(?:cdn-cgi)/",
        lambda item: item.group("quote") + challenge_root,
        text,
        flags=re.IGNORECASE,
    )
    # Some versions JSON-escape slashes inside the bootstrap configuration.
    escaped_root = challenge_root.replace("/", r"\/")
    text = re.sub(
        r"(?P<quote>['\"`])\\/cdn-cgi\\/",
        lambda item: item.group("quote") + escaped_root,
        text,
        flags=re.IGNORECASE,
    )
    # After a successful solve the bootstrap navigates back through cUPMDTk.
    # Keep that navigation inside the cookie-holding proxy as well.
    text = re.sub(
        r"(?P<prefix>\bcUPMDTk\s*:\s*)(?P<quote>['\"])(?P<url>/[^'\"]*)"
        r"(?P=quote)",
        lambda item: (
            item.group("prefix")
            + item.group("quote")
            + map_url(item.group("url"))
            + item.group("quote")
        ),
        text,
        flags=re.IGNORECASE,
    )
    return text.encode(encoding, errors="replace")


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

    def replace_css(value: str) -> str:
        value = CSS_URL.sub(
            lambda item: (
                f"{item.group('prefix')}{item.group('quote')}"
                f"{replace_url(item.group('url'))}{item.group('quote')}"
                f"{item.group('suffix')}"
            ),
            value,
        )
        return CSS_IMPORT.sub(
            lambda item: (
                f"{item.group('prefix')}{item.group('quote')}"
                f"{replace_url(item.group('url'))}{item.group('quote')}"
            ),
            value,
        )

    def replace_meta_refresh(item: re.Match) -> str:
        value = item.group("value")
        match = re.search(r"(?P<prefix>\burl\s*=\s*)(?P<url>.*)$", value, re.IGNORECASE)
        if not match:
            return item.group(0)
        raw_url = match.group("url").strip().strip("'\"")
        rewritten = value[: match.start("prefix")] + match.group("prefix") + replace_url(raw_url)
        return item.group("prefix") + item.group("quote") + rewritten + item.group("quote")

    def rewrite_nuxt_base(value: str) -> str:
        if not proxy_prefix or "__NUXT" not in value:
            return value
        base = proxy_prefix.rstrip("/") + "/"
        # Nuxt's router reads this before mounting. Giving it the proxy prefix
        # makes the browser path /proxy/<id>/ resolve to Nuxt route / and keeps
        # router.push('/aitools') inside the same service.
        value = re.sub(
            r"(?P<key>(?:['\"]?baseURL['\"]?)\s*:\s*)(?P<quote>['\"])/(?P=quote)",
            lambda item: item.group("key") + item.group("quote") + base + item.group("quote"),
            value,
        )
        return value.replace(
            r"\"baseURL\":\"/\"",
            r"\"baseURL\":\"" + base + r"\"",
        )

    if content_type.lower().startswith("text/html"):
        # SRI authenticates the original bytes. This proxy may rewrite script
        # URLs or JavaScript payloads, so retaining an upstream digest makes the
        # browser reject otherwise valid resources before execution.
        text = SCRIPT_OR_LINK_TAG.sub(
            lambda item: INTEGRITY_ATTRIBUTE.sub("", item.group(0)),
            text,
        )
        # Do not run markup/CSS regexes through inline JavaScript. Expressions
        # such as /url\((...)\)/gi were previously mistaken for CSS url() and
        # rewritten into syntactically invalid JavaScript.
        scripts: list[str] = []

        def hold_script(item: re.Match) -> str:
            scripts.append(item.group("body"))
            return (
                item.group("open")
                + f"\x00COOKIE_CORE_SCRIPT_{len(scripts) - 1}\x00"
                + item.group("close")
            )

        text = SCRIPT_BLOCK.sub(hold_script, text)
        text = META_CSP.sub("", text)
        text = META_REFRESH.sub(replace_meta_refresh, text)
        text = URL_ATTRIBUTE.sub(
            lambda m: (
                f"{m.group('prefix')}{m.group('quote')}"
                f"{replace_url(m.group('url'))}{m.group('quote')}"
            ),
            text,
        )
        text = UNQUOTED_URL_ATTRIBUTE.sub(
            lambda m: f"{m.group('prefix')}{replace_url(m.group('url'))}",
            text,
        )
        text = SRCSET_ATTRIBUTE.sub(replace_srcset, text)
        text = STYLE_BLOCK.sub(
            lambda item: item.group("open") + replace_css(item.group("css")) + item.group("close"),
            text,
        )
        text = STYLE_ATTRIBUTE.sub(
            lambda item: (
                item.group("prefix")
                + item.group("quote")
                + replace_css(item.group("css"))
                + item.group("quote")
            ),
            text,
        )
        for index, script_block in enumerate(scripts):
            text = text.replace(f"\x00COOKIE_CORE_SCRIPT_{index}\x00", script_block)
        text = rewrite_nuxt_base(text)
        # Next.js also serializes chunk/preload paths inside executable
        # ``self.__next_f.push(...)`` bootstrap scripts. This intentionally
        # narrow replacement only touches known static roots and therefore
        # cannot reinterpret or mutate JavaScript regular expressions.
        text = ROOT_ASSET_STRING.sub(
            lambda item: item.group("quote") + replace_url(item.group("url")),
            text,
        )
    elif "css" in content_type.lower():
        text = replace_css(text)

    if content_type.lower().startswith(("application/xml", "text/xml", "image/svg+xml")):
        text = URL_ATTRIBUTE.sub(
            lambda m: (
                f"{m.group('prefix')}{m.group('quote')}"
                f"{replace_url(m.group('url'))}{m.group('quote')}"
            ),
            text,
        )
        text = UNQUOTED_URL_ATTRIBUTE.sub(
            lambda m: f"{m.group('prefix')}{replace_url(m.group('url'))}",
            text,
        )
        text = STYLE_BLOCK.sub(
            lambda item: item.group("open") + replace_css(item.group("css")) + item.group("close"),
            text,
        )

    if content_type.lower().startswith("application/manifest+json"):
        try:
            manifest = json.loads(text)

            def rewrite_manifest(value):
                if isinstance(value, str):
                    return replace_url(value)
                if isinstance(value, list):
                    return [rewrite_manifest(item) for item in value]
                if isinstance(value, dict):
                    return {key: rewrite_manifest(item) for key, item in value.items()}
                return value

            text = json.dumps(
                rewrite_manifest(manifest),
                ensure_ascii=False,
                separators=(",", ":"),
            )
        except (json.JSONDecodeError, TypeError):
            pass

    # React Server Components and framework bootstrap payloads can schedule
    # root-relative assets without creating an HTML element first. The runtime
    # DOM hooks never see those URLs, so map only well-known asset roots here.
    if content_type.lower().startswith("text/x-component"):
        text = ROOT_ASSET_STRING.sub(
            lambda item: item.group("quote") + replace_url(item.group("url")),
            text,
        )

    # Absolute URLs also occur inside JSON and JavaScript configuration objects.
    main = (urlparse(launch.upstream_url).hostname or "").lower()
    proxy_origin = urlparse(public_base_url)

    # These endpoints validate the real browser origin and must never be routed
    # through the server proxy. Attribute/runtime rewriting already respects the
    # rule, but the generic absolute-origin pass below previously rewrote the
    # same URL a second time and produced malformed Google GSI JSON responses.
    direct_fragments: list[str] = []

    def hold_direct_browser_path(item: re.Match) -> str:
        direct_fragments.append(item.group(0))
        return f"\x00COOKIE_CORE_DIRECT_{len(direct_fragments) - 1}\x00"

    for direct_host, direct_path in DIRECT_BROWSER_PATHS:
        text = re.sub(
            rf"https?://{re.escape(direct_host)}{re.escape(direct_path)}",
            hold_direct_browser_path,
            text,
            flags=re.I,
        )
    for direct_host in DIRECT_BROWSER_HOSTS:
        text = re.sub(
            rf"https?://{re.escape(direct_host)}(?=[:/\"'])",
            hold_direct_browser_path,
            text,
            flags=re.I,
        )

    def replace_allowed_origin(item: re.Match, *, websocket: bool = False) -> str:
        actual_host = item.group("hostname").lower()
        if _is_public_asset_host(actual_host):
            return item.group(0)
        host_part = "" if actual_host == main else f"/_host/{actual_host}"
        scheme = "wss" if websocket else proxy_origin.scheme
        return f"{scheme}://{proxy_origin.netloc}{proxy_prefix}{host_part}"

    for allowed in sorted(launch.allowed_domains, key=len, reverse=True):
        host = allowed.lower().lstrip(".")
        text = re.sub(
            rf"https?://(?P<hostname>(?:[a-z0-9-]+\.)*{re.escape(host)})(?::\d+)?"
            rf"(?=[/\"'])",
            replace_allowed_origin,
            text,
            flags=re.I,
        )
        text = re.sub(
            rf"wss?://(?P<hostname>(?:[a-z0-9-]+\.)*{re.escape(host)})(?::\d+)?"
            rf"(?=[/\"'])",
            lambda item: replace_allowed_origin(item, websocket=True),
            text,
            flags=re.I,
        )

    for index, original in enumerate(direct_fragments):
        text = text.replace(f"\x00COOKIE_CORE_DIRECT_{index}\x00", original)

    if content_type.lower().startswith("text/html"):
        script = _runtime_script(launch, proxy_prefix, public_base_url)
        head = re.search(r"<head(?:\s[^>]*)?>", text, re.IGNORECASE)
        if head:
            text = text[: head.end()] + script + text[head.end() :]
        else:
            text = script + text
    return text.encode(encoding, errors="replace")


def rewrite_link_header(
    value: str,
    *,
    current_target: str,
    launch: ConsumedLaunch,
    proxy_prefix: str,
    public_base_url: str,
) -> str:
    """Rewrite RFC 8288 preload targets such as Next.js font Link headers."""
    return LINK_URL.sub(
        lambda item: (
            "<"
            + browser_url(
                item.group("url"),
                current_target=current_target,
                launch=launch,
                proxy_prefix=proxy_prefix,
                public_base_url=public_base_url,
            )
            + ">"
        ),
        value,
    )


def rewrite_single_url_header(
    value: str,
    *,
    current_target: str,
    launch: ConsumedLaunch,
    proxy_prefix: str,
    public_base_url: str,
) -> str:
    """Rewrite headers whose entire value is one optionally quoted URL."""
    stripped = value.strip()
    quote_char = stripped[0] if stripped[:1] in {'"', "'"} else ""
    raw_url = stripped[1:-1] if quote_char and stripped.endswith(quote_char) else stripped
    rewritten = browser_url(
        raw_url,
        current_target=current_target,
        launch=launch,
        proxy_prefix=proxy_prefix,
        public_base_url=public_base_url,
    )
    return quote_char + rewritten + quote_char if quote_char else rewritten


def proxy_csp() -> str:
    challenge_sources = " ".join(CHALLENGE_SCRIPT_ORIGINS)
    return (
        "default-src 'self' https: http: data: blob: filesystem:; "
        "base-uri 'self' https: http:; object-src 'none'; "
        f"script-src 'self' https: http: 'unsafe-inline' 'unsafe-eval' blob: data: {challenge_sources}; "
        "style-src 'self' https: http: 'unsafe-inline' data: blob:; "
        "style-src-attr 'self' https: http: 'unsafe-inline' data:; "
        "style-src-elem 'self' https: http: 'unsafe-inline' data:; "
        "img-src 'self' https: http: data: blob: filesystem: mediastream:; "
        "font-src 'self' https: http: data: blob:; "
        "media-src 'self' https: http: data: blob: mediastream:; "
        f"connect-src 'self' https: http: wss: ws: blob: data:; "
        f"frame-src 'self' https: http: blob: data: {challenge_sources}; "
        "worker-src 'self' https: http: blob: data:; "
        "form-action 'self' https: http:; "
        "manifest-src 'self' https: http: data: blob:; "
        "fenced-frame-src 'self' https: http: blob: data:; "
        "upgrade-insecure-requests"
    )


def is_cloudflare_interstitial(headers: httpx.Headers) -> bool:
    """Use Cloudflare's documented signal instead of guessing from status/body."""
    return headers.get("cf-mitigated", "").lower() == "challenge"


def _has_cf_header(headers: Any) -> bool:
    get_header = getattr(headers, "get", None)
    if not callable(get_header):
        return False
    if "cloudflare" in str(get_header("server", "") or "").lower():
        return True
    items = getattr(headers, "items", None)
    if callable(items):
        return any(str(k).lower().startswith("cf-") for k, _v in items())
    for name in (
        "cf-ray",
        "cf-request-id",
        "cf-cache-status",
        "cf-mitigated",
    ):
        if get_header(name, ""):
            return True
    return False


def _replace_response_header(headers: dict[str, str], name: str, value: str) -> None:
    for existing in list(headers):
        if existing.lower() == name.lower():
            headers.pop(existing)
    headers[name.lower()] = value


def _fix_response_content_type(headers: dict[str, str], target_url: str) -> None:
    """Override broken Content-Type headers for static assets when the CDN
    returns generic application/octet-stream instead of the correct type."""
    current = headers.get("content-type", "") or ""
    candidate = current.lower().split(";", 1)[0].strip()
    if candidate and candidate not in {
        "application/octet-stream",
        "application/force-download",
        "binary/octet-stream",
        "",
    }:
        return
    parsed = urlparse(target_url)
    path = unquote(parsed.path or "")
    if not path or path.endswith("/"):
        return
    _, dot_ext = path.rsplit(".", 1) if "." in path.rsplit("/", 1)[-1] else ("", "")
    if not dot_ext:
        return
    ext = "." + dot_ext.lower()
    override = MIME_OVERRIDE_BY_EXTENSION.get(ext)
    if override:
        _replace_response_header(headers, "content-type", override)


def launch_loading_response(destination: str) -> HTMLResponse:
    """Render the branded handoff shown while the browser commits session cookies."""
    target = json.dumps(destination).replace("</", "<\\/")
    fallback = escape(destination, quote=True)
    body = f"""<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="theme-color" content="#07090f">
  <title>Carregando produto JBTools</title>
  <style>
    :root {{ color-scheme: dark; --violet:#8b5cf6; --cyan:#22d3ee; --ink:#07090f; }}
    * {{ box-sizing:border-box; }}
    html,body {{ width:100%; height:100%; margin:0; overflow:hidden; }}
    body {{
      display:grid; place-items:center; color:#f8fafc;
      font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
      background:
        radial-gradient(circle at 20% 15%,rgba(139,92,246,.18),transparent 35%),
        radial-gradient(circle at 82% 84%,rgba(34,211,238,.12),transparent 38%),var(--ink);
    }}
    body::before {{
      content:""; position:fixed; inset:0; opacity:.16; pointer-events:none;
      background-image:linear-gradient(rgba(255,255,255,.035) 1px,transparent 1px),
        linear-gradient(90deg,rgba(255,255,255,.035) 1px,transparent 1px);
      background-size:42px 42px; mask-image:radial-gradient(circle,#000,transparent 75%);
    }}
    .glow {{
      position:fixed; width:34rem; height:34rem; border-radius:50%; filter:blur(90px);
      background:linear-gradient(135deg,rgba(124,58,237,.17),rgba(6,182,212,.09));
      animation:breathe 3.2s ease-in-out infinite;
    }}
    main {{ position:relative; z-index:1; display:grid; justify-items:center; padding:32px; text-align:center; }}
    .orbit {{ position:relative; width:132px; height:132px; display:grid; place-items:center; }}
    .orbit::before,.orbit::after {{ content:""; position:absolute; border-radius:50%; inset:0; }}
    .orbit::before {{
      border:1px solid rgba(255,255,255,.11); border-top-color:var(--violet);
      border-right-color:var(--cyan); animation:spin 1.8s linear infinite;
      box-shadow:0 0 35px rgba(124,58,237,.16);
    }}
    .orbit::after {{
      inset:12px; border:1px dashed rgba(255,255,255,.13); animation:spin 7s linear infinite reverse;
    }}
    .mark {{
      width:80px; height:80px; display:grid; place-items:center; border-radius:24px;
      font-weight:900; font-size:27px; letter-spacing:-2px; transform:rotate(-3deg);
      background:linear-gradient(145deg,rgba(255,255,255,.13),rgba(255,255,255,.035));
      border:1px solid rgba(255,255,255,.14); box-shadow:inset 0 1px rgba(255,255,255,.16),0 18px 45px #0008;
      backdrop-filter:blur(18px);
    }}
    .mark span {{
      background:linear-gradient(90deg,#fff 8%,#c4b5fd 48%,#67e8f9 92%);
      background-clip:text; color:transparent;
    }}
    h1 {{ margin:34px 0 8px; font-size:clamp(24px,4vw,38px); letter-spacing:-.04em; line-height:1.1; }}
    h1 strong {{
      font-weight:800; background:linear-gradient(90deg,#a78bfa,#67e8f9,#a78bfa);
      background-size:200% auto; background-clip:text; color:transparent; animation:shine 2.4s linear infinite;
    }}
    p {{ margin:0; color:#94a3b8; font-size:14px; letter-spacing:.02em; }}
    .track {{
      width:min(320px,72vw); height:3px; margin-top:30px; border-radius:99px; overflow:hidden;
      background:rgba(255,255,255,.08);
    }}
    .bar {{
      width:42%; height:100%; border-radius:inherit; transform:translateX(-110%);
      background:linear-gradient(90deg,var(--violet),var(--cyan));
      box-shadow:0 0 16px rgba(34,211,238,.6); animation:load 1.25s cubic-bezier(.65,0,.35,1) infinite;
    }}
    .status {{ margin-top:13px; min-height:18px; color:#64748b; font-size:11px; text-transform:uppercase; letter-spacing:.2em; }}
    .dot {{ animation:blink 1.4s infinite both; }} .dot:nth-child(2){{animation-delay:.18s}} .dot:nth-child(3){{animation-delay:.36s}}
    @keyframes spin {{ to{{transform:rotate(360deg)}} }}
    @keyframes breathe {{ 50%{{transform:scale(1.12);opacity:.72}} }}
    @keyframes shine {{ to{{background-position:-200% center}} }}
    @keyframes load {{ 0%{{transform:translateX(-110%)}} 70%,100%{{transform:translateX(245%)}} }}
    @keyframes blink {{ 0%,25%{{opacity:.2}} 50%,100%{{opacity:1}} }}
    @media (prefers-reduced-motion:reduce) {{ *{{animation-duration:.01ms!important;animation-iteration-count:1!important}} }}
  </style>
</head>
<body>
  <div class="glow" aria-hidden="true"></div>
  <main role="status" aria-live="polite">
    <div class="orbit"><div class="mark"><span>JB</span></div></div>
    <h1>Carregando produto <strong>JBTools</strong></h1>
    <p>Preparando seu ambiente seguro</p>
    <div class="track"><div class="bar"></div></div>
    <div class="status">Conectando<span class="dot">.</span><span class="dot">.</span><span class="dot">.</span></div>
  </main>
  <noscript><meta http-equiv="refresh" content="1;url={fallback}"></noscript>
  <script>
    (() => {{
      const destination = {target};
      const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
      setTimeout(() => location.replace(destination), reduced ? 180 : 1350);
    }})();
  </script>
</body>
</html>"""
    return HTMLResponse(
        body,
        status_code=200,
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "Pragma": "no-cache",
            "Content-Security-Policy": (
                "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
                "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
            ),
            "X-Robots-Tag": "noindex, nofollow",
        },
    )


def cloudflare_interstitial_response(
    ray_id: str | None = None,
    upstream_host: str | None = None,
) -> Response:
    host = (upstream_host or "").lower().lstrip(".")

    def _is_perplexity(h: str) -> bool:
        return (
            h == "perplexity.ai"
            or h.endswith(".perplexity.ai")
            or h == "pplx.ai"
            or h.endswith(".pplx.ai")
        )

    def _is_kalodata(h: str) -> bool:
        return h == "kalodata.com" or h.endswith(".kalodata.com")

    base_detail = (
        "O upstream recusou a conexão do proxy com um Cloudflare Managed Challenge. "
        "O hostname público do proxy é diferente do hostname protegido, e a Cloudflare "
        "não permite concluir uma Challenge Page emitida para outro domínio. Um hostname "
        "transparente dedicado também não altera essa restrição."
    )
    tail_general = (
        "Se você controla o upstream, isente o IP de saída no WAF ou use autenticação "
        "máquina-a-máquina (Cloudflare Access). Para serviços de terceiros, use a "
        "integração oficial do serviço em vez de retransmitir a sessão do navegador."
    )
    if _is_perplexity(host):
        tail_general = (
            "Perplexity requer uma API oficial (pplx-api.perplexity.ai) ou um solver "
            "de Cloudflare terceirizado (CapSolver, AntiCaptcha, YesCaptcha, 2Captcha ou "
            "endpoint customizado) para obter o cookie cf_clearance. Configure "
            "CF_SOLVER_PROVIDER e CF_SOLVER_API_KEY nas variáveis de ambiente. "
            "Alternativamente, isente o IP de saída do proxy no painel da Cloudflare "
            "caso controle a origem."
        )
    elif _is_kalodata(host):
        tail_general = (
            "Kalodata exige sessão de navegador autêntica. Configure um solver de "
            "Cloudflare (CF_SOLVER_PROVIDER) ou provisionue um hostname dedicado "
            "espelhado no mesmo domínio registrável para permitir relay da challenge."
        )
    detail = f"{base_detail} {tail_general}"
    headers = {
        "X-Cookie-Core-Upstream-Challenge": "cloudflare",
        "X-Cookie-Core-Error-Source": "proxy-core:cloudflare",
    }
    if host:
        headers["X-Cookie-Core-Upstream-Domain"] = host
    if ray_id:
        headers["X-Cookie-Core-Cf-Ray"] = ray_id
    payload = {
        "detail": detail,
        "provider": "cloudflare",
        "ray_id": ray_id,
        "source": "proxy-core",
        "upstream_domain": host or None,
        "resolution": {
            "configure_solver": {
                "env": [
                    "CF_SOLVER_PROVIDER=capsolver|anticaptcha|yescaptcha|2captcha|custom",
                    "CF_SOLVER_API_KEY=...",
                    "CF_SOLVER_API_ENDPOINT=...  # apenas para provider=custom",
                ],
                "note": (
                    "Solver terceirizado resolve Managed Challenges remotamente e "
                    "armazena cf_clearance em cache por ~45 minutos."
                ),
            },
            "self_hosted_alternative": (
                "Apenas funciona se o hostname público do proxy coincidir exatamente "
                "com o hostname protegido (mesma origem HTTPS)."
            ),
        },
    }
    if _is_perplexity(host):
        payload["official_api"] = {
            "base_url": "https://api.perplexity.ai",
            "docs": "https://docs.perplexity.ai",
            "note": (
                "Use a API oficial em vez de retransmissão web. Esta rota não passa "
                "pelo WAF da Cloudflare."
            ),
        }
    return Response(
        json.dumps(payload),
        status_code=502,
        headers=headers,
        media_type="application/json",
    )


class ReverseProxy:
    def __init__(self, core: CookieSessionCore, settings, client: AnyHttpClient):
        self.core = core
        self.settings = settings
        self.client = client
        self._hostname_cache: dict[str, tuple[float, str | None]] = {}

    async def service_id_for_hostname(self, hostname: str) -> str | None:
        normalized = hostname.lower().rstrip(".")
        now = time.monotonic()
        cached = self._hostname_cache.get(normalized)
        if cached and cached[0] > now:
            return cached[1]
        service_id = await self.core.service_id_for_proxy_hostname(normalized)
        self._hostname_cache[normalized] = (now + 30, service_id)
        return service_id

    def clear_hostname_cache(self) -> None:
        self._hostname_cache.clear()

    async def http(
        self,
        service_id: str,
        path: str,
        request: Request,
        *,
        transparent: bool = False,
        transparent_hostname: str | None = None,
    ) -> Response:
        prefix = "" if transparent else f"/proxy/{service_id}"
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
            response = launch_loading_response(destination)
            _expire_stale_client_cookies(
                response,
                request.cookies,
                service_id=service_id,
                proxy_prefix=prefix,
                secure=self.settings.secure_cookies,
            )
            initial_target = resolve_target(
                launch,
                path,
                urlencode(clean) if clean else "",
            )
            _seed_script_visible_cookies(
                response,
                launch,
                initial_target,
                proxy_prefix=prefix,
                secure=self.settings.secure_cookies,
            )
            response.set_cookie(
                "__Secure-cookie_core_proxy",
                grant,
                max_age=self.settings.proxy_grant_ttl_seconds,
                secure=self.settings.secure_cookies,
                httponly=True,
                samesite="lax",
                path=prefix + "/",
            )
            if prefix:
                # A narrow, per-service root cookie lets the application
                # recover root-relative static/Cloudflare requests that escape
                # /proxy/<service>. It avoids one shared root grant, so two
                # products can remain open without replacing each other's
                # session.
                response.set_cookie(
                    _root_grant_cookie_name(service_id),
                    grant,
                    max_age=self.settings.proxy_grant_ttl_seconds,
                    secure=self.settings.secure_cookies,
                    httponly=True,
                    samesite="lax",
                    path="/",
                )
            return response

        raw_grant = request.cookies.get("__Secure-cookie_core_proxy") or request.cookies.get(
            _root_grant_cookie_name(service_id)
        )
        if not raw_grant:
            raise HTTPException(401, "Proxy session is missing")
        try:
            launch = await self.core.proxy_grant(raw_grant=raw_grant, service_id=service_id)
        except (ValueError, TypeError):
            raise HTTPException(401, "Proxy session is invalid or expired")
        request_hostname = (transparent_hostname or request.url.hostname or "").lower().rstrip(".")
        if transparent and (not launch.proxy_hostname or request_hostname != launch.proxy_hostname):
            raise HTTPException(421, "Proxy hostname does not match this service")
        public_base_url = (
            f"https://{launch.proxy_hostname}"
            if transparent and launch.proxy_hostname
            else str(self.settings.public_base_url).rstrip("/")
        )
        # Cloudflare Browser Insights reports data tied to the protected
        # browser origin. A vanity/path proxy cannot submit a meaningful RUM
        # event for that origin; acknowledge this optional telemetry locally
        # instead of surfacing a harmless 404 in every proxied page.
        if _is_optional_telemetry_path(path):
            return Response(status_code=204, headers={"X-Cookie-Core-Telemetry": "ignored"})
        # localStorage bidirectional sync endpoint.
        if _is_localstorage_sync_path(path):
            origin = request.headers.get("origin")
            if origin and origin.rstrip("/") != public_base_url:
                raise HTTPException(403, "Request origin is not allowed")
            if request.method == "OPTIONS":
                return Response(
                    status_code=204,
                    headers={
                        "Access-Control-Allow-Methods": "POST, OPTIONS",
                        "Access-Control-Allow-Headers": "Content-Type",
                        "Cache-Control": "no-store",
                    },
                )
            if request.method != "POST":
                raise HTTPException(405, "Method not allowed")
            raw_body = await request.body()
            if len(raw_body) > 600_000:
                raise HTTPException(413, "localStorage sync payload is too large")
            try:
                body = json.loads(raw_body)
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise HTTPException(400, "Invalid localStorage sync payload")
            if not isinstance(body, dict) or set(body) - {"upserts", "deletes"}:
                raise HTTPException(400, "Invalid localStorage sync payload")
            upserts = body.get("upserts")
            deletes = body.get("deletes")
            if upserts is not None and not isinstance(upserts, dict):
                raise HTTPException(400, "localStorage upserts must be an object")
            if deletes is not None and not isinstance(deletes, list):
                raise HTTPException(400, "localStorage deletes must be an array")
            try:
                snapshot = await self.core.sync_local_storage(
                    launch=launch, upserts=upserts, deletes=deletes
                )
            except ValueError as exc:
                raise HTTPException(400, str(exc))
            payload = json.dumps({"snapshot": snapshot}).replace("</", "<\\/")
            return Response(
                payload.encode("utf-8"),
                status_code=200,
                headers={
                    "Content-Type": "application/json; charset=utf-8",
                    "Cache-Control": "no-store",
                },
            )
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            origin = request.headers.get("origin")
            expected = public_base_url
            if origin and origin.rstrip("/") != expected:
                raise HTTPException(403, "Request origin is not allowed")
        # Preserve signed/opaque query strings byte-for-byte. The only query we
        # consume (launch) already returned through the redirect branch above.
        query = request.scope.get("query_string", b"").decode("latin-1")
        target = resolve_target(launch, path, query)
        target_parts = urlparse(target)
        if _must_stay_in_browser(target_parts.hostname or "", target_parts.path):
            # Recover from stale/cached pages that still contain an old proxied
            # GSI URL. The browser follows this redirect directly at Google and
            # receives Google's original JSON rather than rewritten HTML.
            return RedirectResponse(
                target,
                status_code=307,
                headers={"Cache-Control": "no-store"},
            )
        initiator = upstream_initiator_url(
            launch,
            request.headers.get("referer"),
            prefix,
        )
        headers = {
            key: value
            for key, value in request.headers.items()
            if key.lower() not in HOP_HEADERS
            and key.lower() not in {"content-length", "origin", "referer", "accept-encoding"}
        }
        headers["Accept-Encoding"] = "identity"
        if request.headers.get("sec-fetch-dest", "").lower() == "document":
            headers["Cache-Control"] = "no-cache"
            headers["Pragma"] = "no-cache"
        if request.headers.get("origin"):
            headers["Origin"] = _url_origin(initiator)
        if request.headers.get("referer"):
            headers["Referer"] = initiator
        if request.headers.get("sec-fetch-site"):
            headers["Sec-Fetch-Site"] = upstream_fetch_site(initiator, target)
        cookies = _upstream_cookie_header(launch, target, request.cookies)
        if cookies:
            headers["Cookie"] = cookies
        upstream_request = self.client.build_request(
            request.method, target, headers=headers, content=request.stream()
        )
        upstream_request.extensions["cookie_core_user_id"] = launch.user_id
        should_stream = _is_streaming_request(upstream_request)
        try:
            upstream = await self.client.send(upstream_request, stream=True)
        except httpx.HTTPError as exc:
            raise HTTPException(
                502,
                "Upstream service is unavailable",
                headers={
                    "X-Cookie-Core-Error-Source": "proxy-core:transport",
                    "X-Cookie-Core-Upstream-Error": type(exc).__name__,
                },
            ) from exc
        try:
            for raw_cookie in upstream.headers.get_list("set-cookie"):
                await self.core.capture_set_cookie(launch, raw_cookie, target_parts.hostname or "")
            response_headers = {
                key: value
                for key, value in upstream.headers.items()
                if key.lower() not in DROP_RESPONSE_HEADERS
            }
            _fix_response_content_type(response_headers, target)
            if upstream.headers.get("content-type", "").lower().startswith("text/html"):
                _replace_response_header(
                    response_headers,
                    "cross-origin-opener-policy",
                    "same-origin-allow-popups",
                )
            if upstream.status_code in (502, 503, 504, 520, 521, 522, 524, 525, 526, 527):
                _replace_response_header(
                    response_headers,
                    "x-cookie-core-upstream-status",
                    str(upstream.status_code),
                )
                if _has_cf_header(upstream.headers):
                    _replace_response_header(
                        response_headers,
                        "x-cookie-core-error-source",
                        "upstream:cloudflare",
                    )
                    ray = upstream.headers.get("cf-ray")
                    if ray:
                        _replace_response_header(response_headers, "x-cookie-core-cf-ray", ray)
                else:
                    _replace_response_header(
                        response_headers,
                        "x-cookie-core-error-source",
                        "upstream:origin",
                    )
            if is_cloudflare_interstitial(upstream.headers):
                ray_id = upstream.headers.get("cf-ray")
                upstream_host = (urlparse(target).hostname or "").lower() or None
                if not challenge_can_be_relayed(target, public_base_url, transparent=transparent):
                    await upstream.aclose()
                    return cloudflare_interstitial_response(ray_id, upstream_host=upstream_host)
                body = await upstream.aread()
                content_type = upstream.headers.get("content-type", "text/html")
                body = rewrite_cloudflare_challenge(
                    body,
                    content_type,
                    current_target=target,
                    launch=launch,
                    proxy_prefix=prefix,
                    public_base_url=public_base_url,
                )
                # Keep Cloudflare's challenge CSP and nonce contract intact.
                for name in (
                    "content-security-policy",
                    "content-security-policy-report-only",
                ):
                    if value := upstream.headers.get(name):
                        _replace_response_header(response_headers, name, value)
                response_headers.pop("content-encoding", None)
                response_headers.pop("etag", None)
                _replace_response_header(
                    response_headers,
                    "x-cookie-core-upstream-challenge",
                    "cloudflare-relay",
                )
                await upstream.aclose()
                return Response(
                    body,
                    status_code=upstream.status_code,
                    headers=response_headers,
                    media_type=None,
                )
            locations = upstream.headers.get_list("location")
            if locations:
                if len(locations) > 1:
                    logger.warning(
                        "upstream returned multiple Location headers target=%s count=%s",
                        target,
                        len(locations),
                    )
                _replace_response_header(
                    response_headers,
                    "location",
                    browser_url(
                        locations[0],
                        current_target=target,
                        launch=launch,
                        proxy_prefix=prefix,
                        public_base_url=public_base_url,
                    ),
                )
            if link_header := upstream.headers.get("link"):
                _replace_response_header(
                    response_headers,
                    "link",
                    rewrite_link_header(
                        link_header,
                        current_target=target,
                        launch=launch,
                        proxy_prefix=prefix,
                        public_base_url=public_base_url,
                    ),
                )
            if speculation_rules := upstream.headers.get("speculation-rules"):
                _replace_response_header(
                    response_headers,
                    "speculation-rules",
                    rewrite_single_url_header(
                        speculation_rules,
                        current_target=target,
                        launch=launch,
                        proxy_prefix=prefix,
                        public_base_url=public_base_url,
                    ),
                )
            if content_location := upstream.headers.get("content-location"):
                _replace_response_header(
                    response_headers,
                    "content-location",
                    browser_url(
                        content_location,
                        current_target=target,
                        launch=launch,
                        proxy_prefix=prefix,
                        public_base_url=public_base_url,
                    ),
                )
            cors_origin = upstream.headers.get("access-control-allow-origin")
            if cors_origin and _host_allowed(
                urlparse(cors_origin).hostname or "", launch.allowed_domains
            ):
                _replace_response_header(
                    response_headers,
                    "access-control-allow-origin",
                    str(public_base_url).rstrip("/"),
                )
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
                        public_base_url=public_base_url,
                    )
                )
            content_type = upstream.headers.get("content-type", "")
            content_length = int(upstream.headers.get("content-length", "0") or 0)
            rewritable = any(content_type.lower().startswith(item) for item in REWRITABLE_TYPES)
            if (
                rewritable
                and not should_stream
                and content_length <= self.settings.proxy_max_rewrite_bytes
            ):
                body = await upstream.aread()
                if len(body) <= self.settings.proxy_max_rewrite_bytes:
                    body = rewrite_text(
                        body,
                        content_type,
                        current_target=target,
                        launch=launch,
                        proxy_prefix=prefix,
                        public_base_url=public_base_url,
                    )
                    response_headers.pop("content-encoding", None)
                    response_headers.pop("etag", None)
                    _replace_response_header(
                        response_headers, "content-security-policy", proxy_csp()
                    )
                    await upstream.aclose()
                    return Response(
                        body,
                        status_code=upstream.status_code,
                        headers=response_headers,
                        media_type=None,
                    )
                response_headers.pop("content-encoding", None)
                response_headers.pop("etag", None)
                _replace_response_header(response_headers, "content-security-policy", proxy_csp())
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

            _replace_response_header(response_headers, "content-security-policy", proxy_csp())
            if not should_stream:
                # BrowserLikeClient buffers every non-SSE response. Returning it
                # as a StreamingResponse drops the authoritative length and has
                # produced HTTP/2 protocol errors for fonts/images behind CDNs.
                body = upstream.content
                await upstream.aclose()
                return Response(
                    body,
                    status_code=upstream.status_code,
                    headers=response_headers,
                    media_type=None,
                )
            return StreamingResponse(
                stream(),
                status_code=upstream.status_code,
                headers=response_headers,
                media_type=None,
            )
        except Exception:
            await upstream.aclose()
            raise

    async def websocket(
        self,
        websocket: WebSocket,
        service_id: str,
        path: str,
        *,
        transparent: bool = False,
        transparent_hostname: str | None = None,
    ) -> None:
        hostname = (transparent_hostname or websocket.url.hostname or "").lower().rstrip(".")
        expected = (
            f"https://{hostname}" if transparent else str(self.settings.public_base_url).rstrip("/")
        )
        if websocket.headers.get("origin", "").rstrip("/") != expected:
            await websocket.close(code=4403)
            return
        raw_grant = websocket.cookies.get("__Secure-cookie_core_proxy") or websocket.cookies.get(
            _root_grant_cookie_name(service_id)
        )
        try:
            if not raw_grant:
                raise ValueError
            launch = await self.core.proxy_grant(raw_grant=raw_grant, service_id=service_id)
            if transparent and launch.proxy_hostname != hostname:
                raise ValueError
            query = websocket.scope.get("query_string", b"").decode("latin-1")
            target = resolve_target(launch, path, query)
        except (ValueError, TypeError, HTTPException):
            await websocket.close(code=4401)
            return
        target = target.replace("https://", "wss://", 1)
        parsed = urlparse(target)
        headers = {}
        cookie = _upstream_cookie_header(launch, target, websocket.cookies)
        if cookie:
            headers["Cookie"] = cookie
        if user_agent := websocket.headers.get("user-agent"):
            headers["User-Agent"] = user_agent
        protocols = [
            item.strip()
            for item in websocket.headers.get("sec-websocket-protocol", "").split(",")
            if item.strip()
        ]
        try:
            async with connect(
                target,
                # A browser sends the application origin, not the destination
                # socket host (for example elevenlabs.io, not api.elevenlabs.io).
                origin=_url_origin(launch.upstream_url),
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
