from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from contextlib import suppress
from html import escape
from typing import Any
from urllib.parse import quote, unquote, urlencode, urljoin, urlparse, urlunparse

import httpx
from fastapi import HTTPException, Request, WebSocket
from fastapi.responses import HTMLResponse, Response, StreamingResponse
from websockets.asyncio.client import connect
from websockets.exceptions import WebSocketException

from .browser_client import _is_streaming_request
from .core import ConsumedLaunch, CookieSessionCore

logger = logging.getLogger("cookie_session_core.reverse_proxy")

AnyHttpClient = object

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
    "application/json+protobuf",
    "text/x-component",
)
CHALLENGE_PLATFORM_PATHS = (
    "/cdn-cgi/challenge-platform/",
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
SCRIPT_BLOCK = re.compile(
    r"<script\b[^>]*>.*?</script\s*>",
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
    r"(?P<quote>['\"`])(?P<url>/(?:_next|assets|static)/[^'\"`\\\s]*)",
    re.IGNORECASE,
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
        _registrable_domain(item.lower().lstrip(".").rstrip(".")) == site
        for item in allowed
    )


def _registrable_domain(host: str) -> str:
    """Conservative eTLD+1 approximation for same-site app/account redirects."""
    labels = host.lower().rstrip(".").split(".")
    if len(labels) < 2:
        return host.lower().rstrip(".")
    common_second_level = {"ac", "co", "com", "edu", "gov", "net", "org"}
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in common_second_level:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _url_origin(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))


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
    if initiator_host and target_host and (
        _registrable_domain(initiator_host) == _registrable_domain(target_host)
    ):
        return "same-site"
    return "cross-site"


def _cookie_header(launch: ConsumedLaunch, target: str) -> str:
    parsed = urlparse(target)
    host = (parsed.hostname or "").lower()
    path = parsed.path or "/"
    values: list[tuple[int, str]] = []
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
        values.append((len(cookie_path), f"{cookie['name']}={cookie['value']}"))
    values.sort(key=lambda item: item[0], reverse=True)
    return "; ".join(value for _, value in values)


def _client_cookie_namespace(service_id: str) -> str:
    return f"__Secure-cookie_core_client_{service_id}_"


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
    parsed = urlparse(target)
    host = (parsed.hostname or "").lower()
    path = parsed.path or "/"
    namespace = _client_cookie_namespace(launch.service_id)
    seeded = 0
    for cookie in launch.cookies:
        if bool(cookie.get("httpOnly", True)):
            continue
        domain = str(cookie["domain"]).lower().lstrip(".")
        if host != domain and not host.endswith("." + domain):
            continue
        cookie_path = str(cookie.get("path") or "/")
        if not (
            path == cookie_path
            or path.startswith(cookie_path.rstrip("/") + "/")
            or cookie_path == "/"
        ):
            continue
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


def _must_stay_in_browser(host: str, path: str) -> bool:
    normalized_host = host.lower().rstrip(".")
    normalized_path = path or "/"
    return any(
        normalized_host == direct_host
        and (
            normalized_path == direct_path.rstrip("/")
            or normalized_path.startswith(direct_path)
        )
        for direct_host, direct_path in DIRECT_BROWSER_PATHS
    )


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
            "lockAccountProfile": main_host in {"chatgpt.com", "chat.openai.com"},
        },
        separators=(",", ":"),
    ).replace("</", "<\\/")
    upstream_json = json.dumps(launch.upstream_url)
    return (
        "<script>(function(){"
        f"const C={payload};"
        "const site=h=>{const p=h.toLowerCase().replace(/\\.$/,'').split('.');"
        "const s=new Set(['ac','co','com','edu','gov','net','org']);"
        "return p.length>2&&p.at(-1).length===2&&s.has(p.at(-2))?p.slice(-3).join('.'):p.slice(-2).join('.')};"
        "const ok=h=>C.hosts.some(x=>h===x||h.endsWith('.'+x)||site(h)===site(x));"
        "const direct=u=>C.directBrowserPaths.some(([h,p])=>u.hostname===h&&"
        "(u.pathname===p.replace(/\\/$/,'')||u.pathname.startsWith(p)));"
        "const map=(v,ws=false)=>{if(typeof v!=='string')return v;"
        "if(C.prefix&&v.startsWith(C.prefix))return v;"
        "try{const u=new URL(v,location.href);if(direct(u))return u.href;"
        "if(u.origin===location.origin){"
        "if(!u.pathname.startsWith(C.prefix))u.pathname=C.prefix+u.pathname;}"
        "else if(ok(u.hostname)){"
        f"const main=new URL({upstream_json}).hostname;const h=u.hostname;"
        "u.protocol=ws?'wss:':'https:';u.host=new URL(C.proxyOrigin).host;"
        "u.pathname=C.prefix+(h===main?'':'/_host/'+h)+u.pathname;}"
        "return ws?u.href.replace(/^https:/,'wss:'):u.href;}catch(_e){return v;}};"
        "const f=window.fetch;window.fetch=(v,o)=>{"
        "if(v instanceof Request)return f.call(window,new Request(map(v.url),v),o);"
        "return f.call(window,v instanceof URL?map(v.href):map(v),o)};"
        "const xo=XMLHttpRequest.prototype.open;"
        "XMLHttpRequest.prototype.open=function(m,u,...a){return xo.call(this,m,map(u),...a)};"
        "const sb=navigator.sendBeacon&&navigator.sendBeacon.bind(navigator);"
        "if(sb)navigator.sendBeacon=(u,d)=>sb(map(u),d);"
        "const W=window.WebSocket;"
        "window.WebSocket=function(u,p){"
        "return p===undefined?new W(map(u,true)):new W(map(u,true),p)};"
        "window.WebSocket.prototype=W.prototype;"
        "const E=window.EventSource;"
        "window.EventSource=function(u,o){return new E(map(u),o)};"
        "window.EventSource.prototype=E.prototype;"
        "for(const k of ['Worker','SharedWorker']){"
        "const O=window[k];if(!O)continue;window[k]=function(u,o){return new O(map(u),o)};"
        "window[k].prototype=O.prototype;}"
        "const sa=Element.prototype.setAttribute;"
        "const cssUrlRe=/url\\(\\s*(['\"]?)([^)'\"\\1]+?)\\1\\s*\\)/g;"
        "const rewriteCss=function(v){"
        "if(typeof v!=='string'||v.indexOf('url(')<0)return v;"
        "return v.replace(cssUrlRe,function(m,q,u){const r=map(u);return r===u?m:'url('+(q||'')+r+(q||'')+')'})"
        "};"
        "Element.prototype.setAttribute=function(n,v){"
        "if(/^(?:href|src|action|poster|data|formaction)$/i.test(n))v=map(v);"
        "else if(/^style$/i.test(n))v=rewriteCss(v);"
        "return sa.call(this,n,v)};"
        "for(const [ctor,prop] of [[HTMLAnchorElement,'href'],[HTMLAreaElement,'href'],"
        "[HTMLImageElement,'src'],[HTMLScriptElement,'src'],[HTMLIFrameElement,'src'],"
        "[HTMLLinkElement,'href'],[HTMLFormElement,'action'],[HTMLSourceElement,'src'],"
        "[HTMLVideoElement,'src'],[HTMLAudioElement,'src']]){"
        "const d=Object.getOwnPropertyDescriptor(ctor.prototype,prop);"
        "if(d&&d.set&&d.get)Object.defineProperty(ctor.prototype,prop,{configurable:d.configurable,"
        "enumerable:d.enumerable,get:d.get,set(v){d.set.call(this,map(v))}});}"
        "const wo=window.open;window.open=(u,...a)=>wo.call(window,map(u),...a);"
        "const ps=history.pushState.bind(history),rs=history.replaceState.bind(history);"
        "history.pushState=(s,t,u)=>ps(s,t,u==null?u:map(u));"
        "history.replaceState=(s,t,u)=>rs(s,t,u==null?u:map(u));"
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
        "badge.innerHTML='<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" '"
        "+'stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\">'"
        "+'<rect width=\"14\" height=\"11\" x=\"5\" y=\"10\" rx=\"2\"/>'"
        "+'<path d=\"M8 10V7a4 4 0 0 1 8 0v3\"/></svg>';b.appendChild(badge)})};"
        "lock();new MutationObserver(lock).observe(document.documentElement,{childList:true,subtree:true});"
        "}"
        "let dc=Object.getOwnPropertyDescriptor(Document.prototype,'cookie');"
        "if(dc&&dc.get&&dc.set)Object.defineProperty(Document.prototype,'cookie',{"
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
        return CSS_URL.sub(
            lambda item: (
                f"{item.group('prefix')}{item.group('quote')}"
                f"{replace_url(item.group('url'))}{item.group('quote')}"
                f"{item.group('suffix')}"
            ),
            value,
        )

    if content_type.lower().startswith("text/html"):
        # Do not run markup/CSS regexes through inline JavaScript. Expressions
        # such as /url\((...)\)/gi were previously mistaken for CSS url() and
        # rewritten into syntactically invalid JavaScript.
        scripts: list[str] = []

        def hold_script(item: re.Match) -> str:
            scripts.append(item.group(0))
            return f"\x00COOKIE_CORE_SCRIPT_{len(scripts) - 1}\x00"

        text = SCRIPT_BLOCK.sub(hold_script, text)
        text = META_CSP.sub("", text)
        text = URL_ATTRIBUTE.sub(
            lambda m: (
                f"{m.group('prefix')}{m.group('quote')}"
                f"{replace_url(m.group('url'))}{m.group('quote')}"
            ),
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
    elif "css" in content_type.lower():
        text = replace_css(text)

    # React Server Components and framework bootstrap payloads can schedule
    # root-relative assets without creating an HTML element first. The runtime
    # DOM hooks never see those URLs, so map only well-known asset roots here.
    if content_type.lower().startswith("text/x-component"):
        text = ROOT_ASSET_STRING.sub(
            lambda item: item.group("quote") + replace_url(item.group("url")),
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
        lambda item: "<"
        + browser_url(
            item.group("url"),
            current_target=current_target,
            launch=launch,
            proxy_prefix=proxy_prefix,
            public_base_url=public_base_url,
        )
        + ">",
        value,
    )


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
        self, service_id: str, path: str, request: Request, *, transparent: bool = False
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
            return response

        raw_grant = request.cookies.get("__Secure-cookie_core_proxy")
        if not raw_grant:
            raise HTTPException(401, "Proxy session is missing")
        try:
            launch = await self.core.proxy_grant(raw_grant=raw_grant, service_id=service_id)
        except (ValueError, TypeError):
            raise HTTPException(401, "Proxy session is invalid or expired")
        if transparent and (
            not launch.proxy_hostname
            or (request.url.hostname or "").lower().rstrip(".") != launch.proxy_hostname
        ):
            raise HTTPException(421, "Proxy hostname does not match this service")
        public_base_url = (
            f"https://{launch.proxy_hostname}"
            if transparent and launch.proxy_hostname
            else str(self.settings.public_base_url).rstrip("/")
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
        self, websocket: WebSocket, service_id: str, path: str, *, transparent: bool = False
    ) -> None:
        hostname = (websocket.url.hostname or "").lower().rstrip(".")
        expected = (
            f"https://{hostname}" if transparent else str(self.settings.public_base_url).rstrip("/")
        )
        if websocket.headers.get("origin", "").rstrip("/") != expected:
            await websocket.close(code=4403)
            return
        raw_grant = websocket.cookies.get("__Secure-cookie_core_proxy")
        try:
            if not raw_grant:
                raise ValueError
            launch = await self.core.proxy_grant(raw_grant=raw_grant, service_id=service_id)
            if transparent and launch.proxy_hostname != hostname:
                raise ValueError
            target = resolve_target(launch, path, websocket.url.query)
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
