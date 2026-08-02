from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from contextlib import suppress
from typing import Any
from urllib.parse import unquote, urlencode, urljoin, urlparse, urlunparse

import httpx
from fastapi import HTTPException, Request, WebSocket
from fastapi.responses import RedirectResponse, Response, StreamingResponse
from websockets.asyncio.client import connect
from websockets.exceptions import WebSocketException

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
    host_registrable = _registrable_domain(host) if "." in host else host
    values: list[tuple[int, str]] = []
    for cookie in launch.cookies:
        domain = str(cookie["domain"]).lower().lstrip(".")
        domain_registrable = _registrable_domain(domain) if "." in domain else domain
        direct = host == domain or host.endswith("." + domain)
        same_site_registrable = (
            "." in host_registrable
            and "." in domain_registrable
            and host_registrable == domain_registrable
        )
        if not direct and not same_site_registrable:
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
    payload = json.dumps(
        {
            "prefix": prefix,
            "proxyOrigin": public_base_url.rstrip("/"),
            "hosts": hosts,
            "cookieNamespace": _client_cookie_namespace(launch.service_id),
            "directBrowserPaths": DIRECT_BROWSER_PATHS,
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
        "(function(){"
        "const patch=function(obj){"
        "try{"
        "const desc=Object.getOwnPropertyDescriptor(obj,'href');"
        "if(desc&&desc.set&&desc.get){"
        "Object.defineProperty(obj,'href',{configurable:desc.configurable,enumerable:desc.enumerable,"
        "get:function(){return desc.get.call(this)},set:function(v){desc.set.call(this,map(String(v)))}});"
        "}"
        "}catch(_e){}"
        "if(typeof obj.assign==='function'){"
        "const a=obj.assign.bind(obj);obj.assign=function(u,...r){return a(map(String(u)),...r)};"
        "}"
        "if(typeof obj.replace==='function'){"
        "const rpl=obj.replace.bind(obj);obj.replace=function(u,...r){return rpl(map(String(u)),...r)};"
        "}"
        "};"
        "try{patch(window.location);}catch(_e){}"
        "try{"
        "let dloc=Object.getOwnPropertyDescriptor(Document.prototype,'location');"
        "if(dloc&&dloc.get){"
        "const origGet=dloc.get;"
        "Object.defineProperty(Document.prototype,'location',{configurable:true,enumerable:true,"
        "get:function(){const loc=origGet.call(this);try{patch(loc);}catch(_e){}return loc;}});"
        "}"
        "}catch(_e){}"
        "try{"
        "if(window.Location&&window.Location.prototype){"
        "let lproto=window.Location.prototype;"
        "let descAssign=Object.getOwnPropertyDescriptor(lproto,'assign');"
        "if(descAssign&&descAssign.value){let a=descAssign.value;"
        "descAssign.value=function(u,...r){return a.call(this,map(String(u)),...r)};"
        "Object.defineProperty(lproto,'assign',descAssign);}"
        "let descReplace=Object.getOwnPropertyDescriptor(lproto,'replace');"
        "if(descReplace&&descReplace.value){let rp=descReplace.value;"
        "descReplace.value=function(u,...r){return rp.call(this,map(String(u)),...r)};"
        "Object.defineProperty(lproto,'replace',descReplace);}"
        "let descHref=Object.getOwnPropertyDescriptor(lproto,'href');"
        "if(descHref&&descHref.set&&descHref.get){"
        "Object.defineProperty(lproto,'href',{configurable:descHref.configurable,enumerable:descHref.enumerable,"
        "get:function(){return descHref.get.call(this)},set:function(v){descHref.set.call(this,map(String(v)))}});"
        "}"
        "}"
        "}catch(_e){}"
        "})();"
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
        "prefetch-src 'self' https: http: data: blob:; "
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


def cloudflare_interstitial_response(ray_id: str | None = None) -> Response:
    # A Challenge Page fetched by this server cannot be solved by a browser on
    # another hostname/IP. Do not relay or mutate it: Cloudflare explicitly
    # documents both cases as unsupported.
    detail = (
        "O upstream recusou a conexão do proxy com um Cloudflare Managed Challenge. "
        "O hostname público do proxy é diferente do hostname protegido, e a Cloudflare "
        "não permite concluir uma Challenge Page emitida para outro domínio. Um hostname "
        "transparente dedicado também não altera essa restrição. Se você controla o "
        "upstream, isente o IP de saída no WAF ou use autenticação máquina-a-máquina "
        "(Cloudflare Access). Para serviços de terceiros, use a integração oficial do "
        "serviço em vez de retransmitir a sessão do navegador."
    )
    headers = {
        "X-Cookie-Core-Upstream-Challenge": "cloudflare",
        "X-Cookie-Core-Error-Source": "proxy-core:cloudflare",
    }
    if ray_id:
        headers["X-Cookie-Core-Cf-Ray"] = ray_id
    return Response(
        json.dumps(
            {
                "detail": detail,
                "provider": "cloudflare",
                "ray_id": ray_id,
                "source": "proxy-core",
            }
        ),
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
                if not challenge_can_be_relayed(target, public_base_url, transparent=transparent):
                    await upstream.aclose()
                    return cloudflare_interstitial_response(ray_id)
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
            if rewritable and content_length <= self.settings.proxy_max_rewrite_bytes:
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
            if not _is_sse_request(upstream_request):
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
