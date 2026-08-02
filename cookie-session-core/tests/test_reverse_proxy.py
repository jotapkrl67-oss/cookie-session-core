import httpx
import pytest
from fastapi import HTTPException

from cookie_session_core.core import ConsumedLaunch
from cookie_session_core.reverse_proxy import (
    _client_cookie_namespace,
    _cookie_header,
    _replace_response_header,
    _upstream_cookie_header,
    browser_url,
    challenge_can_be_relayed,
    cloudflare_interstitial_response,
    is_cloudflare_interstitial,
    proxy_csp,
    resolve_target,
    rewrite_cloudflare_challenge,
    rewrite_text,
)


def launch() -> ConsumedLaunch:
    return ConsumedLaunch(
        user_id="user-a",
        service_id="00000000-0000-0000-0000-000000000001",
        upstream_url="https://app.example.com/home",
        allowed_domains=("app.example.com", "cdn.example.com"),
        allowed_paths=("/",),
        allowed_cookie_names=(),
        cookies=[
            {
                "name": "session",
                "value": "upstream-secret",
                "domain": ".example.com",
                "path": "/",
            },
            {
                "name": "admin",
                "value": "wrong-path",
                "domain": "app.example.com",
                "path": "/admin",
            },
        ],
    )


def test_target_and_cookie_are_scoped_to_upstream():
    item = launch()
    target = resolve_target(item, "api/me", "page=1")
    assert target == "https://app.example.com/api/me?page=1"
    assert _cookie_header(item, target) == "session=upstream-secret"


def test_only_namespaced_client_cookies_are_forwarded_and_can_rotate_values():
    item = launch()
    namespace = _client_cookie_namespace(item.service_id)
    result = _upstream_cookie_header(
        item,
        "https://app.example.com/home",
        {
            "__Secure-cookie_core_proxy": "opaque-grant",
            "unrelated": "must-not-leak",
            namespace + "session": "js-rotated",
            namespace + "anti%5Fbot": "browser-signal",
        },
    )
    assert result == "session=js-rotated; anti_bot=browser-signal"
    assert "opaque-grant" not in result
    assert "must-not-leak" not in result


def test_cookie_and_allowlist_paths_use_rfc_boundaries():
    item = launch()
    item.cookies.append(
        {"name": "exact", "value": "yes", "domain": "app.example.com", "path": "/admin"}
    )
    assert "exact=yes" in _cookie_header(item, "https://app.example.com/admin/users")
    assert "exact=yes" not in _cookie_header(item, "https://app.example.com/administrator")

    restricted = ConsumedLaunch(**{**item.__dict__, "allowed_paths": ("/admin",)})
    assert resolve_target(restricted, "admin/users") == "https://app.example.com/admin/users"
    with pytest.raises(HTTPException):
        resolve_target(restricted, "administrator")
    assert resolve_target(restricted, "cdn-cgi/challenge-platform/h/g/orchestrate") == (
        "https://app.example.com/cdn-cgi/challenge-platform/h/g/orchestrate"
    )


def test_absolute_allowed_host_is_mapped_and_unrelated_host_is_not():
    item = launch()
    kwargs = {
        "current_target": "https://app.example.com/home",
        "launch": item,
        "proxy_prefix": f"/proxy/{item.service_id}",
        "public_base_url": "https://servico.jbtools.site",
    }
    assert browser_url("/settings", **kwargs) == (f"/proxy/{item.service_id}/settings")
    assert browser_url("https://cdn.example.com/app.js", **kwargs) == (
        f"/proxy/{item.service_id}/_host/cdn.example.com/app.js"
    )
    assert browser_url("https://evil.test/x", **kwargs) == "https://evil.test/x"


def test_transparent_host_preserves_main_paths_and_routes_secondary_hosts():
    item = launch()
    kwargs = {
        "current_target": "https://app.example.com/home",
        "launch": item,
        "proxy_prefix": "",
        "public_base_url": "https://app.proxy.example",
    }
    assert browser_url("/settings", **kwargs) == "/settings"
    assert browser_url("https://app.example.com/api/me", **kwargs) == "/api/me"
    assert browser_url("https://cdn.example.com/app.js", **kwargs) == (
        "/_host/cdn.example.com/app.js"
    )


def test_html_urls_and_websocket_runtime_are_rewritten_without_cookie_values():
    item = launch()
    result = rewrite_text(
        b'<html><head><meta http-equiv="Content-Security-Policy" content="default-src none">'
        b'</head><body><a href="/account">A</a><img srcset="/a.png 1x, /b.png 2x">'
        b'<script>const ws="wss://app.example.com/live"</script></body></html>',
        "text/html; charset=utf-8",
        current_target="https://app.example.com/home",
        launch=item,
        proxy_prefix=f"/proxy/{item.service_id}",
        public_base_url="https://servico.jbtools.site",
    ).decode()
    assert f'href="/proxy/{item.service_id}/account"' in result
    assert f"wss://servico.jbtools.site/proxy/{item.service_id}/live" in result
    assert "upstream-secret" not in result
    assert "XMLHttpRequest.prototype.open" in result
    assert "http-equiv" not in result
    assert f"/proxy/{item.service_id}/b.png 2x" in result


def test_runtime_maps_request_objects_and_csp_allows_challenge_widgets():
    item = launch()
    result = rewrite_text(
        b"<html><head></head></html>",
        "text/html",
        current_target="https://app.example.com/",
        launch=item,
        proxy_prefix=f"/proxy/{item.service_id}",
        public_base_url="https://servico.jbtools.site",
    ).decode()
    assert "v instanceof Request" in result
    assert "navigator.sendBeacon" in result
    assert "Element.prototype.setAttribute" in result
    assert "SharedWorker" in result
    assert "cookieNamespace" in result
    assert "Object.getOwnPropertyDescriptor(Document.prototype,'cookie')" in result
    assert "https://challenges.cloudflare.com" in proxy_csp()
    assert "img-src 'self' https:" in proxy_csp()


def test_cloudflare_interstitial_is_detected_instead_of_rewritten():
    headers = httpx.Headers({"cf-mitigated": "challenge", "cf-ray": "abc-CGR"})
    assert is_cloudflare_interstitial(headers)
    response = cloudflare_interstitial_response("abc-CGR")
    assert response.status_code == 502
    assert response.headers["x-cookie-core-upstream-challenge"] == "cloudflare"
    assert b"Managed Challenge" in response.body


def test_cloudflare_challenge_relay_requires_exact_original_public_origin():
    assert challenge_can_be_relayed("https://app.example.com/account", "https://app.example.com")
    assert not challenge_can_be_relayed(
        "https://app.example.com/account", "https://servico.jbtools.site"
    )
    assert not challenge_can_be_relayed("https://app.example.com/account", "http://app.example.com")
    assert not challenge_can_be_relayed(
        "https://app.example.com/account",
        "https://app.proxy.example",
        transparent=True,
    )
    assert challenge_can_be_relayed(
        "https://app.example.com/account",
        "https://app.example.com",
        transparent=True,
    )


def test_cloudflare_challenge_rewrite_is_minimal_and_routes_orchestrator():
    item = launch()
    result = rewrite_cloudflare_challenge(
        (
            b'<html><head><script nonce="safe">'
            b"const p='/cdn-cgi/challenge-platform/h/g/orchestrate';"
            b"const e='\\/cdn-cgi\\/challenge-platform\\/x';"
            b'window._cf_chl_opt={cUPMDTk:"/login?__cf_chl_tk=abc"};'
            b'</script></head><form action="/login"></form></html>'
        ),
        "text/html; charset=utf-8",
        current_target="https://app.example.com/login",
        launch=item,
        proxy_prefix=f"/proxy/{item.service_id}",
        public_base_url="https://app.example.com",
    ).decode()
    prefix = f"/proxy/{item.service_id}"
    escaped_prefix = prefix.replace("/", "\\/")
    assert f"'{prefix}/cdn-cgi/challenge-platform/h/g/orchestrate'" in result
    assert f"'{escaped_prefix}\\/cdn-cgi\\/challenge-platform\\/x'" in result
    assert f'cUPMDTk:"{prefix}/login?__cf_chl_tk=abc"' in result
    assert f'action="{prefix}/login"' in result
    assert 'nonce="safe"' in result
    assert "XMLHttpRequest.prototype.open" not in result


def test_response_header_replacement_is_case_insensitive():
    headers = {"location": "https://old.example/", "Location": "https://duplicate.example/"}
    _replace_response_header(headers, "Location", "/proxy/service/home")
    assert headers == {"location": "/proxy/service/home"}
