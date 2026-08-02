import httpx
import pytest
from fastapi import HTTPException, Response

from cookie_session_core.browser_client import _is_sse_request, _is_streaming_request
from cookie_session_core.core import ConsumedLaunch
from cookie_session_core.reverse_proxy import (
    _client_cookie_namespace,
    _cookie_header,
    _expire_stale_client_cookies,
    _host_allowed,
    _must_stay_in_browser,
    _registrable_domain,
    _replace_response_header,
    _seed_script_visible_cookies,
    _upstream_cookie_header,
    browser_url,
    challenge_can_be_relayed,
    cloudflare_interstitial_response,
    is_cloudflare_interstitial,
    launch_loading_response,
    proxy_csp,
    resolve_target,
    rewrite_cloudflare_challenge,
    rewrite_link_header,
    rewrite_text,
    upstream_fetch_site,
    upstream_initiator_url,
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


def test_streaming_branch_can_detect_sse_requests():
    request = httpx.Request(
        "POST",
        "https://chatgpt.com/backend-api/f/conversation",
        headers={"Accept": "text/event-stream"},
    )

    assert _is_sse_request(request)


@pytest.mark.parametrize(
    ("url", "headers"),
    [
        (
            "https://gemini.google.com/_/BardChatUi/StreamGenerate",
            {"Accept": "*/*"},
        ),
        (
            "https://api.elevenlabs.io/v1/text-to-speech/voice/stream",
            {"Accept": "audio/mpeg"},
        ),
        (
            "https://cdn.example.com/sample.mp3",
            {"Range": "bytes=0-"},
        ),
    ],
)
def test_non_sse_media_and_protobuf_streams_are_not_buffered(url, headers):
    assert _is_streaming_request(httpx.Request("GET", url, headers=headers))


def test_regular_json_request_remains_buffered_for_url_rewriting():
    request = httpx.Request(
        "GET",
        "https://app.example.com/api/bootstrap",
        headers={"Accept": "application/json"},
    )
    assert not _is_streaming_request(request)


def test_nextjs_link_header_preloads_remain_inside_service_proxy():
    item = launch()
    prefix = f"/proxy/{item.service_id}"
    result = rewrite_link_header(
        '</_next/static/media/font.woff2>; rel=preload; as=font; crossorigin, '
        '<https://cdn.example.com/chunk.js>; rel=preload; as=script',
        current_target="https://app.example.com/en/explore",
        launch=item,
        proxy_prefix=prefix,
        public_base_url="https://servico.jbtools.site",
    )
    assert f"<{prefix}/_next/static/media/font.woff2>" in result
    assert f"<{prefix}/_host/cdn.example.com/chunk.js>" in result


def test_react_server_component_root_assets_are_rewritten():
    item = launch()
    prefix = f"/proxy/{item.service_id}"
    result = rewrite_text(
        b'1:["$","link",null,{"href":"/_next/static/media/font.woff2"}]',
        "text/x-component",
        current_target="https://app.example.com/en/explore",
        launch=item,
        proxy_prefix=prefix,
        public_base_url="https://servico.jbtools.site",
    ).decode()
    assert f'"{prefix}/_next/static/media/font.woff2"' in result


def test_launch_loading_page_is_branded_uncached_and_escapes_destination():
    response = launch_loading_response('/proxy/service/home?next=</script><script>bad()</script>')
    body = response.body.decode()
    assert response.status_code == 200
    assert response.headers["cache-control"].startswith("no-store")
    assert "Carregando produto <strong>JBTools</strong>" in body
    assert "location.replace(destination)" in body
    assert r"<\/script><script>bad()" in body
    assert "const destination = \"/proxy/service/home" in body


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


def test_new_launch_expires_stale_client_cookies_on_root_and_proxy_paths():
    item = launch()
    namespace = _client_cookie_namespace(item.service_id)
    response = Response()

    expired = _expire_stale_client_cookies(
        response,
        {
            namespace + "session": "stale-logged-out-value",
            "__Secure-cookie_core_proxy": "grant-must-remain",
            "unrelated": "keep",
        },
        service_id=item.service_id,
        proxy_prefix=f"/proxy/{item.service_id}",
        secure=True,
    )

    set_cookies = response.headers.getlist("set-cookie")
    assert expired == 1
    assert len(set_cookies) == 2
    assert all((namespace + "session=") in header for header in set_cookies)
    assert all("Max-Age=0" in header and "Secure" in header for header in set_cookies)
    assert any("Path=/;" in header for header in set_cookies)
    assert any(f"Path=/proxy/{item.service_id}/;" in header for header in set_cookies)
    assert all("cookie_core_proxy" not in header for header in set_cookies)


def test_transparent_launch_emits_one_root_deletion_per_stale_cookie():
    item = launch()
    namespace = _client_cookie_namespace(item.service_id)
    response = Response()

    expired = _expire_stale_client_cookies(
        response,
        {namespace + "oai-did": "old"},
        service_id=item.service_id,
        proxy_prefix="",
        secure=True,
    )

    assert expired == 1
    assert len(response.headers.getlist("set-cookie")) == 1


def test_launch_seeds_only_script_visible_cookies_matching_current_page():
    item = launch()
    item.cookies.extend(
        [
            {
                "name": "csrf_token",
                "value": "visible-value",
                "domain": ".example.com",
                "path": "/",
                "httpOnly": False,
            },
            {
                "name": "private_session",
                "value": "must-stay-in-vault",
                "domain": ".example.com",
                "path": "/",
                "httpOnly": True,
            },
            {
                "name": "other_host",
                "value": "not-visible-here",
                "domain": "unrelated.test",
                "path": "/",
                "httpOnly": False,
            },
        ]
    )
    response = Response()
    seeded = _seed_script_visible_cookies(
        response,
        item,
        "https://app.example.com/home",
        proxy_prefix=f"/proxy/{item.service_id}",
        secure=True,
    )
    headers = response.headers.getlist("set-cookie")
    namespace = _client_cookie_namespace(item.service_id)
    assert seeded == 1
    assert len(headers) == 1
    assert namespace + "csrf_token=visible-value" in headers[0]
    assert "private_session" not in headers[0]
    assert "other_host" not in headers[0]
    assert "HttpOnly" not in headers[0]


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


def test_google_identity_gsi_stays_in_the_real_browser_origin():
    item = ConsumedLaunch(
        **{
            **launch().__dict__,
            "allowed_domains": (*launch().allowed_domains, "google.com"),
        }
    )
    kwargs = {
        "current_target": "https://app.example.com/home",
        "launch": item,
        "proxy_prefix": f"/proxy/{item.service_id}",
        "public_base_url": "https://servico.jbtools.site",
    }
    gsi_status = "https://accounts.google.com/gsi/status?client_id=example"

    assert _must_stay_in_browser("accounts.google.com", "/gsi/status")
    assert browser_url(gsi_status, **kwargs) == gsi_status


def test_runtime_does_not_intercept_google_identity_gsi():
    item = ConsumedLaunch(
        **{
            **launch().__dict__,
            "allowed_domains": (*launch().allowed_domains, "google.com"),
        }
    )
    result = rewrite_text(
        b"<html><head></head><body></body></html>",
        "text/html",
        current_target="https://app.example.com/",
        launch=item,
        proxy_prefix=f"/proxy/{item.service_id}",
        public_base_url="https://servico.jbtools.site",
    ).decode()

    assert "directBrowserPaths" in result
    assert "if(direct(u))return u.href" in result


def test_same_site_apex_and_account_hosts_are_mapped_without_opening_other_sites():
    item = launch()
    kwargs = {
        "current_target": "https://app.example.com/home",
        "launch": item,
        "proxy_prefix": f"/proxy/{item.service_id}",
        "public_base_url": "https://servico.jbtools.site",
    }
    assert _host_allowed("example.com", item.allowed_domains)
    assert _host_allowed("account.example.com", item.allowed_domains)
    assert not _host_allowed("example.com.attacker.test", item.allowed_domains)
    assert _registrable_domain("app.example.co.uk") == "example.co.uk"
    assert browser_url("https://account.example.com/profile", **kwargs) == (
        f"/proxy/{item.service_id}/_host/account.example.com/profile"
    )


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


def test_cross_host_auth_keeps_the_logical_page_as_request_origin():
    item = launch()
    prefix = f"/proxy/{item.service_id}"
    initiator = upstream_initiator_url(
        item,
        f"https://servico.jbtools.site{prefix}/account?step=login",
        prefix,
    )

    assert initiator == "https://app.example.com/account?step=login"
    assert upstream_fetch_site(initiator, "https://cdn.example.com/auth/session") == "same-site"


def test_cross_site_identity_provider_is_not_reported_as_same_origin():
    item = ConsumedLaunch(
        **{
            **launch().__dict__,
            "allowed_domains": ("app.example.com", "identity.example-id.com"),
        }
    )
    prefix = f"/proxy/{item.service_id}"
    initiator = upstream_initiator_url(
        item,
        f"https://servico.jbtools.site{prefix}/account",
        prefix,
    )

    assert upstream_fetch_site(initiator, "https://identity.example-id.com/session") == (
        "cross-site"
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


def test_style_attribute_inline_url_is_rewritten():
    item = launch()
    html = (
        b'<html><body>'
        b'<div style="background-image:url(\'https://cdn.example.com/icon.png\');'
        b'background: url(https://app.example.com/bg.svg) no-repeat;"></div>'
        b'<span style=\'background: url("https://cdn.example.com/logo.png")\'>X</span>'
        b'</body></html>'
    )
    result = rewrite_text(
        html,
        "text/html; charset=utf-8",
        current_target="https://app.example.com/home",
        launch=item,
        proxy_prefix=f"/proxy/{item.service_id}",
        public_base_url="https://servico.jbtools.site",
    ).decode()
    prefix = f"/proxy/{item.service_id}"
    assert f"{prefix}/_host/cdn.example.com/icon.png" in result
    assert f"{prefix}/bg.svg" in result
    assert f"{prefix}/_host/cdn.example.com/logo.png" in result
    double = f"{prefix}/{prefix}/"
    assert double not in result, "CSS_URL must not double-proxy style inline URLs"


def test_json_protobuf_content_type_is_rewritten():
    item = launch()
    body = (
        b'[null,null,["https://app.example.com/api/chat",'
        b'"https://cdn.example.com/media/image.png"],null]'
    )
    result = rewrite_text(
        body,
        "application/json+protobuf",
        current_target="https://app.example.com/home",
        launch=item,
        proxy_prefix=f"/proxy/{item.service_id}",
        public_base_url="https://servico.jbtools.site",
    ).decode()
    prefix = f"/proxy/{item.service_id}"
    assert f"{prefix}/api/chat" in result
    assert f"{prefix}/_host/cdn.example.com/media/image.png" in result


def test_cookie_header_preserves_host_only_scope_across_google_subdomains():
    item = ConsumedLaunch(
        user_id="u",
        service_id="s",
        upstream_url="https://gemini.google.com/",
        allowed_domains=("gemini.google.com", "clients6.google.com"),
        allowed_paths=("/",),
        allowed_cookie_names=(),
        cookies=[
            {"name": "SID", "value": "sess", "domain": ".google.com", "path": "/"},
            {"name": "HSID", "value": "h", "domain": "accounts.google.com", "path": "/"},
            {"name": "UNRELATED", "value": "x", "domain": ".other.site", "path": "/"},
        ],
    )
    header = _cookie_header(item, "https://signaler-pa.clients6.google.com/punctual/v1/chooseServer")
    assert "SID=sess" in header
    assert "HSID=h" not in header
    assert "UNRELATED" not in header


def test_runtime_uses_history_navigation_without_patching_location_objects():
    item = launch()
    result = rewrite_text(
        b"<html><head></head></html>",
        "text/html",
        current_target="https://app.example.com/",
        launch=item,
        proxy_prefix=f"/proxy/{item.service_id}",
        public_base_url="https://servico.jbtools.site",
    ).decode()
    assert "history.pushState" in result
    assert "history.replaceState" in result
    assert "patch(window.location)" not in result
    assert "Location.prototype" not in result
    assert "rewriteCss" in result, "Dynamic CSS URL rewriting helper must be injected"
    assert "cssUrlRe" in result, "CSS url() regex helper must be present"
    assert "else if(/^style$/i.test(n))v=rewriteCss(v)" in result
