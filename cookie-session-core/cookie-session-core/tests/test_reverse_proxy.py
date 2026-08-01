from cookie_session_core.core import ConsumedLaunch
from cookie_session_core.reverse_proxy import (
    _cookie_header,
    browser_url,
    resolve_target,
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
