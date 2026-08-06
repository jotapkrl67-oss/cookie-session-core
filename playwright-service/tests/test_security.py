from __future__ import annotations

import pytest
from fastapi import HTTPException
from playwright_service.app import Settings, _proxy_config, _validate_public_url


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://[::1]/",
        "http://10.0.0.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost/",
    ],
)
async def test_private_destinations_are_rejected(url: str):
    with pytest.raises(HTTPException, match="Private destinations"):
        await _validate_public_url(url)


@pytest.mark.asyncio
async def test_public_literal_ip_is_allowed():
    await _validate_public_url("https://1.1.1.1/")


def test_browser_proxy_configuration_is_optional_and_authenticated():
    base = {"playwright_service_token": "t" * 32}
    direct = Settings(**base)
    assert _proxy_config(direct) is None
    assert direct.egress_id == "direct"
    assert _proxy_config(
        Settings(
            **base,
            browser_proxy_server="http://vps-proxy.example:3128",
            browser_proxy_username="user",
            browser_proxy_password="password",
        )
    ) == {
        "server": "http://vps-proxy.example:3128",
        "username": "user",
        "password": "password",
    }
    with pytest.raises(ValueError, match="USERNAME"):
        Settings(
            **base,
            browser_proxy_server="http://vps-proxy.example:3128",
            browser_proxy_password="password-only",
        )
