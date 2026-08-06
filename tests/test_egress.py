import socket

import pytest

from cookie_session_core.egress import PublicAddressGuard


@pytest.mark.asyncio
async def test_egress_guard_rejects_private_ip_literals():
    guard = PublicAddressGuard()
    with pytest.raises(ValueError, match="Private"):
        await guard.check("https://127.0.0.1/admin")
    with pytest.raises(ValueError, match="Private"):
        await guard.check("https://[::ffff:127.0.0.1]/admin")


@pytest.mark.asyncio
async def test_egress_guard_rejects_mixed_public_and_private_dns(monkeypatch):
    def mixed_records(*_args, **_kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 443)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", mixed_records)
    with pytest.raises(ValueError, match="Private"):
        await PublicAddressGuard(cache_seconds=0).check("https://example.com/path")
