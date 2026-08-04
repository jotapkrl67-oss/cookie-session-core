from __future__ import annotations

import asyncio
import socket

import pytest
from fastapi import HTTPException
from playwright_service.app import Settings, SolveCapacity, _validate_public_url


@pytest.mark.asyncio
async def test_dns_answer_mixing_public_and_private_is_rejected(monkeypatch):
    def mixed(*args, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 443)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", mixed)
    with pytest.raises(HTTPException, match="Private destinations"):
        await _validate_public_url(
            "https://mixed.example/", Settings(playwright_service_token="t" * 32)
        )


@pytest.mark.asyncio
async def test_disallowed_port_and_cgnat_are_rejected():
    settings = Settings(playwright_service_token="t" * 32)
    with pytest.raises(HTTPException, match="port is not allowed"):
        await _validate_public_url("https://1.1.1.1:8443/", settings)
    with pytest.raises(HTTPException, match="Private destinations"):
        await _validate_public_url("http://100.64.0.1/", settings)


def test_proxy_credentials_embedded_in_url_are_rejected():
    with pytest.raises(ValueError, match="without credentials"):
        Settings(
            playwright_service_token="t" * 32,
            browser_proxy_server="http://user:password@proxy.example:3128",
        )


@pytest.mark.asyncio
async def test_capacity_rejects_when_queue_is_full():
    capacity = SolveCapacity(1, 0)
    entered = asyncio.Event()
    release = asyncio.Event()

    async def hold():
        async with capacity.acquire(1):
            entered.set()
            await release.wait()

    task = asyncio.create_task(hold())
    await entered.wait()
    with pytest.raises(HTTPException) as exc:
        async with capacity.acquire(1):
            pass
    assert exc.value.status_code == 429
    release.set()
    await task
    assert capacity.active == capacity.queued == 0
