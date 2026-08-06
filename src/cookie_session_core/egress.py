from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from collections import OrderedDict
from urllib.parse import urlparse


def _public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return address.is_global


class PublicAddressGuard:
    """Reject loopback/private egress targets with bounded DNS caching."""

    def __init__(self, *, cache_seconds: int = 60, max_entries: int = 4096):
        self._ttl = max(0, int(cache_seconds))
        self._max_entries = max(1, int(max_entries))
        self._cache: OrderedDict[tuple[str, int], float] = OrderedDict()
        self._inflight: dict[tuple[str, int], asyncio.Task[None]] = {}
        self._lock = asyncio.Lock()

    @staticmethod
    def parse(url: str, *, require_https: bool = True) -> tuple[str, int]:
        parsed = urlparse(url)
        if (
            parsed.scheme not in ({"https"} if require_https else {"http", "https"})
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.fragment
        ):
            raise ValueError("Destination must be a public HTTPS URL")
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError as exc:
            raise ValueError("Destination port is invalid") from exc
        host = parsed.hostname.lower().rstrip(".")
        if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
            raise ValueError("Private destinations are not allowed")
        return host, port

    async def check(self, url: str, *, require_https: bool = True) -> None:
        host, port = self.parse(url, require_https=require_https)
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        if literal is not None:
            if not _public_ip(str(literal)):
                raise ValueError("Private destinations are not allowed")
            return

        key = (host, port)
        now = time.monotonic()
        async with self._lock:
            expiry = self._cache.get(key, 0)
            if expiry > now:
                self._cache.move_to_end(key)
                return
            self._cache.pop(key, None)
            task = self._inflight.get(key)
            if task is None:
                task = asyncio.create_task(self._resolve(host, port))
                self._inflight[key] = task
        try:
            await asyncio.shield(task)
        finally:
            async with self._lock:
                if self._inflight.get(key) is task and task.done():
                    self._inflight.pop(key, None)
        async with self._lock:
            self._cache[key] = time.monotonic() + self._ttl
            self._cache.move_to_end(key)
            while len(self._cache) > self._max_entries:
                self._cache.popitem(last=False)

    @staticmethod
    async def _resolve(host: str, port: int) -> None:
        try:
            records = await asyncio.to_thread(
                socket.getaddrinfo, host, port, type=socket.SOCK_STREAM
            )
        except socket.gaierror as exc:
            raise ValueError("Destination hostname could not be resolved") from exc
        addresses = {str(record[4][0]).split("%", 1)[0] for record in records}
        if not addresses or not all(_public_ip(address) for address in addresses):
            raise ValueError("Private destinations are not allowed")
