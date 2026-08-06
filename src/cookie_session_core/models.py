from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class ServicePolicy:
    id: str
    name: str
    upstream_url: str
    allowed_domains: tuple[str, ...]
    allowed_paths: tuple[str, ...] = ("/",)
    allowed_cookie_names: tuple[str, ...] = ()
    enabled: bool = True


@dataclass(frozen=True)
class ImportedCookie:
    name: str
    value: str
    domain: str
    path: str = "/"
    expires_at: datetime | None = None
    secure: bool = True
    http_only: bool = True
    same_site: str | None = None
    host_only: bool = True


@dataclass(frozen=True)
class StoredCookie:
    name: str
    encrypted_value: bytes
    nonce: bytes
    domain: str
    path: str
    expires_at: datetime | None
    secure: bool
    http_only: bool
    same_site: str | None
    host_only: bool = True


@dataclass(frozen=True)
class ImportedLocalStorageItem:
    key: str
    value: str


@dataclass(frozen=True)
class StoredLocalStorageItem:
    key: str
    encrypted_value: bytes
    nonce: bytes
