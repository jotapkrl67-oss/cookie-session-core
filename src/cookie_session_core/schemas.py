from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator, model_validator

PRIVATE_HOSTING_SUFFIXES = {
    "appspot.com",
    "fly.dev",
    "github.io",
    "gitlab.io",
    "herokuapp.com",
    "netlify.app",
    "onrender.com",
    "pages.dev",
    "railway.app",
    "vercel.app",
    "workers.dev",
}


class ServiceInput(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    category: str = Field(default="Geral", max_length=80)
    upstream_url: HttpUrl
    proxy_hostname: str | None = Field(default=None, max_length=253)
    allowed_domains: list[str] = Field(min_length=1, max_length=30)
    allowed_paths: list[str] = Field(default=["/"], min_length=1, max_length=30)
    allowed_cookie_names: list[str] = Field(default=[], max_length=200)
    enabled: bool = True

    @field_validator("upstream_url")
    @classmethod
    def https_only(cls, value: HttpUrl) -> HttpUrl:
        if value.scheme != "https":
            raise ValueError("Service URL must use HTTPS")
        return value

    @field_validator("allowed_domains")
    @classmethod
    def clean_domains(cls, values: list[str]) -> list[str]:
        output = []
        for raw in values:
            value = raw.strip().lower().lstrip(".").rstrip(".")
            try:
                ipaddress.ip_address(value)
            except ValueError:
                address = None
            else:
                address = value
            labels = value.split(".")
            if (
                not value
                or len(value) > 253
                or "://" in value
                or "/" in value
                or "." not in value
                or address is not None
                or value in {"localhost", "local"}
                or value in PRIVATE_HOSTING_SUFFIXES
                or value.endswith((".localhost", ".local", ".internal"))
                or any(
                    not part
                    or len(part) > 63
                    or not part.isascii()
                    or part.startswith("-")
                    or part.endswith("-")
                    or not all(char.isalnum() or char == "-" for char in part)
                    for part in labels
                )
            ):
                raise ValueError(f"Invalid allowed domain: {raw}")
            parts = labels
            if (
                len(parts) == 2
                and len(parts[-1]) == 2
                and parts[-2] in {"ac", "co", "com", "edu", "gov", "net", "org"}
            ):
                raise ValueError(f"Public suffix cannot be an allowed domain: {raw}")
            output.append(value)
        if len(output) != len(set(output)):
            raise ValueError("Allowed domains contain duplicates")
        return output

    @field_validator("proxy_hostname")
    @classmethod
    def clean_proxy_hostname(cls, raw: str | None) -> str | None:
        if raw is None or not raw.strip():
            return None
        value = raw.strip().lower().rstrip(".")
        if (
            "://" in value
            or "/" in value
            or ":" in value
            or "." not in value
            or value.startswith(".")
            or any(not part or len(part) > 63 for part in value.split("."))
            or any(
                not all(char.isalnum() or char == "-" for char in part)
                or not part.isascii()
                or part.startswith("-")
                or part.endswith("-")
                for part in value.split(".")
            )
        ):
            raise ValueError("proxy_hostname must be a public DNS hostname without scheme/path")
        return value

    @field_validator("allowed_paths")
    @classmethod
    def clean_paths(cls, values: list[str]) -> list[str]:
        if not all(value.startswith("/") and len(value) <= 500 for value in values):
            raise ValueError("Every allowed path must start with /")
        return list(dict.fromkeys(values))

    @field_validator("allowed_cookie_names")
    @classmethod
    def clean_cookie_names(cls, values: list[str]) -> list[str]:
        output = []
        for raw in values:
            value = raw.strip()
            if not value or len(value) > 250 or any(char in value for char in " \t\r\n;,="):
                raise ValueError(f"Invalid cookie name: {raw}")
            output.append(value)
        return list(dict.fromkeys(output))

    @model_validator(mode="after")
    def upstream_is_allowed(self):
        host = (urlparse(str(self.upstream_url)).hostname or "").lower()
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
        if address and (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
        ):
            raise ValueError("Service URL cannot target a private address")
        if not any(
            host == domain or host.endswith("." + domain) for domain in self.allowed_domains
        ):
            raise ValueError("Service hostname must be inside allowed_domains")
        return self


class CookieImport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cookies: str = Field(min_length=1, max_length=100_000)


class LaunchInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pass


class CfClearanceInject(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain: str = Field(min_length=3, max_length=253)
    cf_clearance: str = Field(min_length=10, max_length=4096)
    ttl_seconds: int = Field(default=2700, ge=60, le=24 * 3600 * 7)

    @field_validator("domain")
    @classmethod
    def clean_domain(cls, raw: str) -> str:
        value = raw.strip().lower().lstrip(".").rstrip(".")
        if (
            not value
            or "://" in value
            or "/" in value
            or ":" in value
            or "." not in value
            or any(not part or len(part) > 63 for part in value.split("."))
        ):
            raise ValueError("domain must be a plain DNS hostname")
        return value

    @field_validator("cf_clearance")
    @classmethod
    def validate_clearance_value(cls, raw: str) -> str:
        value = raw.strip()
        if value.startswith("cf_clearance="):
            value = value.split("=", 1)[1].split(";", 1)[0].strip()
        if len(value) < 20 or any(c.isspace() for c in value):
            raise ValueError("cf_clearance value looks malformed")
        return value


class CfSolveUrlInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: HttpUrl = Field(description="URL protected by Cloudflare to solve")
    impersonate: str = Field(default="chrome124", min_length=3, max_length=40)
    max_timeout_seconds: int = Field(default=120, ge=15, le=600)


class LocalStorageImport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: str = Field(
        min_length=1, max_length=500_000, description="JSON string of localStorage key-value pairs"
    )
