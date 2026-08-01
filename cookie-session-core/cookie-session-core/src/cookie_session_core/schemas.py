from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator, model_validator


class ServiceInput(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    category: str = Field(default="Geral", max_length=80)
    upstream_url: HttpUrl
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
            if (
                not value
                or "://" in value
                or "/" in value
                or "." not in value
                or value in {"localhost", "local"}
                or value.endswith((".localhost", ".local", ".internal"))
            ):
                raise ValueError(f"Invalid allowed domain: {raw}")
            parts = value.split(".")
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
