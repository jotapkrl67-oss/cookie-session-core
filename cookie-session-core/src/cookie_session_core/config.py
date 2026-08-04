from __future__ import annotations

import base64
from enum import Enum
from functools import cached_property, lru_cache
from typing import Annotated
from urllib.parse import urlparse

from pydantic import Field, HttpUrl, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class CfSolverProvider(str, Enum):
    NONE = "none"
    CAPSOLVER = "capsolver"
    ANTICAPTCHA = "anticaptcha"
    YESCAPTCHA = "yescaptcha"
    TWOCAPTCHA = "2captcha"
    CUSTOM = "custom"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    database_url: str = Field(min_length=20)
    supabase_url: HttpUrl
    supabase_publishable_key: str = Field(min_length=20)
    supabase_jwt_audience: str = "authenticated"
    cookie_vault_key_base64: str
    launch_token_pepper_base64: str
    admin_proxy_secret: str = Field(min_length=32)
    public_base_url: HttpUrl
    allowed_origins: str
    proxy_grant_ttl_seconds: int = Field(default=1800, ge=60, le=7200)
    proxy_timeout_seconds: int = Field(default=60, ge=5, le=180)
    proxy_max_rewrite_bytes: int = Field(default=10_000_000, ge=100_000, le=50_000_000)
    secure_cookies: bool = True
    metrics_enabled: bool = True
    blocked_cookie_public_suffixes: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: [
            "com",
            "org",
            "net",
            "edu",
            "gov",
            "mil",
            "io",
            "co.uk",
            "org.uk",
            "com.br",
            "com.au",
            "com.mx",
            "co.jp",
            "co.in",
            "co.nz",
            "co.za",
            "com.cn",
            "com.sg",
            "com.tr",
            "com.ar",
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
        ]
    )

    cf_solver_provider: CfSolverProvider = CfSolverProvider.NONE
    cf_solver_providers: Annotated[list[CfSolverProvider], NoDecode] = Field(default_factory=list)
    cf_solver_api_key: str = ""
    cf_solver_api_keys: dict[str, str] = Field(default_factory=dict)
    cf_solver_provider_timeouts: dict[str, int] = Field(default_factory=dict)
    cf_solver_api_endpoint: HttpUrl | None = None
    cf_solver_timeout_seconds: int = Field(default=120, ge=10, le=600)
    cf_solver_max_retries: int = Field(default=2, ge=0, le=5)
    cf_solver_impersonate_targets: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["chrome124", "chrome120", "safari17_2_ios"]
    )

    @field_validator("database_url")
    @classmethod
    def postgres_only(cls, value: str) -> str:
        if not value.startswith(("postgres://", "postgresql://")):
            raise ValueError("DATABASE_URL must be PostgreSQL")
        return value

    @field_validator("public_base_url")
    @classmethod
    def public_base_must_be_an_origin(cls, value: HttpUrl) -> HttpUrl:
        parsed = urlparse(str(value))
        if (
            parsed.scheme != "https"
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or parsed.username
            or parsed.password
        ):
            raise ValueError("PUBLIC_BASE_URL must be one HTTPS origin without path/query")
        return value

    @field_validator("cf_solver_provider", mode="before")
    @classmethod
    def normalize_provider(cls, value: object) -> CfSolverProvider:
        if isinstance(value, CfSolverProvider):
            return value
        raw = str(value).strip().lower()
        for member in CfSolverProvider:
            if member.value == raw:
                return member
        return CfSolverProvider.NONE

    @field_validator("cf_solver_providers", mode="before")
    @classmethod
    def normalize_providers(cls, value: object) -> list[CfSolverProvider]:
        if value in (None, "", []):
            return []
        values = value if isinstance(value, list) else str(value).split(",")
        output: list[CfSolverProvider] = []
        for item in values:
            raw = str(item).strip().lower()
            provider = next((p for p in CfSolverProvider if p.value == raw), None)
            if provider and provider != CfSolverProvider.NONE and provider not in output:
                output.append(provider)
        return output

    @field_validator("blocked_cookie_public_suffixes", mode="before")
    @classmethod
    def normalize_blocked_suffixes(cls, value: object) -> list[str]:
        values = value if isinstance(value, list) else str(value).split(",")
        return [str(item).strip().lower().lstrip(".") for item in values if str(item).strip()]

    @property
    def solver_provider_list(self) -> list[CfSolverProvider]:
        if self.cf_solver_providers:
            return self.cf_solver_providers
        return [] if self.cf_solver_provider == CfSolverProvider.NONE else [self.cf_solver_provider]

    @field_validator("cf_solver_impersonate_targets", mode="before")
    @classmethod
    def normalize_targets(cls, value: object) -> list[str]:
        if isinstance(value, list):
            return [str(x).strip() for x in value if str(x).strip()]
        if isinstance(value, str):
            parts = [p.strip() for p in value.split(",") if p.strip()]
            if parts:
                return parts
        return ["chrome124", "chrome120", "safari17_2_ios"]

    @cached_property
    def vault_key(self) -> bytes:
        return self._decode_secret(self.cookie_vault_key_base64, "COOKIE_VAULT_KEY_BASE64")

    @cached_property
    def token_pepper(self) -> bytes:
        return self._decode_secret(self.launch_token_pepper_base64, "LAUNCH_TOKEN_PEPPER_BASE64")

    @cached_property
    def origin_list(self) -> list[str]:
        values = [item.strip().rstrip("/") for item in self.allowed_origins.split(",")]
        values = [value for value in values if value]
        if not values or not all(
            value.startswith("https://")
            and (parsed := urlparse(value)).path in {"", "/"}
            and bool(parsed.hostname)
            and not parsed.query
            and not parsed.fragment
            and not parsed.username
            and not parsed.password
            for value in values
        ):
            raise ValueError("ALLOWED_ORIGINS must contain only HTTPS origins without paths")
        return values

    @staticmethod
    def _decode_secret(value: str, name: str) -> bytes:
        try:
            decoded = base64.b64decode(value, validate=True)
        except ValueError as exc:
            raise ValueError(f"{name} must be valid base64") from exc
        if len(decoded) < 32:
            raise ValueError(f"{name} must decode to at least 32 bytes")
        return decoded


@lru_cache
def get_settings() -> Settings:
    return Settings()
