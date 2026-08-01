from __future__ import annotations

import base64
from enum import Enum
from functools import cached_property, lru_cache

from pydantic import Field, HttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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

    cf_solver_provider: CfSolverProvider = CfSolverProvider.NONE
    cf_solver_api_key: str = ""
    cf_solver_api_endpoint: HttpUrl | None = None
    cf_solver_timeout_seconds: int = Field(default=120, ge=10, le=600)
    cf_solver_max_retries: int = Field(default=2, ge=0, le=5)
    cf_solver_impersonate_targets: list[str] = Field(
        default_factory=lambda: ["chrome124", "chrome120", "safari17_2_ios"]
    )

    @field_validator("database_url")
    @classmethod
    def postgres_only(cls, value: str) -> str:
        if not value.startswith(("postgres://", "postgresql://")):
            raise ValueError("DATABASE_URL must be PostgreSQL")
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
        if not all(value.startswith("https://") for value in values if value):
            raise ValueError("ALLOWED_ORIGINS must contain only HTTPS origins")
        return [value for value in values if value]

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
