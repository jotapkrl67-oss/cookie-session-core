from __future__ import annotations

import base64
import hashlib
from enum import Enum
from functools import cached_property, lru_cache
from typing import Annotated
from urllib.parse import quote, urlparse

from pydantic import Field, HttpUrl, field_validator, model_validator
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
    supabase_jwks_timeout_seconds: int = Field(default=8, ge=2, le=30)
    cookie_vault_key_base64: str
    launch_token_pepper_base64: str
    admin_proxy_secret: str = Field(min_length=32)
    public_base_url: HttpUrl
    allowed_origins: str
    proxy_grant_ttl_seconds: int = Field(default=1800, ge=60, le=7200)
    proxy_grant_refresh_interval_seconds: int = Field(default=60, ge=15, le=600)
    auth_rate_limit_per_minute: int = Field(default=300, ge=30, le=5000)
    database_startup_attempts: int = Field(default=10, ge=1, le=30)
    database_startup_max_delay_seconds: int = Field(default=10, ge=1, le=60)
    proxy_timeout_seconds: int = Field(default=60, ge=5, le=180)
    proxy_max_rewrite_bytes: int = Field(default=10_000_000, ge=100_000, le=50_000_000)
    proxy_max_request_body_bytes: int = Field(
        default=50_000_000, ge=1_000_000, le=500_000_000
    )
    profile_lock_enabled: bool = True
    egress_dns_cache_seconds: int = Field(default=60, ge=0, le=3600)
    secure_cookies: bool = True
    metrics_enabled: bool = True
    log_file_path: str = "/app/logs/cookie-session-core.txt"
    log_level: str = "INFO"
    log_max_bytes: int = Field(default=20_000_000, ge=1_000_000, le=500_000_000)
    log_backup_count: int = Field(default=5, ge=1, le=30)
    log_slow_request_ms: int = Field(default=3000, ge=100, le=120_000)
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
    playwright_service_url: HttpUrl | None = None
    playwright_service_token: str = ""
    playwright_service_allow_insecure_http: bool = False
    upstream_proxy_url: str = ""
    upstream_proxy_username: str = ""
    upstream_proxy_password: str = ""
    cf_auto_refresh: bool = True
    cf_clearance_expiry_skew_seconds: int = Field(default=15, ge=0, le=300)
    cf_clearance_default_ttl_seconds: int = Field(default=2700, ge=1, le=86400)
    cf_clearance_max_ttl_seconds: int = Field(default=86400, ge=60, le=604800)
    cf_solve_cooldown_seconds: int = Field(default=30, ge=0, le=3600)
    cf_solve_negative_cache_seconds: int = Field(default=10, ge=0, le=300)
    cf_clearance_store_max_entries: int = Field(default=1000, ge=1, le=100_000)
    cf_challenge_body_inspection_limit_bytes: int = Field(default=262_144, ge=1024, le=2_000_000)
    cf_request_replay_buffer_limit_bytes: int = Field(default=2_000_000, ge=0, le=50_000_000)

    @field_validator("database_url")
    @classmethod
    def postgres_only(cls, value: str) -> str:
        if not value.startswith(("postgres://", "postgresql://")):
            raise ValueError("DATABASE_URL must be PostgreSQL")
        return value

    @field_validator("log_level")
    @classmethod
    def supported_log_level(cls, value: str) -> str:
        normalized = value.strip().upper()
        if normalized not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("LOG_LEVEL must be DEBUG, INFO, WARNING, ERROR, or CRITICAL")
        return normalized

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

    @field_validator("playwright_service_url")
    @classmethod
    def playwright_service_must_be_an_origin(cls, value: HttpUrl | None) -> HttpUrl | None:
        if value is None:
            return None
        parsed = urlparse(str(value))
        if (
            parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or parsed.username
            or parsed.password
        ):
            raise ValueError("PLAYWRIGHT_SERVICE_URL must be one HTTP(S) origin")
        return value

    @field_validator("cf_solver_api_endpoint")
    @classmethod
    def solver_endpoint_must_be_https(cls, value: HttpUrl | None) -> HttpUrl | None:
        if value is not None and urlparse(str(value)).scheme != "https":
            raise ValueError("CF_SOLVER_API_ENDPOINT must use HTTPS")
        return value

    @field_validator("playwright_service_token")
    @classmethod
    def normalize_playwright_service_token(cls, value: str) -> str:
        return value.strip()

    @field_validator("upstream_proxy_url")
    @classmethod
    def upstream_proxy_must_be_an_origin(cls, value: str) -> str:
        value = value.strip().rstrip("/")
        if not value:
            return value
        parsed = urlparse(value)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("UPSTREAM_PROXY_URL must be an HTTP(S) proxy origin")
        return value

    @field_validator("upstream_proxy_username", "upstream_proxy_password")
    @classmethod
    def valid_upstream_proxy_credentials(cls, value: str) -> str:
        if len(value) > 1024 or any(ord(char) < 32 for char in value):
            raise ValueError("Upstream proxy credentials are malformed")
        return value

    @model_validator(mode="after")
    def require_playwright_service_token(self) -> "Settings":
        if (
            self.cf_auto_refresh
            and self.playwright_service_url is not None
            and len(self.playwright_service_token) < 32
        ):
            raise ValueError(
                "PLAYWRIGHT_SERVICE_TOKEN must contain at least 32 characters when "
                "PLAYWRIGHT_SERVICE_URL is configured"
            )
        if (
            self.cf_auto_refresh
            and self.playwright_service_url is not None
            and urlparse(str(self.playwright_service_url)).scheme != "https"
            and not self.playwright_service_allow_insecure_http
        ):
            raise ValueError(
                "PLAYWRIGHT_SERVICE_URL must use HTTPS unless "
                "PLAYWRIGHT_SERVICE_ALLOW_INSECURE_HTTP=true"
            )
        if self.cf_clearance_default_ttl_seconds > self.cf_clearance_max_ttl_seconds:
            raise ValueError("CF_CLEARANCE_DEFAULT_TTL_SECONDS cannot exceed max TTL")
        if (self.upstream_proxy_username or self.upstream_proxy_password) and not self.upstream_proxy_url:
            raise ValueError("Upstream proxy credentials require UPSTREAM_PROXY_URL")
        if self.upstream_proxy_password and not self.upstream_proxy_username:
            raise ValueError("UPSTREAM_PROXY_USERNAME is required when a password is configured")
        providers = self.solver_provider_list
        if CfSolverProvider.CUSTOM in providers and self.cf_solver_api_endpoint is None:
            raise ValueError("CF_SOLVER_API_ENDPOINT is required for the custom provider")
        for provider in providers:
            if (
                provider != CfSolverProvider.CUSTOM
                and not self.cf_solver_api_keys.get(provider.value, self.cf_solver_api_key).strip()
            ):
                raise ValueError(f"A solver API key is required for provider {provider.value}")
        valid_provider_keys = {item.value for item in CfSolverProvider if item != CfSolverProvider.NONE}
        if invalid := set(self.cf_solver_api_keys) - valid_provider_keys:
            raise ValueError(f"CF_SOLVER_API_KEYS has unknown providers: {sorted(invalid)}")
        if invalid := set(self.cf_solver_provider_timeouts) - valid_provider_keys:
            raise ValueError(
                f"CF_SOLVER_PROVIDER_TIMEOUTS has unknown providers: {sorted(invalid)}"
            )
        if any(not 10 <= int(value) <= 600 for value in self.cf_solver_provider_timeouts.values()):
            raise ValueError("CF_SOLVER_PROVIDER_TIMEOUTS values must be between 10 and 600")
        return self

    @property
    def egress_id(self) -> str:
        if not self.upstream_proxy_url:
            return "direct"
        raw = "|".join(
            (self.upstream_proxy_url, self.upstream_proxy_username, self.upstream_proxy_password)
        )
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @property
    def httpx_proxy_url(self) -> str | None:
        if not self.upstream_proxy_url:
            return None
        if not self.upstream_proxy_username:
            return self.upstream_proxy_url
        credentials = quote(self.upstream_proxy_username, safe="")
        if self.upstream_proxy_password:
            credentials += ":" + quote(self.upstream_proxy_password, safe="")
        return self.upstream_proxy_url.replace("://", f"://{credentials}@", 1)

    @property
    def cloudflare_cookie_provider_enabled(self) -> bool:
        return bool(
            self.cf_auto_refresh
            and self.playwright_service_url is not None
            and self.playwright_service_token
        )

    @field_validator("cf_solver_provider", mode="before")
    @classmethod
    def normalize_provider(cls, value: object) -> CfSolverProvider:
        if isinstance(value, CfSolverProvider):
            return value
        raw = str(value).strip().lower()
        for member in CfSolverProvider:
            if member.value == raw:
                return member
        raise ValueError(f"Unknown CF_SOLVER_PROVIDER: {raw}")

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
            if provider is None:
                raise ValueError(f"Unknown CF_SOLVER_PROVIDERS entry: {raw}")
            if provider != CfSolverProvider.NONE and provider not in output:
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
