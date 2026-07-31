from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
from uuid import UUID

import asyncpg

from .models import ImportedCookie, ServicePolicy
from .parser import parse_cookie_import, validate_cookie
from .vault import CookieVault


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class ConsumedLaunch:
    user_id: str
    service_id: str
    profile_id: str
    upstream_url: str
    allowed_domains: tuple[str, ...]
    allowed_paths: tuple[str, ...]
    allowed_cookie_names: tuple[str, ...]
    cookies: list[dict]


class CookieSessionCore:
    """Database-backed use cases. Authentication remains owned by the host app."""

    def __init__(self, pool: asyncpg.Pool, vault_key: bytes, token_pepper: bytes):
        if len(token_pepper) < 32:
            raise ValueError("LAUNCH_TOKEN_PEPPER must contain at least 32 random bytes")
        self.pool = pool
        self.vault = CookieVault(vault_key)
        self.token_pepper = token_pepper

    def _token_hash(self, raw: str) -> str:
        return hmac.new(self.token_pepper, raw.encode(), hashlib.sha256).hexdigest()

    async def import_profile(
        self,
        *,
        actor_user_id: str,
        subject_user_id: str,
        service_id: str,
        label: str,
        raw_cookies: str,
        profile_id: str | None = None,
        make_default: bool = False,
    ) -> tuple[str, int]:
        """Admin-only at the HTTP boundary. Never accept actor identity from the browser."""
        service_uuid = UUID(service_id)
        profile_uuid = UUID(profile_id) if profile_id else None
        async with self.pool.acquire() as conn, conn.transaction():
            row = await conn.fetchrow(
                "SELECT * FROM cookie_core_services WHERE id=$1 AND enabled=true", service_uuid
            )
            if not row:
                raise ValueError("Service not found or disabled")
            policy = ServicePolicy(
                id=str(row["id"]),
                name=row["name"],
                upstream_url=row["upstream_url"],
                allowed_domains=tuple(row["allowed_domains"]),
                allowed_paths=tuple(row["allowed_paths"]),
                allowed_cookie_names=tuple(row["allowed_cookie_names"]),
            )
            default_domain = urlparse(policy.upstream_url).hostname or ""
            cookies = parse_cookie_import(raw_cookies, default_domain)
            for cookie in cookies:
                validate_cookie(cookie, policy)

            if profile_uuid:
                owner = await conn.fetchval(
                    """SELECT 1 FROM cookie_core_profiles
                       WHERE id=$1 AND user_id=$2 AND service_id=$3""",
                    profile_uuid, subject_user_id, service_uuid,
                )
                if not owner:
                    raise ValueError("Profile does not belong to this user and service")
                await conn.execute(
                    "UPDATE cookie_core_profiles SET label=$1, updated_at=now() WHERE id=$2",
                    label, profile_uuid,
                )
            else:
                profile_id = str(await conn.fetchval(
                    """INSERT INTO cookie_core_profiles(user_id, service_id, label)
                       VALUES($1,$2,$3) RETURNING id""",
                    subject_user_id, service_uuid, label,
                ))
                profile_uuid = UUID(profile_id)

            await conn.execute(
                """DELETE FROM cookie_core_stored_cookies
                   WHERE user_id=$1 AND service_id=$2 AND profile_id=$3""",
                subject_user_id, service_uuid, profile_uuid,
            )
            for cookie in cookies:
                encrypted = self.vault.encrypt(
                    cookie.value, subject_user_id, service_id, cookie.name
                )
                await conn.execute(
                    """INSERT INTO cookie_core_stored_cookies(
                         user_id,service_id,profile_id,name,domain,path,
                         encrypted_value,nonce,expires_at,secure,http_only,same_site
                       ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)""",
                    subject_user_id, service_uuid, profile_uuid, cookie.name,
                    cookie.domain.lower(), cookie.path, encrypted.ciphertext,
                    encrypted.nonce, cookie.expires_at, cookie.secure,
                    cookie.http_only, cookie.same_site,
                )
            if make_default:
                await conn.execute(
                    """UPDATE cookie_core_profiles SET is_default=(id=$1)
                       WHERE user_id=$2 AND service_id=$3""",
                    profile_uuid, subject_user_id, service_uuid,
                )
            await conn.execute(
                """INSERT INTO cookie_core_audit_logs(
                     actor_user_id,subject_user_id,service_id,profile_id,action,details
                   ) VALUES($1,$2,$3,$4,'cookies.import',$5::jsonb)""",
                actor_user_id, subject_user_id, service_uuid, profile_uuid,
                f'{{"count":{len(cookies)}}}',
            )
            return str(profile_uuid), len(cookies)

    async def issue_launch(
        self, *, user_id: str, service_id: str, profile_id: str, ttl_seconds: int = 30
    ) -> str:
        if not 5 <= ttl_seconds <= 120:
            raise ValueError("Launch token TTL must be between 5 and 120 seconds")
        raw = secrets.token_urlsafe(32)
        service_uuid = UUID(service_id)
        profile_uuid = UUID(profile_id)
        async with self.pool.acquire() as conn:
            inserted = await conn.fetchval(
                """INSERT INTO cookie_core_launch_tokens(
                     token_hash,user_id,service_id,profile_id,expires_at
                   )
                   SELECT $1,$2,p.service_id,p.id,$5
                   FROM cookie_core_profiles p
                   JOIN cookie_core_services s ON s.id=p.service_id AND s.enabled=true
                   WHERE p.id=$4 AND p.user_id=$2 AND p.service_id=$3
                     AND EXISTS (
                       SELECT 1 FROM cookie_core_stored_cookies c
                       WHERE c.profile_id=p.id AND c.user_id=p.user_id
                         AND c.service_id=p.service_id AND c.revoked_at IS NULL
                         AND (c.expires_at IS NULL OR c.expires_at > now())
                     )
                   RETURNING id""",
                self._token_hash(raw), user_id, service_uuid, profile_uuid,
                _now() + timedelta(seconds=ttl_seconds),
            )
            if not inserted:
                raise ValueError("Profile is unavailable for this user")
        return raw

    async def consume_launch(
        self, *, raw_token: str, user_id: str | None = None
    ) -> ConsumedLaunch:
        """Atomically consumes a one-use token and decrypts only its owner's cookies."""
        async with self.pool.acquire() as conn, conn.transaction():
            grant = await conn.fetchrow(
                """DELETE FROM cookie_core_launch_tokens
                   WHERE token_hash=$1
                     AND ($2::text IS NULL OR user_id=$2)
                     AND consumed_at IS NULL
                     AND expires_at > now()
                   RETURNING user_id,service_id,profile_id""",
                self._token_hash(raw_token), user_id,
            )
            if not grant:
                raise ValueError("Launch token is invalid, expired, or already used")
            owner_user_id = grant["user_id"]
            service = await conn.fetchrow(
                "SELECT * FROM cookie_core_services WHERE id=$1 AND enabled=true",
                grant["service_id"],
            )
            rows = await conn.fetch(
                """SELECT * FROM cookie_core_stored_cookies
                   WHERE user_id=$1 AND service_id=$2 AND profile_id=$3
                     AND revoked_at IS NULL
                     AND (expires_at IS NULL OR expires_at > now())""",
                owner_user_id, grant["service_id"], grant["profile_id"],
            )
            cookies = [
                {
                    "name": row["name"],
                    "value": self.vault.decrypt(
                        row["encrypted_value"], row["nonce"], owner_user_id,
                        str(grant["service_id"]), row["name"],
                    ),
                    "domain": row["domain"],
                    "path": row["path"],
                    "secure": row["secure"],
                    "httpOnly": row["http_only"],
                    "sameSite": row["same_site"] or "Lax",
                    **({"expires": row["expires_at"].timestamp()} if row["expires_at"] else {}),
                }
                for row in rows
            ]
            await conn.execute(
                """INSERT INTO cookie_core_audit_logs(
                     actor_user_id,subject_user_id,service_id,profile_id,action,details
                   ) VALUES($1,$1,$2,$3,'cookies.inject',$4::jsonb)""",
                owner_user_id, grant["service_id"], grant["profile_id"],
                f'{{"count":{len(cookies)}}}',
            )
            return ConsumedLaunch(
                user_id=owner_user_id,
                service_id=str(grant["service_id"]),
                profile_id=str(grant["profile_id"]),
                upstream_url=service["upstream_url"],
                allowed_domains=tuple(service["allowed_domains"]),
                allowed_paths=tuple(service["allowed_paths"]),
                allowed_cookie_names=tuple(service["allowed_cookie_names"]),
                cookies=cookies,
            )

    async def sync_browser_cookies(
        self, launch: ConsumedLaunch, browser_cookies: list[dict]
    ) -> int:
        """Persists cookie rotation back into the same owner/service/profile tuple."""
        policy = ServicePolicy(
            id=launch.service_id,
            name="runtime",
            upstream_url=launch.upstream_url,
            allowed_domains=launch.allowed_domains,
            allowed_paths=launch.allowed_paths,
            allowed_cookie_names=launch.allowed_cookie_names,
        )
        parsed = [
            ImportedCookie(
                name=str(item["name"]),
                value=str(item["value"]),
                domain=str(item["domain"]),
                path=str(item.get("path") or "/"),
                expires_at=(
                    datetime.fromtimestamp(float(item["expires"]), tz=timezone.utc)
                    if float(item.get("expires") or 0) > 0
                    else None
                ),
                secure=bool(item.get("secure", True)),
                http_only=bool(item.get("httpOnly", True)),
                same_site=str(item.get("sameSite") or "Lax"),
            )
            for item in browser_cookies
        ]
        parsed = [
            item
            for item in parsed
            if any(
                item.domain.lower().lstrip(".") == domain.lower().lstrip(".")
                or item.domain.lower().lstrip(".").endswith(
                    "." + domain.lower().lstrip(".")
                )
                for domain in launch.allowed_domains
            )
        ]
        for cookie in parsed:
            validate_cookie(cookie, policy)

        async with self.pool.acquire() as conn, conn.transaction():
            service_uuid = UUID(launch.service_id)
            profile_uuid = UUID(launch.profile_id)
            owner = await conn.fetchval(
                """SELECT 1 FROM cookie_core_profiles
                   WHERE id=$1 AND user_id=$2 AND service_id=$3""",
                profile_uuid, launch.user_id, service_uuid,
            )
            if not owner:
                raise ValueError("Cookie profile ownership changed")
            await conn.execute(
                """DELETE FROM cookie_core_stored_cookies
                   WHERE user_id=$1 AND service_id=$2 AND profile_id=$3""",
                launch.user_id, service_uuid, profile_uuid,
            )
            for cookie in parsed:
                encrypted = self.vault.encrypt(
                    cookie.value, launch.user_id, launch.service_id, cookie.name
                )
                await conn.execute(
                    """INSERT INTO cookie_core_stored_cookies(
                         user_id,service_id,profile_id,name,domain,path,
                         encrypted_value,nonce,expires_at,secure,http_only,same_site
                       ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)""",
                    launch.user_id, service_uuid, profile_uuid,
                    cookie.name, cookie.domain.lower(), cookie.path,
                    encrypted.ciphertext, encrypted.nonce, cookie.expires_at,
                    cookie.secure, cookie.http_only, cookie.same_site,
                )
            await conn.execute(
                """INSERT INTO cookie_core_audit_logs(
                     actor_user_id,subject_user_id,service_id,profile_id,action,details
                   ) VALUES($1,$1,$2,$3,'cookies.rotate',$4::jsonb)""",
                launch.user_id, service_uuid, profile_uuid,
                f'{{"count":{len(parsed)}}}',
            )
        return len(parsed)
