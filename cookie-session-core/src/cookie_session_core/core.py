from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from http.cookies import SimpleCookie
from urllib.parse import urlparse
from uuid import UUID

import asyncpg

from .models import ImportedCookie, ImportedLocalStorageItem, ServicePolicy
from .parser import parse_cookie_import, parse_localstorage_import, validate_cookie
from .vault import CookieVault


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class ConsumedLaunch:
    user_id: str
    service_id: str
    upstream_url: str
    allowed_domains: tuple[str, ...]
    allowed_paths: tuple[str, ...]
    allowed_cookie_names: tuple[str, ...]
    cookies: list[dict]
    local_storage_items: dict[str, str]
    proxy_hostname: str | None = None


class CookieSessionCore:
    """Database-backed use cases. Authentication remains owned by the host app."""

    def __init__(
        self,
        pool: asyncpg.Pool,
        vault_key: bytes,
        token_pepper: bytes,
        blocked_cookie_public_suffixes: set[str] | None = None,
    ):
        if len(token_pepper) < 32:
            raise ValueError("LAUNCH_TOKEN_PEPPER must contain at least 32 random bytes")
        self.pool = pool
        self.vault = CookieVault(vault_key)
        self.token_pepper = token_pepper
        self.blocked_cookie_public_suffixes = blocked_cookie_public_suffixes

    def _token_hash(self, raw: str) -> str:
        return hmac.new(self.token_pepper, raw.encode(), hashlib.sha256).hexdigest()

    async def _load_local_storage_items(
        self, conn: asyncpg.Connection, user_id: str, service_id: str
    ) -> dict[str, str]:
        rows = await conn.fetch(
            """SELECT item_key,encrypted_value,nonce
               FROM cookie_core_stored_localstorage
               WHERE user_id=$1 AND service_id=$2
                 AND revoked_at IS NULL""",
            user_id,
            UUID(service_id),
        )
        result: dict[str, str] = {}
        for row in rows:
            try:
                value = self.vault.decrypt(
                    row["encrypted_value"],
                    row["nonce"],
                    user_id,
                    service_id,
                    row["item_key"],
                )
                result[row["item_key"]] = value
            except Exception:
                continue
        return result

    async def import_cookies(
        self,
        *,
        actor_user_id: str,
        subject_user_id: str,
        service_id: str,
        raw_cookies: str,
    ) -> int:
        """Admin-only at the HTTP boundary. Never accept actor identity from the browser."""
        service_uuid = UUID(service_id)
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
                validate_cookie(cookie, policy, self.blocked_cookie_public_suffixes)

            await conn.execute(
                """DELETE FROM cookie_core_stored_cookies
                   WHERE user_id=$1 AND service_id=$2""",
                subject_user_id,
                service_uuid,
            )
            for cookie in cookies:
                encrypted = self.vault.encrypt(
                    cookie.value, subject_user_id, service_id, cookie.name
                )
                await conn.execute(
                    """INSERT INTO cookie_core_stored_cookies(
                         user_id,service_id,name,domain,path,
                         encrypted_value,nonce,expires_at,secure,http_only,same_site
                       ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)""",
                    subject_user_id,
                    service_uuid,
                    cookie.name,
                    cookie.domain.lower(),
                    cookie.path,
                    encrypted.ciphertext,
                    encrypted.nonce,
                    cookie.expires_at,
                    cookie.secure,
                    cookie.http_only,
                    cookie.same_site,
                )
            await conn.execute(
                """INSERT INTO cookie_core_audit_logs(
                     actor_user_id,subject_user_id,service_id,action,details
                   ) VALUES($1,$2,$3,'cookies.import',$4::jsonb)""",
                actor_user_id,
                subject_user_id,
                service_uuid,
                f'{{"count":{len(cookies)}}}',
            )
            return len(cookies)

    async def issue_launch(self, *, user_id: str, service_id: str, ttl_seconds: int = 30) -> str:
        if not 5 <= ttl_seconds <= 120:
            raise ValueError("Launch token TTL must be between 5 and 120 seconds")
        raw = secrets.token_urlsafe(32)
        service_uuid = UUID(service_id)
        async with self.pool.acquire() as conn:
            inserted = await conn.fetchval(
                """INSERT INTO cookie_core_launch_tokens(
                     token_hash,user_id,service_id,expires_at
                   )
                   SELECT $1,$2,s.id,$4
                   FROM cookie_core_services s
                   WHERE s.id=$3 AND s.enabled=true
                     AND (
                       EXISTS (
                         SELECT 1 FROM cookie_core_stored_cookies c
                         WHERE c.user_id=$2 AND c.service_id=s.id
                           AND c.revoked_at IS NULL
                           AND (c.expires_at IS NULL OR c.expires_at > now())
                       )
                       OR EXISTS (
                         SELECT 1 FROM cookie_core_stored_localstorage l
                         WHERE l.user_id=$2 AND l.service_id=s.id
                           AND l.revoked_at IS NULL
                       )
                     )
                   RETURNING id""",
                self._token_hash(raw),
                user_id,
                service_uuid,
                _now() + timedelta(seconds=ttl_seconds),
            )
            if not inserted:
                raise ValueError("Cookies or localStorage are not configured for this user and service")
        return raw

    async def consume_launch(self, *, raw_token: str, user_id: str | None = None) -> ConsumedLaunch:
        """Atomically consumes a one-use token and decrypts only its owner's cookies."""
        async with self.pool.acquire() as conn, conn.transaction():
            grant = await conn.fetchrow(
                """DELETE FROM cookie_core_launch_tokens
                   WHERE token_hash=$1
                     AND ($2::text IS NULL OR user_id=$2)
                     AND consumed_at IS NULL
                     AND expires_at > now()
                   RETURNING user_id,service_id""",
                self._token_hash(raw_token),
                user_id,
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
                   WHERE user_id=$1 AND service_id=$2
                     AND revoked_at IS NULL
                     AND (expires_at IS NULL OR expires_at > now())""",
                owner_user_id,
                grant["service_id"],
            )
            cookies = [
                {
                    "name": row["name"],
                    "value": self.vault.decrypt(
                        row["encrypted_value"],
                        row["nonce"],
                        owner_user_id,
                        str(grant["service_id"]),
                        row["name"],
                    ),
                    "domain": row["domain"],
                    "path": row["path"],
                    "secure": row["secure"],
                    "httpOnly": row["http_only"],
                    "sameSite": row["same_site"] or "Lax",
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"],
                    **({"expires": row["expires_at"].timestamp()} if row["expires_at"] else {}),
                }
                for row in rows
            ]
            local_storage = await self._load_local_storage_items(
                conn, owner_user_id, str(grant["service_id"])
            )
            await conn.execute(
                """INSERT INTO cookie_core_audit_logs(
                     actor_user_id,subject_user_id,service_id,action,details
                   ) VALUES($1,$1,$2,'cookies.inject',$3::jsonb)""",
                owner_user_id,
                grant["service_id"],
                f'{{"cookie_count":{len(cookies)},"localstorage_count":{len(local_storage)}}}',
            )
            return ConsumedLaunch(
                user_id=owner_user_id,
                service_id=str(grant["service_id"]),
                upstream_url=service["upstream_url"],
                allowed_domains=tuple(service["allowed_domains"]),
                allowed_paths=tuple(service["allowed_paths"]),
                allowed_cookie_names=tuple(service["allowed_cookie_names"]),
                cookies=cookies,
                local_storage_items=local_storage,
                proxy_hostname=service.get("proxy_hostname"),
            )

    async def create_proxy_grant(self, launch: ConsumedLaunch, ttl_seconds: int) -> str:
        """Creates the only browser-visible credential; it contains no upstream secret."""
        raw = secrets.token_urlsafe(32)
        await self.pool.execute(
            """INSERT INTO cookie_core_proxy_grants(
                 token_hash,user_id,service_id,expires_at
               ) VALUES($1,$2,$3,$4)""",
            self._token_hash(raw),
            launch.user_id,
            UUID(launch.service_id),
            _now() + timedelta(seconds=ttl_seconds),
        )
        return raw

    async def proxy_grant(self, *, raw_grant: str, service_id: str) -> ConsumedLaunch:
        """Validates a proxy grant and loads cookies for its exact owner tuple."""
        service_uuid = UUID(service_id)
        async with self.pool.acquire() as conn:
            grant = await conn.fetchrow(
                """SELECT g.user_id,g.service_id,s.*
                   FROM cookie_core_proxy_grants g
                   JOIN cookie_core_services s ON s.id=g.service_id AND s.enabled=true
                   WHERE g.token_hash=$1 AND g.service_id=$2
                     AND g.revoked_at IS NULL AND g.expires_at > now()""",
                self._token_hash(raw_grant),
                service_uuid,
            )
            if not grant:
                raise ValueError("Proxy grant is invalid or expired")
            rows = await conn.fetch(
                """SELECT * FROM cookie_core_stored_cookies
                   WHERE user_id=$1 AND service_id=$2
                     AND revoked_at IS NULL
                     AND (expires_at IS NULL OR expires_at > now())""",
                grant["user_id"],
                service_uuid,
            )
        cookies = [
            {
                "name": row["name"],
                "value": self.vault.decrypt(
                    row["encrypted_value"],
                    row["nonce"],
                    grant["user_id"],
                    service_id,
                    row["name"],
                ),
                "domain": row["domain"],
                "path": row["path"],
                "secure": row["secure"],
                "httpOnly": row["http_only"],
                "sameSite": row["same_site"] or "Lax",
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
                **({"expires": row["expires_at"].timestamp()} if row["expires_at"] else {}),
            }
            for row in rows
        ]
        async with self.pool.acquire() as conn:
            local_storage = await self._load_local_storage_items(
                conn, grant["user_id"], service_id
            )
        return ConsumedLaunch(
            user_id=grant["user_id"],
            service_id=service_id,
            upstream_url=grant["upstream_url"],
            allowed_domains=tuple(grant["allowed_domains"]),
            allowed_paths=tuple(grant["allowed_paths"]),
            allowed_cookie_names=tuple(grant["allowed_cookie_names"]),
            cookies=cookies,
            local_storage_items=local_storage,
            proxy_hostname=grant.get("proxy_hostname"),
        )

    async def service_id_for_proxy_hostname(self, hostname: str) -> str | None:
        value = await self.pool.fetchval(
            """SELECT id FROM cookie_core_services
               WHERE lower(proxy_hostname)=$1 AND enabled=true""",
            hostname.lower().rstrip("."),
        )
        return str(value) if value else None

    async def capture_set_cookie(
        self, launch: ConsumedLaunch, raw_cookie: str, upstream_host: str
    ) -> str | None:
        """Stores an upstream Set-Cookie without ever forwarding it to the browser."""
        parsed = SimpleCookie()
        try:
            parsed.load(raw_cookie)
        except Exception:
            return None
        if len(parsed) != 1:
            return None
        name, morsel = next(iter(parsed.items()))
        expires_at = None
        if morsel["expires"]:
            try:
                expires_at = parsedate_to_datetime(morsel["expires"])
                if not expires_at.tzinfo:
                    expires_at = expires_at.replace(tzinfo=timezone.utc)
            except (TypeError, ValueError):
                expires_at = None
        domain = (morsel["domain"] or upstream_host).lower()
        path = morsel["path"] or "/"
        same_site = (morsel["samesite"] or "Lax").capitalize()
        if same_site not in {"Strict", "Lax", "None"}:
            same_site = "Lax"
        cookie = ImportedCookie(
            name=name,
            value=morsel.value,
            domain=domain,
            path=path,
            expires_at=expires_at,
            secure=bool(morsel["secure"]),
            http_only=bool(morsel["httponly"]),
            same_site=same_site,
        )
        policy = ServicePolicy(
            id=launch.service_id,
            name="runtime",
            upstream_url=launch.upstream_url,
            allowed_domains=launch.allowed_domains,
            allowed_paths=launch.allowed_paths,
            allowed_cookie_names=launch.allowed_cookie_names,
        )
        try:
            validate_cookie(cookie, policy, self.blocked_cookie_public_suffixes)
        except ValueError:
            return None
        expired = (
            morsel["max-age"].strip().startswith("-")
            or morsel["max-age"].strip() == "0"
            or (expires_at is not None and expires_at <= _now())
        )
        async with self.pool.acquire() as conn, conn.transaction():
            args = (
                launch.user_id,
                UUID(launch.service_id),
                name,
                domain,
                path,
            )
            if expired:
                await conn.execute(
                    """DELETE FROM cookie_core_stored_cookies
                       WHERE user_id=$1 AND service_id=$2
                         AND name=$3 AND domain=$4 AND path=$5""",
                    *args,
                )
            else:
                encrypted = self.vault.encrypt(
                    morsel.value, launch.user_id, launch.service_id, name
                )
                await conn.execute(
                    """INSERT INTO cookie_core_stored_cookies(
                         user_id,service_id,name,domain,path,
                         encrypted_value,nonce,expires_at,secure,http_only,same_site
                       ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
                       ON CONFLICT(user_id,service_id,name,domain,path)
                       DO UPDATE SET encrypted_value=excluded.encrypted_value,
                         nonce=excluded.nonce,expires_at=excluded.expires_at,
                         secure=excluded.secure,http_only=excluded.http_only,
                         same_site=excluded.same_site,revoked_at=NULL,updated_at=now()""",
                    *args,
                    encrypted.ciphertext,
                    encrypted.nonce,
                    expires_at,
                    cookie.secure,
                    cookie.http_only,
                    cookie.same_site,
                )
            await conn.execute(
                """INSERT INTO cookie_core_audit_logs(
                     actor_user_id,subject_user_id,service_id,action,details
                   ) VALUES($1,$1,$2,'cookies.rotate',$3::jsonb)""",
                launch.user_id,
                UUID(launch.service_id),
                '{"count":1}',
            )
        return name

    async def import_local_storage(
        self,
        *,
        actor_user_id: str,
        subject_user_id: str,
        service_id: str,
        raw_items: str,
    ) -> int:
        service_uuid = UUID(service_id)
        async with self.pool.acquire() as conn, conn.transaction():
            row = await conn.fetchrow(
                "SELECT * FROM cookie_core_services WHERE id=$1 AND enabled=true", service_uuid
            )
            if not row:
                raise ValueError("Service not found or disabled")
            items = parse_localstorage_import(raw_items)
            await conn.execute(
                """DELETE FROM cookie_core_stored_localstorage
                   WHERE user_id=$1 AND service_id=$2""",
                subject_user_id,
                service_uuid,
            )
            for item in items:
                encrypted = self.vault.encrypt(
                    item.value, subject_user_id, service_id, item.key
                )
                await conn.execute(
                    """INSERT INTO cookie_core_stored_localstorage(
                         user_id,service_id,item_key,encrypted_value,nonce
                       ) VALUES($1,$2,$3,$4,$5)
                       ON CONFLICT(user_id,service_id,item_key)
                       DO UPDATE SET encrypted_value=excluded.encrypted_value,
                         nonce=excluded.nonce,revoked_at=NULL,updated_at=now()""",
                    subject_user_id,
                    service_uuid,
                    item.key,
                    encrypted.ciphertext,
                    encrypted.nonce,
                )
            await conn.execute(
                """INSERT INTO cookie_core_audit_logs(
                     actor_user_id,subject_user_id,service_id,action,details
                   ) VALUES($1,$1,$2,'localstorage.import',$3::jsonb)""",
                actor_user_id,
                service_uuid,
                f'{{"count":{len(items)}}}',
            )
            return len(items)

    async def sync_local_storage(
        self,
        *,
        launch: ConsumedLaunch,
        upserts: dict[str, str] | None = None,
        deletes: list[str] | None = None,
    ) -> dict[str, str]:
        service_uuid = UUID(launch.service_id)
        async with self.pool.acquire() as conn, conn.transaction():
            if upserts:
                for key, value in upserts.items():
                    if not isinstance(key, str) or not key.strip() or len(key) > 500:
                        continue
                    if not isinstance(value, str):
                        continue
                    if len(value.encode()) > 512_000:
                        continue
                    if any(ord(c) < 32 and c not in "\t\n\r" for c in key):
                        continue
                    encrypted = self.vault.encrypt(
                        value, launch.user_id, launch.service_id, key
                    )
                    await conn.execute(
                        """INSERT INTO cookie_core_stored_localstorage(
                             user_id,service_id,item_key,encrypted_value,nonce
                           ) VALUES($1,$2,$3,$4,$5)
                           ON CONFLICT(user_id,service_id,item_key)
                           DO UPDATE SET encrypted_value=excluded.encrypted_value,
                             nonce=excluded.nonce,revoked_at=NULL,updated_at=now()""",
                        launch.user_id,
                        service_uuid,
                        key.strip(),
                        encrypted.ciphertext,
                        encrypted.nonce,
                    )
            if deletes:
                for key in deletes:
                    if not isinstance(key, str) or not key.strip():
                        continue
                    await conn.execute(
                        """UPDATE cookie_core_stored_localstorage
                           SET revoked_at=now(),updated_at=now()
                           WHERE user_id=$1 AND service_id=$2 AND item_key=$3
                             AND revoked_at IS NULL""",
                        launch.user_id,
                        service_uuid,
                        key.strip(),
                    )
            return await self._load_local_storage_items(
                conn, launch.user_id, launch.service_id
            )
