from __future__ import annotations

import hashlib
import hmac
import logging
from dataclasses import dataclass

import httpx
import jwt
from fastapi import Depends, Header, HTTPException, Request
from jwt import PyJWKClient
from jwt.exceptions import PyJWKClientConnectionError

from .config import Settings
from .redaction import install_redaction

logger = logging.getLogger("cookie_session_core.auth")
install_redaction(logger)


def _subject_fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:12]


@dataclass(frozen=True)
class AuthenticatedUser:
    id: str
    email: str | None
    claims: dict


class SupabaseJWTVerifier:
    """Verifies asymmetric tokens locally and legacy HS256 tokens with Supabase Auth."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.issuer = f"{str(settings.supabase_url).rstrip('/')}/auth/v1"
        self.jwks = PyJWKClient(
            f"{self.issuer}/.well-known/jwks.json",
            cache_keys=True,
            lifespan=600,
            timeout=float(settings.supabase_jwks_timeout_seconds),
        )

    async def verify(self, token: str) -> AuthenticatedUser:
        try:
            header = jwt.get_unverified_header(token)
            algorithm = header.get("alg")
            if algorithm in {"ES256", "RS256"}:
                key = await __import__("asyncio").to_thread(
                    self.jwks.get_signing_key_from_jwt, token
                )
                claims = jwt.decode(
                    token,
                    key.key,
                    algorithms=[algorithm],
                    audience=self.settings.supabase_jwt_audience,
                    issuer=self.issuer,
                    options={"require": ["exp", "sub", "iss"]},
                )
            elif algorithm == "HS256":
                claims = await self._verify_legacy_token(token)
            else:
                raise HTTPException(401, "Unsupported authentication token")
        except HTTPException:
            raise
        except PyJWKClientConnectionError as exc:
            raise HTTPException(503, "Authentication service is temporarily unavailable") from exc
        except (jwt.PyJWTError, httpx.HTTPError, KeyError, ValueError):
            raise HTTPException(401, "Invalid or expired authentication")
        subject = str(claims.get("sub") or claims.get("id") or "")
        if not subject:
            raise HTTPException(401, "Authentication has no user identifier")
        return AuthenticatedUser(
            id=subject,
            email=claims.get("email"),
            claims=claims,
        )

    async def _verify_legacy_token(self, token: str) -> dict:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(
                    f"{self.issuer}/user",
                    headers={
                        "apikey": self.settings.supabase_publishable_key,
                        "Authorization": f"Bearer {token}",
                    },
                )
        except httpx.HTTPError as exc:
            raise HTTPException(503, "Authentication service is temporarily unavailable") from exc
        if response.status_code == 429 or response.status_code >= 500:
            raise HTTPException(503, "Authentication service is temporarily unavailable")
        if response.status_code != 200:
            raise HTTPException(401, "Invalid or expired authentication")
        try:
            user = response.json()
            subject = str(user["id"])
        except (ValueError, KeyError, TypeError) as exc:
            raise HTTPException(503, "Authentication service returned an invalid response") from exc
        return {
            "sub": subject,
            "email": user.get("email"),
            "app_metadata": user.get("app_metadata") or {},
            "user_metadata": user.get("user_metadata") or {},
        }


async def current_user(request: Request, authorization: str | None = Header(default=None)):
    client_host = request.client.host if request.client else "unknown"
    request.app.state.rate_limiter.check(
        "auth", client_host, request.app.state.settings.auth_rate_limit_per_minute
    )
    scheme, separator, token = (authorization or "").partition(" ")
    if not separator or scheme.casefold() != "bearer" or not token.strip():
        logger.warning(
            "authentication_failed request_id=%s path=%s reason=missing_bearer",
            getattr(request.state, "request_id", "unknown"),
            request.url.path,
        )
        raise HTTPException(401, "Authentication required")
    try:
        user = await request.app.state.jwt_verifier.verify(
            token.strip()
        )
    except HTTPException as exc:
        logger.warning(
            "authentication_failed request_id=%s path=%s status=%s reason=%s",
            getattr(request.state, "request_id", "unknown"),
            request.url.path,
            exc.status_code,
            exc.detail,
        )
        raise
    request.state.user_fingerprint = _subject_fingerprint(user.id)
    return user


async def current_admin(
    request: Request,
    user: AuthenticatedUser = Depends(current_user),
    x_cookie_core_admin: str | None = Header(default=None),
):
    expected = request.app.state.settings.admin_proxy_secret
    if not x_cookie_core_admin or not hmac.compare_digest(
        x_cookie_core_admin.encode(), expected.encode()
    ):
        logger.warning(
            "authorization_failed request_id=%s path=%s user=%s reason=admin_secret",
            getattr(request.state, "request_id", "unknown"),
            request.url.path,
            _subject_fingerprint(user.id),
        )
        raise HTTPException(403, "Administrator permission required")
    return user
