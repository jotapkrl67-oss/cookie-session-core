from __future__ import annotations

import hmac
from dataclasses import dataclass

import httpx
import jwt
from fastapi import Depends, Header, HTTPException, Request
from jwt import PyJWKClient

from .config import Settings


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
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(
                f"{self.issuer}/user",
                headers={
                    "apikey": self.settings.supabase_publishable_key,
                    "Authorization": f"Bearer {token}",
                },
            )
        if response.status_code != 200:
            raise HTTPException(401, "Invalid or expired authentication")
        user = response.json()
        return {
            "sub": user["id"],
            "email": user.get("email"),
            "app_metadata": user.get("app_metadata") or {},
            "user_metadata": user.get("user_metadata") or {},
        }


async def current_user(request: Request, authorization: str | None = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Authentication required")
    return await request.app.state.jwt_verifier.verify(
        authorization.removeprefix("Bearer ").strip()
    )


async def current_admin(
    request: Request,
    user: AuthenticatedUser = Depends(current_user),
    x_cookie_core_admin: str | None = Header(default=None),
):
    expected = request.app.state.settings.admin_proxy_secret
    if not x_cookie_core_admin or not hmac.compare_digest(
        x_cookie_core_admin.encode(), expected.encode()
    ):
        raise HTTPException(403, "Administrator permission required")
    return user
