from __future__ import annotations

import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


@dataclass(frozen=True)
class EncryptedValue:
    ciphertext: bytes
    nonce: bytes


class CookieVault:
    """AES-256-GCM vault with a different derived key per user and service."""

    def __init__(self, master_key: bytes):
        if len(master_key) < 32:
            raise ValueError("COOKIE_VAULT_KEY must contain at least 32 random bytes")
        self._master_key = master_key

    def _key(self, user_id: str, service_id: str) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=service_id.encode(),
            info=f"cookie-session-core:{user_id}:{service_id}".encode(),
        ).derive(self._master_key)

    def encrypt(self, value: str, user_id: str, service_id: str, name: str) -> EncryptedValue:
        nonce = secrets.token_bytes(12)
        aad = f"{user_id}:{service_id}:{name}".encode()
        ciphertext = AESGCM(self._key(user_id, service_id)).encrypt(
            nonce, value.encode(), aad
        )
        return EncryptedValue(ciphertext, nonce)

    def decrypt(
        self,
        ciphertext: bytes,
        nonce: bytes,
        user_id: str,
        service_id: str,
        name: str,
    ) -> str:
        aad = f"{user_id}:{service_id}:{name}".encode()
        return AESGCM(self._key(user_id, service_id)).decrypt(
            nonce, ciphertext, aad
        ).decode()
