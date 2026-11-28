"""AES-256-GCM encryption for sensitive gateway artifacts at rest.

Scope (deliberately narrow): only stored secrets / sensitive audit payloads.
Guardrail decisions, reason codes and HTTP responses remain plaintext and are
never encrypted here. The key is read from the ``ENCRYPTION_KEY`` environment
variable as base64 of 32 random bytes; no key is stored in this repository.

Generate a development key with:

    python -c "import base64,os;print(base64.b64encode(os.urandom(32)).decode())"

Token format (base64): ``nonce (12 bytes) || GCM ciphertext + tag (16 bytes)``.
Associated data binds a token to its context so it cannot be replayed as a
different kind of artifact.
"""
from __future__ import annotations

import base64
import binascii
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_ENV_VAR = "ENCRYPTION_KEY"
KEY_BYTES = 32
NONCE_BYTES = 12
AUDIT_AAD = b"sentinelops:audit:v1"


class DecryptionTamperError(Exception):
    """Raised when ciphertext fails authentication or is malformed."""


def load_key(env_var: str = KEY_ENV_VAR) -> bytes:
    """Load and validate the 32-byte base64 key from the environment."""
    raw = os.environ.get(env_var, "").strip()
    if not raw:
        raise ValueError(
            f"{env_var} is not set; generate one with "
            'python -c "import base64,os;print(base64.b64encode(os.urandom(32)).decode())"'
        )
    try:
        key = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{env_var} must be base64-encoded") from exc
    if len(key) != KEY_BYTES:
        raise ValueError(f"{env_var} must decode to exactly {KEY_BYTES} bytes (got {len(key)})")
    return key


def key_is_configured(env_var: str = KEY_ENV_VAR) -> bool:
    """True when a valid key is available; never raises."""
    try:
        load_key(env_var)
    except ValueError:
        return False
    return True


def _validated_key(key: bytes | None, env_var: str) -> bytes:
    material = key if key is not None else load_key(env_var)
    if len(material) != KEY_BYTES:
        raise ValueError(f"encryption key must be exactly {KEY_BYTES} bytes")
    return material


def encrypt(
    plaintext: str | bytes,
    key: bytes | None = None,
    *,
    aad: bytes = AUDIT_AAD,
    env_var: str = KEY_ENV_VAR,
) -> str:
    """Encrypt data and return a base64 token containing nonce + ciphertext."""
    material = _validated_key(key, env_var)
    data = plaintext.encode("utf-8") if isinstance(plaintext, str) else bytes(plaintext)
    nonce = os.urandom(NONCE_BYTES)  # fresh nonce for every encryption
    token = nonce + AESGCM(material).encrypt(nonce, data, aad)
    return base64.b64encode(token).decode("ascii")


def decrypt(
    token: str | bytes,
    key: bytes | None = None,
    *,
    aad: bytes = AUDIT_AAD,
    env_var: str = KEY_ENV_VAR,
) -> bytes:
    """Decrypt and authenticate a token produced by :func:`encrypt`.

    Any modification of nonce, ciphertext, tag or AAD raises
    :class:`DecryptionTamperError` (GCM ``InvalidTag``).
    """
    material = _validated_key(key, env_var)
    try:
        raw = base64.b64decode(token, validate=True) if isinstance(token, str) else bytes(token)
    except (binascii.Error, ValueError) as exc:
        raise DecryptionTamperError("encrypted payload is not valid base64") from exc
    if len(raw) <= NONCE_BYTES:
        raise DecryptionTamperError("encrypted payload is too short")
    try:
        return AESGCM(material).decrypt(raw[:NONCE_BYTES], raw[NONCE_BYTES:], aad)
    except InvalidTag as exc:
        raise DecryptionTamperError("encrypted payload failed authentication") from exc


def decrypt_text(
    token: str | bytes,
    key: bytes | None = None,
    *,
    aad: bytes = AUDIT_AAD,
    env_var: str = KEY_ENV_VAR,
) -> str:
    """Decrypt a UTF-8 text token produced by :func:`encrypt`."""
    return decrypt(token, key, aad=aad, env_var=env_var).decode("utf-8")
