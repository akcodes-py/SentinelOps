"""Gateway security helpers (AES-256-GCM encryption for sensitive stored artifacts)."""
from __future__ import annotations

from .encryption import (
    AUDIT_AAD,
    KEY_ENV_VAR,
    DecryptionTamperError,
    decrypt,
    decrypt_text,
    encrypt,
    key_is_configured,
    load_key,
)

__all__ = [
    "AUDIT_AAD",
    "KEY_ENV_VAR",
    "DecryptionTamperError",
    "decrypt",
    "decrypt_text",
    "encrypt",
    "key_is_configured",
    "load_key",
]
