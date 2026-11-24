"""JWT authentication, RBAC and tenant scoping (PDR 6.3, phase 4)."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import jwt

ROLE_LEVEL = {"viewer": 0, "analyst": 1, "admin": 2}


class AuthError(Exception):
    pass


@dataclass
class Principal:
    tenant_id: int
    username: str
    role: str

    def has_role(self, minimum: str) -> bool:
        return ROLE_LEVEL.get(self.role, -1) >= ROLE_LEVEL.get(minimum, 99)


def create_token(tenant_id: int, username: str, role: str, secret: str, minutes: int = 15) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "tenant_id": tenant_id,
        "role": role,
        "iat": now,
        "exp": now + timedelta(minutes=minutes),
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def decode_token(token: str, secret: str) -> Principal:
    try:
        claims = jwt.decode(token, secret, algorithms=["HS256"])
    except jwt.PyJWTError as exc:
        raise AuthError("invalid or expired token") from exc
    try:
        return Principal(int(claims["tenant_id"]), str(claims["sub"]), str(claims["role"]))
    except (KeyError, ValueError, TypeError) as exc:
        raise AuthError("malformed token claims") from exc


def authenticate(authorization: str | None, secret: str, defended: bool, db) -> Principal:
    """Baseline accepts anything (planted flaw); defended validates JWT."""
    if not defended:
        return Principal(1, "unauthenticated", "admin")
    if not authorization or not authorization.lower().startswith("bearer "):
        raise AuthError("missing bearer token")
    principal = decode_token(authorization.split(" ", 1)[1].strip(), secret)
    user = db.one(
        "SELECT id FROM users WHERE tenant_id = ? AND username = ? AND role = ?",
        (principal.tenant_id, principal.username, principal.role),
    )
    if user is None:
        raise AuthError("unknown user for tenant")
    return principal
