"""Password hashing, session tokens, CSRF and API-token encryption."""
import secrets
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken

from .config import get_settings

_ph = PasswordHasher()


def hash_password(password: str) -> str:
    return _ph.hash(password)


_DUMMY_HASH = _ph.hash(secrets.token_urlsafe(16))


def burn_password_check(password: str) -> None:
    """Same Argon2 cost as a real check, so unknown usernames are not distinguishable by response time."""
    verify_password(password, _DUMMY_HASH)


def verify_password(password: str, hashed: str) -> bool:
    try:
        return _ph.verify(hashed, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def validate_password_strength(password: str) -> None:
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters")


def create_session_token(user_id: int, role: str, version: int = 0) -> tuple[str, str]:
    """Returns (jwt, csrf_token). The CSRF token is bound into the JWT (double-submit); `ver` ties the token to the
    user's session_version so it can be revoked server-side."""
    s = get_settings()
    csrf = secrets.token_urlsafe(24)
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {"sub": str(user_id), "role": role, "csrf": csrf, "ver": version, "iat": now,
         "exp": now + timedelta(minutes=s.session_ttl_minutes)},
        s.secret_key,
        algorithm="HS256",
    )
    return token, csrf


def decode_session_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, get_settings().secret_key, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None


class TokenCipher:
    """Encrypts FortiGate API tokens with a key supplied outside the database."""

    def __init__(self, key: str | None = None):
        key = key or get_settings().token_encryption_key
        if not key:
            raise RuntimeError("TOKEN_ENCRYPTION_KEY is not configured")
        self._f = Fernet(key.encode())

    def encrypt(self, plaintext: str) -> str:
        return self._f.encrypt(plaintext.encode()).decode()

    def decrypt(self, ciphertext: str) -> str:
        try:
            return self._f.decrypt(ciphertext.encode()).decode()
        except InvalidToken as e:
            raise RuntimeError("Unable to decrypt stored API token (wrong TOKEN_ENCRYPTION_KEY?)") from e
