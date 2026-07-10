from datetime import datetime, timedelta, timezone
from functools import wraps

import bcrypt
import jwt
from flask import g, jsonify, request

from app.config import Config

# bcrypt silently ignores bytes beyond 72; truncate explicitly so behavior is
# consistent instead of depending on that implementation detail.
_BCRYPT_MAX_BYTES = 72


def hash_password(password: str) -> str:
    truncated = password.encode("utf-8")[:_BCRYPT_MAX_BYTES]
    return bcrypt.hashpw(truncated, bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    truncated = password.encode("utf-8")[:_BCRYPT_MAX_BYTES]
    return bcrypt.checkpw(truncated, password_hash.encode("utf-8"))


def create_token(user_id: int, role: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "role": role,
        "iat": now,
        "exp": now + timedelta(minutes=Config.JWT_EXP_MINUTES),
    }
    return jwt.encode(payload, Config.JWT_SECRET_KEY, algorithm="HS256")


def decode_token(token: str) -> dict:
    return jwt.decode(token, Config.JWT_SECRET_KEY, algorithms=["HS256"])


def _get_bearer_token():
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    return header.split(" ", 1)[1].strip()


def require_role(*roles):
    """Require a valid JWT bearer token; optionally restrict to specific roles.

    Usage: @require_role() for any authenticated user, @require_role("admin") to
    restrict to admins. Sets g.user_id and g.user_role on success.
    """

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            token = _get_bearer_token()
            if not token:
                return jsonify({"error": "Missing or invalid Authorization header"}), 401
            try:
                payload = decode_token(token)
            except jwt.ExpiredSignatureError:
                return jsonify({"error": "Token expired"}), 401
            except jwt.InvalidTokenError:
                return jsonify({"error": "Invalid token"}), 401

            if roles and payload.get("role") not in roles:
                return jsonify({"error": "Insufficient permissions"}), 403

            g.user_id = int(payload["sub"])
            g.user_role = payload.get("role")
            return fn(*args, **kwargs)

        return wrapper

    return decorator
