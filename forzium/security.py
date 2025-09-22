# flake8: noqa
"""Security helpers including JWT, RBAC, and audit logging."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sqlite3
import time
from fnmatch import fnmatchcase
from typing import Any, Dict, Iterable, List, Protocol, Tuple, Union

from infrastructure.monitoring import record_metric

from .dependency import Request
from .responses import HTTPException

_revoked_tokens: set[str] = set()
# scope required on refresh tokens
REFRESH_SCOPE = "refresh"

DB_PATH = os.getenv("FORZIUM_RBAC_DB", "rbac.db")

# user permission cache: {user: [(perm, expires)]}
_perm_cache: Dict[str, List[Tuple[str, float | None]]] = {}
# global cache version for cross-instance invalidation
_cache_version: float = 0.0


class CacheVersionBackend(Protocol):
    """Backend storing the distributed cache version."""

    def get(self) -> float:
        """Return the current cache version."""

    def set(self, version: float) -> None:
        """Persist *version* as the new cache version."""


class SQLiteCacheBackend:
    """Default cache backend persisting version in SQLite."""

    def get(self) -> float:
        with _conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT version FROM cache_version WHERE id=1")
            row = cur.fetchone()
        return float(row[0]) if row else 0.0

    def set(self, version: float) -> None:
        with _conn() as conn:
            conn.execute(
                "UPDATE cache_version SET version=? WHERE id=1", (version,)
            )
            conn.commit()


class RedisCacheBackend:
    """Cache backend storing the version in Redis."""

    def __init__(
        self,
        url: str | None = None,
        client: Any | None = None,
        key: str = "forzium:cache_version",
    ) -> None:
        if client is None:
            try:  # pragma: no cover - import guarded to avoid hard dependency
                import redis  # type: ignore
            except ImportError as exc:  # pragma: no cover - redis not installed
                raise RuntimeError("redis package required for RedisCacheBackend") from exc
            self.client = redis.Redis.from_url(url or "redis://localhost:6379/0")
        else:
            self.client = client
        self.key = key

    def healthy(self) -> bool:
        """Return ``True`` if the Redis backend is reachable."""

        try:
            return bool(self.client.ping())
        except Exception:  # pragma: no cover - network failures
            return False

    def get(self) -> float:
        val = self.client.get(self.key)
        if not val:
            return 0.0
        try:
            return float(val)
        except (TypeError, ValueError):
            return 0.0

    def set(self, version: float) -> None:
        self.client.set(self.key, version)


_cache_backend: CacheVersionBackend = SQLiteCacheBackend()


def set_cache_backend(backend: CacheVersionBackend) -> None:
    """Set permission cache version *backend* and report its health."""

    global _cache_backend, _cache_version
    healthy = True
    if hasattr(backend, "healthy"):
        try:
            healthy = bool(getattr(backend, "healthy")())
        except Exception:  # pragma: no cover - defensive
            healthy = False
    record_metric("cache_backend_health", 1.0 if healthy else 0.0)
    if healthy:
        _cache_backend = backend
    else:
        _cache_backend = SQLiteCacheBackend()
    _cache_version = _cache_backend.get()


def _invalidate_cache(user: str | None = None) -> None:
    """Invalidate permission cache for *user* or all users."""

    if user is None:
        _perm_cache.clear()
    else:
        _perm_cache.pop(user, None)


def purge_expired_permissions() -> None:
    """Remove expired permission entries from the database."""

    with _conn() as conn:
        conn.execute(
            "DELETE FROM role_permissions WHERE expires IS NOT NULL AND expires<=?",
            (time.time(),),
        )
        conn.commit()


def _load_cache_version() -> float:
    return _cache_backend.get()


def _bump_cache_version() -> None:
    global _cache_version
    _cache_version = time.time()
    _cache_backend.set(_cache_version)


def _sync_cache_version() -> None:
    global _cache_version
    version = _cache_backend.get()
    if version != _cache_version:
        _cache_version = version
        _invalidate_cache()


def _user_permissions(user: str) -> List[str]:
    """Return cached permissions for *user* with lazy expiry purge."""

    purge_expired_permissions()
    _sync_cache_version()
    perms = _perm_cache.get(user)
    now = time.time()
    if perms is None:
        with _conn() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT rp.perm, rp.expires FROM user_roles ur
                JOIN role_permissions rp ON ur.role = rp.role
                WHERE ur.user=?
                """,
                (user,),
            )
            perms = [(p, e) for p, e in cur.fetchall()]
            _perm_cache[user] = perms

    fresh = [(p, e) for p, e in perms if e is None or e > now]
    if len(fresh) != len(perms):
        _perm_cache[user] = fresh
    return [p for p, _ in fresh]


def _conn() -> sqlite3.Connection:
    return sqlite3.connect(DB_PATH)


def init_db() -> None:
    with _conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "CREATE TABLE IF NOT EXISTS roles (name TEXT PRIMARY KEY)"
        )
        cur.execute(
            "CREATE TABLE IF NOT EXISTS user_roles (user TEXT, role TEXT)"
        )
        cur.execute(
            "CREATE TABLE IF NOT EXISTS role_permissions (role TEXT, perm TEXT, expires REAL)"
        )
        # add expires column if migrating from older schema
        cur.execute("PRAGMA table_info(role_permissions)")
        cols = {row[1] for row in cur.fetchall()}
        if "expires" not in cols:
            cur.execute("ALTER TABLE role_permissions ADD COLUMN expires REAL")
        cur.execute(
            "CREATE TABLE IF NOT EXISTS audit_log (token TEXT, action TEXT, ts REAL)"
        )
        cur.execute(
            "CREATE TABLE IF NOT EXISTS cache_version (id INTEGER PRIMARY KEY CHECK (id=1), version REAL)"
        )
        cur.execute(
            "INSERT OR IGNORE INTO cache_version VALUES (1, 0)"
        )
        conn.commit()


init_db()
_cache_version = _load_cache_version()


def log_event(subject: str, action: str) -> None:
    """Record *action* performed on *subject* with timestamp."""

    with _conn() as conn:
        conn.execute(
            "INSERT INTO audit_log VALUES (?, ?, ?)",
            (subject, action, time.time()),
        )
        conn.commit()


def log_token_event(token: str, action: str) -> None:
    """Compatibility wrapper for token-based audit events."""

    log_event(token, action)


def get_audit_log(subject: str | None = None) -> List[Dict[str, Any]]:
    """Return audit log entries filtered by *subject* if provided."""

    with _conn() as conn:
        cur = conn.cursor()
        if subject:
            cur.execute(
                "SELECT token, action, ts FROM audit_log WHERE token=? ORDER BY ts",
                (subject,),
            )
        else:
            cur.execute(
                "SELECT token, action, ts FROM audit_log ORDER BY ts",
            )
        rows = cur.fetchall()
    return [{"token": t, "action": a, "ts": ts} for t, a, ts in rows]


PermissionSpec = Union[str, Tuple[str, float]]


def define_role(name: str, permissions: Iterable[PermissionSpec]) -> None:
    """Register role *name* with iterable *permissions*.

    Each permission may be a plain string or a ``(permission, expires)`` tuple
    where ``expires`` is a UNIX timestamp. ``None`` indicates no expiry.
    """

    with _conn() as conn:
        conn.execute("INSERT INTO roles VALUES (?)", (name,))
        rows = []
        for item in permissions:
            if isinstance(item, tuple):
                perm, exp = item
            else:
                perm, exp = item, None
            rows.append((name, perm, exp))
        conn.executemany(
            "INSERT INTO role_permissions VALUES (?, ?, ?)",
            rows,
        )
        conn.commit()
    log_event(name, "role_defined")
    _invalidate_cache()
    _bump_cache_version()


def assign_role(user: str, role: str) -> None:
    """Assign existing *role* to *user*."""

    with _conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM roles WHERE name=?", (role,))
        if not cur.fetchone():
            raise KeyError(role)
        cur.execute(
            "INSERT OR IGNORE INTO user_roles VALUES (?, ?)",
            (user, role),
        )
        conn.commit()
    log_event(user, f"role_assigned:{role}")
    _invalidate_cache(user)
    _bump_cache_version()


def check_permission(user: str, permission: str) -> bool:
    """Return ``True`` if *user* possesses *permission*.

    Hierarchical permissions are supported using ``*`` wildcards and entries may
    expire when an ``expires`` timestamp is set.
    """

    perms = _user_permissions(user)
    allowed = any(fnmatchcase(permission, p) for p in perms)
    log_event(user, f"perm:{permission}:{'granted' if allowed else 'denied'}")
    return allowed


def authorize_permissions(
    user: str, permissions: Iterable[str], mode: str = "all"
) -> bool:
    """Return ``True`` if *user* satisfies permission *mode*.

    Parameters
    ----------
    user:
        User identifier.
    permissions:
        Iterable of required permission strings.
    mode:
        ``"all"`` requires every permission. ``"any"`` allows access when at
        least one permission is present.
    """

    needed = set(permissions)
    if not needed:
        return True
    user_perms = _user_permissions(user)

    def has(req: str) -> bool:
        return any(fnmatchcase(req, p) for p in user_perms)

    if mode == "any":
        allowed = any(has(req) for req in needed)
    else:
        allowed = all(has(req) for req in needed)
    log_event(
        user,
        f"perm:{','.join(sorted(needed))}:{'granted' if allowed else 'denied'}",
    )
    return allowed


def list_roles() -> List[str]:
    """Return all defined role names."""

    with _conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT name FROM roles")
        return [r[0] for r in cur.fetchall()]


def list_user_roles(user: str) -> List[str]:
    """Return roles assigned to *user*."""

    with _conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT DISTINCT role FROM user_roles WHERE user=?",
            (user,),
        )
        return [r[0] for r in cur.fetchall()]


def remove_role(user: str, role: str) -> None:
    """Remove *role* assignment from *user*."""

    with _conn() as conn:
        conn.execute(
            "DELETE FROM user_roles WHERE user=? AND role=?",
            (user, role),
        )
        conn.commit()
    log_event(user, f"role_removed:{role}")
    _invalidate_cache(user)
    _bump_cache_version()


def revoke_permission(role: str, permission: str) -> None:
    """Remove *permission* from *role*."""

    with _conn() as conn:
        conn.execute(
            "DELETE FROM role_permissions WHERE role=? AND perm=?",
            (role, permission),
        )
        conn.commit()
    log_event(role, f"perm_revoked:{permission}")
    _invalidate_cache()
    _bump_cache_version()


def delete_role(name: str) -> None:
    """Delete role *name* and its assignments."""

    with _conn() as conn:
        conn.execute("DELETE FROM roles WHERE name=?", (name,))
        conn.execute("DELETE FROM role_permissions WHERE role=?", (name,))
        conn.execute("DELETE FROM user_roles WHERE role=?", (name,))
        conn.commit()
    log_event(name, "role_deleted")
    _invalidate_cache()
    _bump_cache_version()


def create_jwt(payload: Dict[str, Any], secret: str) -> str:
    """Encode *payload* as a JWT using HS256."""

    header = {"alg": "HS256", "typ": "JWT"}

    def b64(obj: Dict[str, Any]) -> str:
        data = json.dumps(obj, separators=(",", ":"))
        return base64.urlsafe_b64encode(data.encode()).decode().rstrip("=")

    signing_input = f"{b64(header)}.{b64(payload)}".encode()
    signature = hmac.new(
        secret.encode(),
        signing_input,
        hashlib.sha256,
    ).digest()
    sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")
    token = f"{signing_input.decode()}.{sig_b64}"
    log_token_event(token, "created")
    return token


def decode_jwt(token: str, secret: str) -> Dict[str, Any] | None:
    """Decode *token* and return payload if valid and not revoked."""

    if token in _revoked_tokens:
        return None
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
        signing_input = f"{header_b64}.{payload_b64}".encode()
        expected = hmac.new(
            secret.encode(),
            signing_input,
            hashlib.sha256,
        ).digest()
        signature = base64.urlsafe_b64decode(sig_b64 + "==")
        if not hmac.compare_digest(expected, signature):
            return None
        payload_json = base64.urlsafe_b64decode(payload_b64 + "==")
        return json.loads(payload_json)
    except Exception:
        return None


def authorize_scopes(token: str, secret: str, required: Iterable[str]) -> bool:
    """Return True if *token* carries all *required* scopes."""

    payload = decode_jwt(token, secret)
    if not isinstance(payload, dict):
        return False
    token_scopes = payload.get("scopes", [])
    return all(scope in token_scopes for scope in required)


def refresh_jwt(
    refresh_token: str, access_secret: str, refresh_secret: str
) -> str | None:
    """Generate a new access token using *refresh_token*."""

    payload = decode_jwt(refresh_token, refresh_secret)
    if not isinstance(payload, dict) or REFRESH_SCOPE not in payload.get("scopes", []):
        return None
    new_token = create_jwt(payload, access_secret)
    log_token_event(new_token, "refreshed")
    return new_token


def refresh_and_rotate(
    refresh_token: str, access_secret: str, refresh_secret: str
) -> tuple[str, str] | None:
    """Return new access and refresh tokens, revoking the old refresh token."""

    payload = decode_jwt(refresh_token, refresh_secret)
    if not isinstance(payload, dict) or REFRESH_SCOPE not in payload.get("scopes", []):
        return None
    revoke_token(refresh_token)
    payload = dict(payload)
    payload["iat"] = time.time()
    new_refresh = create_jwt(payload, refresh_secret)
    log_token_event(new_refresh, "rotated")
    new_access = create_jwt(payload, access_secret)
    log_token_event(new_access, "refreshed")
    return new_access, new_refresh


API_KEYS = {"secret"}


def _normalize_api_key(raw_value: Any) -> str | None:
    """Return the first non-empty API key candidate from *raw_value*.

    ``raw_value`` may be a string, a sequence of potential values, or ``None``.
    The function iterates the sequence (if provided) and returns the first
    truthy element coerced to ``str``. Empty strings and ``None`` entries are
    skipped. If no suitable value is found ``None`` is returned.
    """

    if raw_value is None:
        return None

    if isinstance(raw_value, (list, tuple)):
        for candidate in raw_value:
            if not candidate:
                continue
            if isinstance(candidate, str):
                return candidate
            return str(candidate)
        return None

    if isinstance(raw_value, str):
        return raw_value or None

    return str(raw_value) if raw_value else None


def api_key_query(request: Request) -> str:
    """Validate ``api_key`` query parameter and return its value.

    Raises :class:`HTTPException` with status 401 if the key is missing or
    invalid.
    """

    key = _normalize_api_key(request.query_params.get("api_key"))
    if not key or key not in API_KEYS:
        raise HTTPException(401, "Invalid API key")
    return key



def revoke_token(token: str) -> None:
    """Add *token* to the revocation set."""

    _revoked_tokens.add(token)
    log_token_event(token, "revoked")


def is_token_revoked(token: str) -> bool:
    """Return True if *token* has been revoked."""

    return token in _revoked_tokens


def rotate_jwt(token: str, old_secret: str, new_secret: str) -> str | None:
    """Re-sign *token* with *new_secret* and revoke the old one."""

    payload = decode_jwt(token, old_secret)
    if not isinstance(payload, dict):
        return None
    revoke_token(token)
    new_token = create_jwt(payload, new_secret)
    log_token_event(new_token, "rotated")
    return new_token


def hash_password(password: str, salt: bytes | None = None) -> str:
    """Hash *password* using PBKDF2-HMAC-SHA256."""

    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return base64.urlsafe_b64encode(salt + digest).decode()


def verify_password(password: str, hashed: str) -> bool:
    """Return True if *password* matches *hashed*."""

    try:
        data = base64.urlsafe_b64decode(hashed.encode())
        salt, digest = data[:16], data[16:]
        check = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
        return hmac.compare_digest(digest, check)
    except Exception:
        return False


__all__ = [
    "assign_role",
    "authorize_scopes",
    "authorize_permissions",
    "check_permission",
    "create_jwt",
    "decode_jwt",
    "define_role",
    "delete_role",
    "revoke_permission",
    "get_audit_log",
    "hash_password",
    "log_event",
    "log_token_event",
    "list_roles",
    "list_user_roles",
    "refresh_jwt",
    "refresh_and_rotate",
    "revoke_token",
    "is_token_revoked",
    "remove_role",
    "rotate_jwt",
    "verify_password",
    "REFRESH_SCOPE",
]
