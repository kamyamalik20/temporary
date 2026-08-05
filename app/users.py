"""
users.py — Task 5: User accounts + login

A deliberately small, dependency-free auth system:
    - Users are stored in data/users.json as {username: {salt, hash, role, created_at}}
    - Passwords are never stored in plaintext: PBKDF2-HMAC-SHA256, 200k
      iterations, per-user random salt (stdlib hashlib only, no extra deps).
    - Login issues an opaque random bearer token, held in-memory
      (TOKENS dict) with an expiry. Restarting the server invalidates all
      sessions — acceptable for an internal admin tool; swap for a real
      session store / JWT if this needs to survive restarts or scale to
      multiple server processes.
    - Two roles: "admin" (can execute delete/compress actions) and
      "viewer" (can view scans/plans but not execute them). Enforce role
      checks in AI_server.py via `require_role(...)`.

This module intentionally does NOT hash with plain SHA-256/MD5 (too fast,
brute-forceable) and does NOT roll its own crypto primitive — it uses
hashlib.pbkdf2_hmac, which is a standard, reviewed KDF.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from pathlib import Path
from typing import Optional

from fastapi import Header, HTTPException

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
USERS_FILE = DATA_DIR / "users.json"

PBKDF2_ITERATIONS = 200_000
TOKEN_TTL_SECONDS = 8 * 60 * 60  # 8 hour sessions
VALID_ROLES = {"admin", "viewer"}

# In-memory session store: token -> {"username": ..., "expires_at": ...}
TOKENS: dict[str, dict] = {}


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------
def _load_users() -> dict:
    if not USERS_FILE.exists():
        return {}
    with open(USERS_FILE, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}


def _save_users(users: dict) -> None:
    tmp = USERS_FILE.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(users, f, indent=2)
    tmp.replace(USERS_FILE)  # atomic on POSIX


def _hash_password(password: str, salt: bytes) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return dk.hex()


# ---------------------------------------------------------------------------
# User management
# ---------------------------------------------------------------------------
def create_user(username: str, password: str, role: str = "viewer") -> None:
    if not username or not username.strip():
        raise ValueError("username is required")
    if not password or len(password) < 8:
        raise ValueError("password must be at least 8 characters")
    if role not in VALID_ROLES:
        raise ValueError(f"role must be one of {sorted(VALID_ROLES)}")

    users = _load_users()
    if username in users:
        raise ValueError(f"user '{username}' already exists")

    salt = secrets.token_bytes(16)
    users[username] = {
        "salt": salt.hex(),
        "hash": _hash_password(password, salt),
        "role": role,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    _save_users(users)


def verify_user(username: str, password: str) -> Optional[dict]:
    """Return the user's record (without secrets) if the password is correct, else None."""
    users = _load_users()
    record = users.get(username)
    if not record:
        # Still run a hash to avoid trivially leaking "user exists" via timing.
        _hash_password(password, secrets.token_bytes(16))
        return None

    salt = bytes.fromhex(record["salt"])
    candidate = _hash_password(password, salt)
    if not secrets.compare_digest(candidate, record["hash"]):
        return None

    return {"username": username, "role": record["role"]}


def issue_token(username: str, role: str) -> str:
    token = secrets.token_urlsafe(32)
    TOKENS[token] = {"username": username, "role": role, "expires_at": time.time() + TOKEN_TTL_SECONDS}
    return token


def _get_session(token: str) -> Optional[dict]:
    session = TOKENS.get(token)
    if not session:
        return None
    if session["expires_at"] < time.time():
        TOKENS.pop(token, None)
        return None
    return session


# ---------------------------------------------------------------------------
# FastAPI dependencies
# ---------------------------------------------------------------------------
def get_current_user(authorization: str = Header(default="")) -> dict:
    """
    FastAPI dependency: expects `Authorization: Bearer <token>`.
    Raises 401 if missing/invalid/expired.
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = authorization[len("Bearer "):].strip()
    session = _get_session(token)
    if not session:
        raise HTTPException(status_code=401, detail="invalid or expired token")
    return session


def require_role(*allowed_roles: str):
    """
    FastAPI dependency factory: use as
        current_user: dict = Depends(require_role("admin"))
    to restrict an endpoint to specific roles.
    """
    from fastapi import Depends

    def checker(current_user: dict = Depends(get_current_user)):
        if current_user["role"] not in allowed_roles:
            raise HTTPException(
                status_code=403,
                detail=f"role '{current_user['role']}' is not permitted; requires one of {allowed_roles}",
            )
        return current_user

    return checker


def bootstrap_default_admin() -> None:
    """
    If no users exist yet, create a default admin so the system is usable
    on first run. Prints the generated password ONCE — change it
    immediately after first login. Safe to call on every startup; it's a
    no-op once any user exists.
    """
    users = _load_users()
    if users:
        return
    default_password = secrets.token_urlsafe(12)
    create_user("admin", default_password, role="admin")
    print("=" * 60)
    print(" No users existed — created a default admin account:")
    print(f"   username: admin")
    print(f"   password: {default_password}")
    print(" Log in and create a real account, then remove/rotate this one.")
    print("=" * 60)
