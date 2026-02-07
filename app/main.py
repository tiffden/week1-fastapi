from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import os
import secrets
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel

# ------------------------------------
# •	/health is public
# •	/auth/token issues a bearer token using the standard OAuth2 password flow (form fields)
# •	/users requires Authorization: Bearer <token>
#
# OpenAPI docs auto-generate from the type hints and FastAPI routing
# ------------------------------------

# ------------------------------------
# bash> uvicorn main:app --reload --port 8000
#
#   main -> main.py
#   app -> ASGI application object inside the file
#   --reload  (for development only, not production)
#       starts a watcher process to detect VS Code changes, terminates/restarts server
#       Because the process restarts:
# 	    •	Global variables are re-initialized
# 	    •	In-memory caches are wiped
# 	    •	Open connections are closed
# 	    •	Background tasks restart
# ------------------------------------

# ------------------------------------
# health:  curl -s http://127.0.0.1:8000/health
# token:   curl -s -X POST http://127.0.0.1:8000/auth/token \
#               -H "Content-Type: application/x-www-form-urlencoded" \
#               -d "username=tee&password=password"
# /users (authorized):   TOKEN="paste_token_here"
#                        curl -s http://127.0.0.1:8000/users -H "Authorization: Bearer $TOKEN"
# /users (unauthorized): curl -i http://127.0.0.1:8000/users (should return 401)
# ------------------------------------

app = FastAPI(title="Week1 Minimal FastAPI")

# ---- Fake "database" / identity store ----
FAKE_USERS = [
    {"id": 1, "email": "tee@example.com"},
    {"id": 2, "email": "d-man@example.com"},
]

# ---- Auth primitives (minimal demo token, improved for clarity) ----
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

# A toy token system. In real life you'd use JWT (pyjwt/python-jose) + proper password hashing.
TOKEN_TTL_MIN = 30
# In production this should be a long, random secret stored in env/secret manager.
# Keeping a default only so the demo runs without extra setup.
TOKEN_SIGNING_SECRET = os.getenv("TOKEN_SIGNING_SECRET", "dev-only-secret-change-me")


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: datetime


class UserOut(BaseModel):
    id: int
    email: str

# Example of Endpoint and Handler
@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/auth/token", response_model=Token)
def issue_token(form: Annotated[OAuth2PasswordRequestForm, Depends()]) -> Token:
    # ELI5 flow:
    # 1) Client sends an HTTP POST with a form body (not JSON).
    # 2) FastAPI sees Depends() + OAuth2PasswordRequestForm and parses the form.
    # 3) It creates a "form" object with attributes like .username and .password.
    # 4) Only then does it call this function and hands you that "form" object.
    #
    # Example curl (what the client sends):
    # curl -s -X POST http://127.0.0.1:8000/auth/token \
    #   -H "Content-Type: application/x-www-form-urlencoded" \
    #   -d "username=tee&password=password"
    #
    # Minimal check: accept one hardcoded user/password.
    # Use constant-time compare to avoid timing attacks on secrets.
    if not (
        secrets.compare_digest(form.username, "tee")
        and secrets.compare_digest(form.password, "password")
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Token is a string encoding the username + expiry (still a toy).
    # We add a simple HMAC signature for integrity so the client can't
    # forge or extend the expiry without knowing the secret.
    expires_at = datetime.now(UTC) + timedelta(minutes=TOKEN_TTL_MIN)
    exp_ts = int(expires_at.timestamp())
    token_core = f"user:{form.username}|exp:{exp_ts}"
    sig = hmac.new(
        TOKEN_SIGNING_SECRET.encode("utf-8"),
        token_core.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    token = f"{token_core}|sig:{sig}"

    return Token(access_token=token, expires_at=expires_at)


def require_user(token: Annotated[str, Depends(oauth2_scheme)]) -> str:
    """
    Dependency that validates the bearer token.
    Returns the username if valid.
    """
    try:
        parts = token.split("|")
        user_part = parts[0]  # "user:tee"
        exp_part = parts[1]   # "exp:..."
        username = user_part.split(":", 1)[1]
        exp_ts = int(exp_part.split(":", 1)[1])
        sig_part = parts[2] if len(parts) > 2 else None
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e

    if datetime.now(UTC).timestamp() > exp_ts:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # If a signature is present, validate integrity.
    if sig_part is not None:
        sig = sig_part.split(":", 1)[1]
        token_core = f"user:{username}|exp:{exp_ts}"
        expected = hmac.new(
            TOKEN_SIGNING_SECRET.encode("utf-8"),
            token_core.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not secrets.compare_digest(sig, expected):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token signature",
                headers={"WWW-Authenticate": "Bearer"},
            )

    return username


@app.get("/users", response_model=list[UserOut])
def list_users(_username: Annotated[str, Depends(require_user)]) -> list[UserOut]:
    # ELI5 flow:
    # 1) Client calls GET /users with an Authorization header:
    #    curl -s http://127.0.0.1:8000/users -H "Authorization: Bearer <token>"
    # 2) FastAPI sees Depends(require_user) and pauses this function.
    # 3) It calls require_user(token) first, passing the bearer token it extracted.
    # 4) If the token is valid, require_user returns the username.
    # 5) Only then does FastAPI call this function (list_users).
    #
    # If the token is missing/invalid, require_user raises HTTPException(401)
    # and this function never runs.
    #
    # _username is available if you want it; underscore says "intentionally unused".
    # You would use it like:  if user is in an Admin list then return full list,
    # else just let the caller see themself in the list
    return [UserOut(**u) for u in FAKE_USERS]
