from __future__ import annotations

from datetime import UTC, datetime, timedelta
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

# ---- Auth primitives (minimal demo token, NOT production) ----
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

# A toy token system. In real life you'd use JWT (pyjwt/python-jose) + proper password hashing.
TOKEN_TTL_MIN = 30


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
    # OAuth2PasswordRequestForm gives you: form.username, form.password
    # Minimal check: accept one hardcoded user/password.
    if not (form.username == "tee" and form.password == "password"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Token is just a string encoding the username + expiry; 
    # do NOT do this in production
    expires_at = datetime.now(UTC) + timedelta(minutes=TOKEN_TTL_MIN)
    token = f"user:{form.username}|exp:{int(expires_at.timestamp())}"

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

    return username


@app.get("/users", response_model=list[UserOut])
def list_users(_username: Annotated[str, Depends(require_user)]) -> list[UserOut]:
    # _username is available if you want it; underscore says "intentionally unused".
    return [UserOut(**u) for u in FAKE_USERS]