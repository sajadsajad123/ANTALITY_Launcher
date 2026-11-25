
import os
import secrets
import hashlib
import hmac
from pathlib import Path
from datetime import datetime, timezone, timedelta

import psycopg
from psycopg.rows import dict_row
from psycopg.errors import UniqueViolation

from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field


# ==========================================
# CONFIG
# ==========================================

BASE_DIR = Path(__file__).resolve().parent
ENV_FILE = BASE_DIR / ".env"


def load_env():
    if not ENV_FILE.exists():
        return

    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()

        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        value = value.strip().strip('"').strip("'")

        os.environ.setdefault(key.strip(), value)


load_env()

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL is missing. Check your .env file."
    )


app = FastAPI(
    title="ANTALITY API",
    description="ANTALITY Launcher Online Backend",
    version="2.0.0"
)

security = HTTPBearer()


# ==========================================
# DATABASE
# ==========================================

def get_db():
    return psycopg.connect(
        DATABASE_URL,
        row_factory=dict_row,
        connect_timeout=15
    )


def init_database():
    with get_db() as conn:

        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id BIGSERIAL PRIMARY KEY,
                username VARCHAR(24) NOT NULL,
                password_hash BYTEA NOT NULL,
                password_salt BYTEA NOT NULL,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                last_seen TIMESTAMPTZ DEFAULT NOW()
            )
        """)

        conn.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS
            users_username_lower_idx
            ON users (LOWER(username))
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL REFERENCES users(id)
                    ON DELETE CASCADE,
                token TEXT NOT NULL UNIQUE,
                created_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS friend_requests (
                id BIGSERIAL PRIMARY KEY,
                sender_id BIGINT NOT NULL REFERENCES users(id)
                    ON DELETE CASCADE,
                receiver_id BIGINT NOT NULL REFERENCES users(id)
                    ON DELETE CASCADE,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE(sender_id, receiver_id),
                CHECK(sender_id <> receiver_id)
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS friendships (
                user_id BIGINT NOT NULL REFERENCES users(id)
                    ON DELETE CASCADE,
                friend_id BIGINT NOT NULL REFERENCES users(id)
                    ON DELETE CASCADE,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                PRIMARY KEY(user_id, friend_id),
                CHECK(user_id <> friend_id)
            )
        """)

    print("ANTALITY database initialized successfully.")


@app.on_event("startup")
def startup():
    init_database()


# ==========================================
# PASSWORD SECURITY
# ==========================================

def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_bytes(32)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        310000
    )

    return password_hash, salt


# ==========================================
# REQUEST MODELS
# ==========================================

class RegisterModel(BaseModel):
    username: str = Field(min_length=3, max_length=24)
    password: str = Field(min_length=8, max_length=128)


class LoginModel(BaseModel):
    username: str
    password: str


# ==========================================
# AUTHENTICATION
# ==========================================

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    token = credentials.credentials

    with get_db() as conn:

        user = conn.execute("""
            SELECT users.id, users.username
            FROM sessions
            JOIN users ON users.id = sessions.user_id
            WHERE sessions.token = %s
        """, (token,)).fetchone()

        if not user:
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired session"
            )

        conn.execute("""
            UPDATE users
            SET last_seen = NOW()
            WHERE id = %s
        """, (user["id"],))

    return user


# ==========================================
# HOME
# ==========================================

@app.get("/")
def home():
    return {
        "name": "ANTALITY API",
        "status": "ONLINE",
        "database": "Neon PostgreSQL",
        "version": "2.0.0"
    }


# ==========================================
# REGISTER
# ==========================================

@app.post("/register")
def register(data: RegisterModel):

    username = data.username.strip()

    if not username:
        raise HTTPException(400, "Invalid username")

    if not all(c.isalnum() or c == "_" for c in username):
        raise HTTPException(
            400,
            "Username can only contain letters, numbers and underscores"
        )

    password_hash, salt = hash_password(data.password)
    token = secrets.token_urlsafe(32)

    try:
        with get_db() as conn:

            user = conn.execute("""
                INSERT INTO users (
                    username,
                    password_hash,
                    password_salt
                )
                VALUES (%s, %s, %s)
                RETURNING id, username
            """, (
                username,
                password_hash,
                salt
            )).fetchone()

            conn.execute("""
                INSERT INTO sessions (user_id, token)
                VALUES (%s, %s)
            """, (user["id"], token))

    except UniqueViolation:
        raise HTTPException(
            status_code=409,
            detail="Username already exists"
        )

    return {
        "message": "Account created successfully",
        "user_id": user["id"],
        "username": user["username"],
        "token": token
    }


# ==========================================
# LOGIN
# ==========================================

@app.post("/login")
def login(data: LoginModel):

    with get_db() as conn:

        user = conn.execute("""
            SELECT *
            FROM users
            WHERE LOWER(username) = LOWER(%s)
        """, (data.username.strip(),)).fetchone()

        if not user:
            raise HTTPException(
                status_code=401,
                detail="Incorrect username or password"
            )

        password_hash, _ = hash_password(
            data.password,
            user["password_salt"]
        )

        if not hmac.compare_digest(
            password_hash,
            user["password_hash"]
        ):
            raise HTTPException(
                status_code=401,
                detail="Incorrect username or password"
            )

        token = secrets.token_urlsafe(32)

        conn.execute("""
            INSERT INTO sessions (user_id, token)
            VALUES (%s, %s)
        """, (user["id"], token))

        conn.execute("""
            UPDATE users
            SET last_seen = NOW()
            WHERE id = %s
        """, (user["id"],))

    return {
        "message": "Login successful",
        "user_id": user["id"],
        "username": user["username"],
        "token": token
    }


# ==========================================
# LOGOUT
# ==========================================

@app.post("/logout")
def logout(user=Depends(get_current_user),
           credentials: HTTPAuthorizationCredentials = Depends(security)):

    with get_db() as conn:
        conn.execute("""
            DELETE FROM sessions
            WHERE token = %s
        """, (credentials.credentials,))

    return {"message": "Logged out successfully"}


# ==========================================
# CURRENT USER
# ==========================================

@app.get("/me")
def me(user=Depends(get_current_user)):
    return user


# ==========================================
# SEARCH USERS
# ==========================================

@app.get("/users/search")
def search_users(
    q: str,
    user=Depends(get_current_user)
):

    q = q.strip()

    if len(q) < 2:
        return []

    with get_db() as conn:

        results = conn.execute("""
            SELECT id, username
            FROM users
            WHERE LOWER(username) LIKE LOWER(%s)
              AND id <> %s
              AND NOT EXISTS (
                  SELECT 1
                  FROM friendships f
                  WHERE f.user_id = %s
                    AND f.friend_id = users.id
              )
            ORDER BY username
            LIMIT 20
        """, (
            f"%{q}%",
            user["id"],
            user["id"]
        )).fetchall()

    return results


# ==========================================
# SEND FRIEND REQUEST
# ==========================================

@app.post("/friends/request/{target_id}")
def send_friend_request(
    target_id: int,
    user=Depends(get_current_user)
):

    if target_id == user["id"]:
        raise HTTPException(400, "Cannot add yourself")

    with get_db() as conn:

        target = conn.execute("""
            SELECT id FROM users WHERE id = %s
        """, (target_id,)).fetchone()

        if not target:
            raise HTTPException(404, "User not found")

        existing = conn.execute("""
            SELECT 1 FROM friendships
            WHERE user_id = %s AND friend_id = %s
        """, (user["id"], target_id)).fetchone()

        if existing:
            raise HTTPException(409, "Already friends")

        existing_request = conn.execute("""
            SELECT 1 FROM friend_requests
            WHERE
                (sender_id = %s AND receiver_id = %s)
                OR
                (sender_id = %s AND receiver_id = %s)
        """, (
            user["id"],
            target_id,
            target_id,
            user["id"]
        )).fetchone()

        if existing_request:
            raise HTTPException(409, "Friend request already exists")

        conn.execute("""
            INSERT INTO friend_requests (sender_id, receiver_id)
            VALUES (%s, %s)
        """, (user["id"], target_id))

    return {"message": "Friend request sent"}


# ==========================================
# INCOMING FRIEND REQUESTS
# ==========================================

@app.get("/friends/requests")
def get_friend_requests(user=Depends(get_current_user)):

    with get_db() as conn:

        requests = conn.execute("""
            SELECT
                fr.id AS request_id,
                u.id AS user_id,
                u.username
            FROM friend_requests fr
            JOIN users u ON u.id = fr.sender_id
            WHERE fr.receiver_id = %s
            ORDER BY fr.created_at DESC
        """, (user["id"],)).fetchall()

    return requests


# ==========================================
# ACCEPT FRIEND REQUEST
# ==========================================

@app.post("/friends/requests/{request_id}/accept")
def accept_request(
    request_id: int,
    user=Depends(get_current_user)
):

    with get_db() as conn:

        request = conn.execute("""
            SELECT *
            FROM friend_requests
            WHERE id = %s AND receiver_id = %s
        """, (request_id, user["id"])).fetchone()

        if not request:
            raise HTTPException(404, "Friend request not found")

        sender_id = request["sender_id"]
        receiver_id = user["id"]

        conn.execute("""
            INSERT INTO friendships (user_id, friend_id)
            VALUES (%s, %s), (%s, %s)
            ON CONFLICT DO NOTHING
        """, (
            sender_id, receiver_id,
            receiver_id, sender_id
        ))

        conn.execute("""
            DELETE FROM friend_requests
            WHERE id = %s
        """, (request_id,))

    return {"message": "Friend request accepted"}


# ==========================================
# DECLINE FRIEND REQUEST
# ==========================================

@app.post("/friends/requests/{request_id}/decline")
def decline_request(
    request_id: int,
    user=Depends(get_current_user)
):

    with get_db() as conn:

        result = conn.execute("""
            DELETE FROM friend_requests
            WHERE id = %s AND receiver_id = %s
            RETURNING id
        """, (request_id, user["id"])).fetchone()

        if not result:
            raise HTTPException(404, "Friend request not found")

    return {"message": "Friend request declined"}


# ==========================================
# FRIENDS LIST
# ==========================================

@app.get("/friends")
def get_friends(user=Depends(get_current_user)):

    with get_db() as conn:

        friends = conn.execute("""
            SELECT
                u.id,
                u.username,
                CASE
                    WHEN u.last_seen > NOW() - INTERVAL '60 seconds'
                    THEN 'ONLINE'
                    ELSE 'OFFLINE'
                END AS status
            FROM friendships f
            JOIN users u ON u.id = f.friend_id
            WHERE f.user_id = %s
            ORDER BY u.username
        """, (user["id"],)).fetchall()

    return friends


# ==========================================
# REMOVE FRIEND
# ==========================================

@app.delete("/friends/{target_id}")
def remove_friend(
    target_id: int,
    user=Depends(get_current_user)
):

    with get_db() as conn:

        conn.execute("""
            DELETE FROM friendships
            WHERE
                (user_id = %s AND friend_id = %s)
                OR
                (user_id = %s AND friend_id = %s)
        """, (
            user["id"],
            target_id,
            target_id,
            user["id"]
        ))

    return {"message": "Friend removed"}


# ==========================================
# HEARTBEAT
# ==========================================

@app.post("/heartbeat")
def heartbeat(user=Depends(get_current_user)):
    return {
        "message": "Heartbeat received",
        "status": "ONLINE"
    }
