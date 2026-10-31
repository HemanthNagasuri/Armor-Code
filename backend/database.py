import hashlib
import json
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from typing import Any, Iterator, Optional


DB_PATH = os.environ.get(
    "ARMORCODE_DB_PATH",
    os.path.join(os.path.dirname(__file__), "armorcode.db"),
)
PASSWORD_ITERATIONS = 260_000
OTP_ITERATIONS = 100_000
SESSION_TTL_SECONDS = 60 * 60 * 24 * 7
ZERO_WIDTH_CHARS = ("\u200b", "\u200c", "\u200d")


@contextmanager
def get_db() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 10000")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    with get_db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL COLLATE NOCASE,
                name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                default_signature TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS otp_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL COLLATE NOCASE,
                otp_code TEXT NOT NULL DEFAULT '',
                action TEXT NOT NULL,
                code_hash TEXT NOT NULL,
                target_signature TEXT,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                verified INTEGER NOT NULL DEFAULT 0,
                otp_salt TEXT,
                otp_hash TEXT,
                attempts INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS otp_send_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL COLLATE NOCASE,
                action TEXT NOT NULL,
                created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS code_registry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code_hash TEXT UNIQUE NOT NULL,
                owner_email TEXT NOT NULL COLLATE NOCASE,
                author_signature TEXT NOT NULL,
                code_preview TEXT,
                clean_code TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                history TEXT DEFAULT '[]'
            );
            CREATE INDEX IF NOT EXISTS idx_otp_lookup
                ON otp_codes(email, action, code_hash, target_signature);
            CREATE INDEX IF NOT EXISTS idx_registry_owner
                ON code_registry(owner_email);
            """
        )
        columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(otp_codes)")
        }
        if "otp_salt" not in columns:
            conn.execute("ALTER TABLE otp_codes ADD COLUMN otp_salt TEXT")
        if "otp_hash" not in columns:
            conn.execute("ALTER TABLE otp_codes ADD COLUMN otp_hash TEXT")
        if "attempts" not in columns:
            conn.execute(
                "ALTER TABLE otp_codes ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0"
            )
        conn.execute(
            "DELETE FROM otp_codes WHERE otp_hash IS NULL OR expires_at <= ?",
            (time.time(),),
        )
        conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (time.time(),))


def hash_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), PASSWORD_ITERATIONS
    )
    return digest.hex(), salt


def verify_password(password: str, password_hash: str, salt: str) -> bool:
    digest, _ = hash_password(password, salt)
    return secrets.compare_digest(digest, password_hash)


def _public_user(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "email": row["email"],
        "name": row["name"],
        "default_signature": row["default_signature"],
        "created_at": row["created_at"],
    }


def create_user(
    email: str,
    name: str,
    password: str,
    default_signature: Optional[str] = None,
) -> dict[str, Any]:
    email = email.strip().lower()
    name = name.strip()
    default_signature = (default_signature or "").strip()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise ValueError("Enter a valid email address.")
    if not name or len(name) > 100:
        raise ValueError("Name must contain 1 to 100 characters.")
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters.")
    if not default_signature:
        compact_name = re.sub(r"\s+", "", name)
        default_signature = f"{compact_name}-2026"
    if len(default_signature) > 48:
        raise ValueError("Default signature must be 48 characters or fewer.")

    password_hash, salt = hash_password(password)
    created_at = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        with get_db() as conn:
            cursor = conn.execute(
                """
                INSERT INTO users
                    (email, name, password_hash, salt, default_signature, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (email, name, password_hash, salt, default_signature, created_at),
            )
            user_id = cursor.lastrowid
    except sqlite3.IntegrityError as exc:
        raise ValueError("An account with this email already exists.") from exc

    return {
        "id": user_id,
        "email": email,
        "name": name,
        "default_signature": default_signature,
        "created_at": created_at,
    }


def get_user_by_email(email: str) -> Optional[dict[str, Any]]:
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE email = ? COLLATE NOCASE",
            (email.strip().lower(),),
        ).fetchone()
    return dict(row) if row else None


def authenticate_user(email: str, password: str) -> Optional[dict[str, Any]]:
    user = get_user_by_email(email)
    if not user or not verify_password(
        password, user["password_hash"], user["salt"]
    ):
        return None
    return _public_user(user)


def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
    with get_db() as conn:
        conn.execute(
            "INSERT INTO sessions(token_hash, user_id, expires_at) VALUES (?, ?, ?)",
            (token_hash, user_id, time.time() + SESSION_TTL_SECONDS),
        )
    return token


def get_user_for_session(token: str) -> Optional[dict[str, Any]]:
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    now = time.time()
    with get_db() as conn:
        row = conn.execute(
            """
            SELECT users.* FROM sessions
            JOIN users ON users.id = sessions.user_id
            WHERE sessions.token_hash = ? AND sessions.expires_at > ?
            """,
            (token_hash, now),
        ).fetchone()
    return _public_user(row) if row else None


def revoke_session(token: str) -> None:
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    with get_db() as conn:
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))


def generate_otp() -> str:
    return f"{secrets.randbelow(900_000) + 100_000:06d}"


def create_and_store_otp(
    email: str,
    action: str,
    code_hash: str,
    target_signature: str = "",
    ttl_seconds: int = 600,
) -> str:
    email = email.strip().lower()
    now = time.time()
    otp = generate_otp()
    otp_salt = secrets.token_hex(16)
    otp_hash = hashlib.pbkdf2_hmac(
        "sha256", otp.encode("ascii"), otp_salt.encode("ascii"), OTP_ITERATIONS
    ).hex()

    with get_db() as conn:
        conn.execute("DELETE FROM otp_send_events WHERE created_at < ?", (now - 86400,))
        recent_count = conn.execute(
            """
            SELECT COUNT(*) FROM otp_send_events
            WHERE email = ? AND action = ? AND created_at > ?
            """,
            (email, action, now - 900),
        ).fetchone()[0]
        if recent_count >= 5:
            raise ValueError("Too many OTP requests. Try again in 15 minutes.")

        conn.execute(
            "DELETE FROM otp_codes WHERE email = ? AND action = ? AND code_hash = ?",
            (email, action, code_hash),
        )
        conn.execute(
            """
            INSERT INTO otp_codes
                (email, otp_code, action, code_hash, target_signature,
                 created_at, expires_at, otp_salt, otp_hash)
            VALUES (?, '', ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                email,
                action,
                code_hash,
                target_signature,
                now,
                now + ttl_seconds,
                otp_salt,
                otp_hash,
            ),
        )
        conn.execute(
            "INSERT INTO otp_send_events(email, action, created_at) VALUES (?, ?, ?)",
            (email, action, now),
        )
    return otp


def invalidate_otp(email: str, action: str, code_hash: str) -> None:
    with get_db() as conn:
        conn.execute(
            "DELETE FROM otp_codes WHERE email = ? AND action = ? AND code_hash = ?",
            (email.strip().lower(), action, code_hash),
        )


def verify_stored_otp(
    email: str,
    otp_code: str,
    action: str,
    code_hash: str,
    target_signature: str,
) -> bool:
    email = email.strip().lower()
    now = time.time()
    with get_db() as conn:
        row = conn.execute(
            """
            SELECT id, otp_salt, otp_hash, expires_at, attempts
            FROM otp_codes
            WHERE email = ? AND action = ? AND code_hash = ?
                AND target_signature = ? AND verified = 0
            ORDER BY created_at DESC LIMIT 1
            """,
            (email, action, code_hash, target_signature),
        ).fetchone()
        if not row or row["expires_at"] <= now or row["attempts"] >= 5:
            return False

        candidate = hashlib.pbkdf2_hmac(
            "sha256",
            otp_code.strip().encode("utf-8"),
            (row["otp_salt"] or "").encode("ascii"),
            OTP_ITERATIONS,
        ).hex()
        if not secrets.compare_digest(candidate, row["otp_hash"] or ""):
            conn.execute(
                "UPDATE otp_codes SET attempts = attempts + 1 WHERE id = ?",
                (row["id"],),
            )
            return False
        conn.execute(
            "UPDATE otp_codes SET verified = 1, attempts = attempts + 1 WHERE id = ?",
            (row["id"],),
        )
        return True


def has_verified_otp(
    email: str, action: str, code_hash: str, target_signature: str
) -> bool:
    with get_db() as conn:
        row = conn.execute(
            """
            SELECT 1 FROM otp_codes
            WHERE email = ? AND action = ? AND code_hash = ?
                AND target_signature = ? AND verified = 1 AND expires_at > ?
            LIMIT 1
            """,
            (email.strip().lower(), action, code_hash, target_signature, time.time()),
        ).fetchone()
    return row is not None


def clear_otps_for_code(code_hash: str) -> None:
    with get_db() as conn:
        conn.execute("DELETE FROM otp_codes WHERE code_hash = ?", (code_hash,))


def compute_normalized_code_hash(code_text: str) -> str:
    clean = "".join(ch for ch in code_text if ch not in ZERO_WIDTH_CHARS)
    return hashlib.sha256(clean.encode("utf-8")).hexdigest()


def get_code_owner(code_hash: str) -> Optional[dict[str, Any]]:
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM code_registry WHERE code_hash = ?", (code_hash,)
        ).fetchone()
    if not row:
        return None
    data = dict(row)
    try:
        data["history"] = json.loads(data.get("history") or "[]")
    except (TypeError, json.JSONDecodeError):
        data["history"] = []
    return data


def register_code_ownership(
    code_hash: str,
    owner_email: str,
    author_signature: str,
    clean_code: str,
    authorized_original_owner_email: Optional[str] = None,
    embedded_owner_email: Optional[str] = None,
) -> dict[str, Any]:
    owner_email = owner_email.strip().lower()
    authorized_original_owner_email = (
        authorized_original_owner_email.strip().lower()
        if authorized_original_owner_email
        else None
    )
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM code_registry WHERE code_hash = ?", (code_hash,)
        ).fetchone()
        existing = dict(row) if row else None
        original_owner = (
            existing["owner_email"] if existing else embedded_owner_email
        )
        if (
            original_owner
            and original_owner.lower() != owner_email
            and authorized_original_owner_email != original_owner.lower()
        ):
            raise PermissionError("Original owner authorization is required.")

        if existing:
            try:
                history = json.loads(existing.get("history") or "[]")
            except (TypeError, json.JSONDecodeError):
                history = []
            if existing["owner_email"].lower() != owner_email:
                history.append(
                    {
                        "previous_owner": existing["owner_email"],
                        "previous_signature": existing["author_signature"],
                        "new_owner": owner_email,
                        "new_signature": author_signature,
                        "reassigned_at": now,
                    }
                )
            conn.execute(
                """
                UPDATE code_registry
                SET owner_email = ?, author_signature = ?, updated_at = ?,
                    history = ?, clean_code = NULL, code_preview = ?
                WHERE code_hash = ?
                """,
                (
                    owner_email,
                    author_signature,
                    now,
                    json.dumps(history),
                    clean_code[:200],
                    code_hash,
                ),
            )
        else:
            conn.execute(
                """
                INSERT INTO code_registry
                    (code_hash, owner_email, author_signature, code_preview,
                     clean_code, created_at, updated_at, history)
                VALUES (?, ?, ?, ?, NULL, ?, ?, '[]')
                """,
                (
                    code_hash,
                    owner_email,
                    author_signature,
                    clean_code[:200],
                    now,
                    now,
                ),
            )

    record = get_code_owner(code_hash)
    if record is None:
        raise RuntimeError("Ownership record was not persisted.")
    return record


def get_user_registered_codes(owner_email: str) -> list[dict[str, Any]]:
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT code_hash, owner_email, author_signature, code_preview,
                   created_at, updated_at, history
            FROM code_registry
            WHERE owner_email = ? COLLATE NOCASE
            ORDER BY updated_at DESC
            """,
            (owner_email.strip().lower(),),
        ).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        try:
            item["history"] = json.loads(item.get("history") or "[]")
        except (TypeError, json.JSONDecodeError):
            item["history"] = []
        result.append(item)
    return result


init_db()
