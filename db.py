import sqlite3
from typing import Optional
from config import DB_PATH

def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db() -> None:
    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            user_handle BLOB NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,

            credential_id_hash BLOB UNIQUE NOT NULL,
            credential_id_enc  BLOB NOT NULL,

            public_key_enc     BLOB NOT NULL,
            sign_count         INTEGER NOT NULL DEFAULT 0,
            transports         TEXT,
            device_type        TEXT,
            backed_up          INTEGER NOT NULL DEFAULT 0,

            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """
    )

    conn.commit()
    conn.close()

def get_user(username: str) -> Optional[sqlite3.Row]:
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    return row

def get_username_by_user_id(user_id: int) -> Optional[str]:
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    return row["username"] if row else None


def get_or_create_user(username: str, user_handle: bytes) -> sqlite3.Row:
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    if row:
        conn.close()
        return row

    cur.execute("INSERT INTO users(username, user_handle) VALUES (?, ?)", (username, user_handle))
    conn.commit()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    return row

def list_user_credentials(user_id: int) -> list[sqlite3.Row]:
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM credentials WHERE user_id = ?", (user_id,))
    rows = cur.fetchall()
    conn.close()
    return list(rows)

def find_credential_by_hash(cred_hash: bytes) -> Optional[sqlite3.Row]:
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM credentials WHERE credential_id_hash = ?", (cred_hash,))
    row = cur.fetchone()
    conn.close()
    return row

def insert_or_replace_credential(
    user_id: int,
    credential_id_hash: bytes,
    credential_id_enc: bytes,
    public_key_enc: bytes,
    sign_count: int,
    transports_json: str,
    device_type: str | None,
    backed_up: bool,
) -> None:
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT OR REPLACE INTO credentials(
            user_id, credential_id_hash, credential_id_enc, public_key_enc,
            sign_count, transports, device_type, backed_up
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            credential_id_hash,
            credential_id_enc,
            public_key_enc,
            sign_count,
            transports_json,
            device_type,
            1 if backed_up else 0,
        ),
    )
    conn.commit()
    conn.close()

def update_credential_sign_count(
    cred_hash: bytes,
    new_sign_count: int,
    device_type: str | None,
    backed_up: bool,
) -> None:
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE credentials
        SET sign_count = ?, device_type = ?, backed_up = ?
        WHERE credential_id_hash = ?
        """,
        (new_sign_count, device_type, 1 if backed_up else 0, cred_hash),
    )
    conn.commit()
    conn.close()