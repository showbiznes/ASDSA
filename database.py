# =============================================================================
# database.py — SQLite для предупреждений и настроек серверов
# =============================================================================

import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

import config

logger = logging.getLogger("antispam.database")


@contextmanager
def get_conn():
    conn = sqlite3.connect(config.DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    Path(config.DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    with get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS warnings (
                user_id     INTEGER NOT NULL,
                guild_id    INTEGER NOT NULL,
                count       INTEGER NOT NULL DEFAULT 0,
                updated_at  TIMESTAMP NOT NULL,
                PRIMARY KEY (user_id, guild_id)
            );
            CREATE TABLE IF NOT EXISTS violations (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER NOT NULL,
                guild_id    INTEGER NOT NULL,
                username    TEXT NOT NULL,
                filename    TEXT,
                confidence  REAL,
                method      TEXT,
                action      TEXT,
                created_at  TIMESTAMP NOT NULL
            );
            CREATE TABLE IF NOT EXISTS guild_settings (
                guild_id        INTEGER PRIMARY KEY,
                log_channel_id  INTEGER,
                updated_at      TIMESTAMP NOT NULL
            );
            CREATE TABLE IF NOT EXISTS stats (
                key     TEXT PRIMARY KEY,
                value   INTEGER NOT NULL DEFAULT 0
            );
            INSERT OR IGNORE INTO stats (key, value) VALUES ('images_checked', 0);
            INSERT OR IGNORE INTO stats (key, value) VALUES ('violations_found', 0);
            INSERT OR IGNORE INTO stats (key, value) VALUES ('users_muted', 0);
        """)
    logger.info("БД инициализирована: %s", config.DB_PATH)


def get_warnings(user_id: int, guild_id: int) -> int:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT count FROM warnings WHERE user_id = ? AND guild_id = ?",
            (user_id, guild_id),
        ).fetchone()
    return row["count"] if row else 0


def add_warning(user_id: int, guild_id: int) -> int:
    now = datetime.utcnow()
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO warnings (user_id, guild_id, count, updated_at)
            VALUES (?, ?, 1, ?)
            ON CONFLICT(user_id, guild_id) DO UPDATE SET
                count = count + 1, updated_at = excluded.updated_at
        """, (user_id, guild_id, now))
        row = conn.execute(
            "SELECT count FROM warnings WHERE user_id = ? AND guild_id = ?",
            (user_id, guild_id),
        ).fetchone()
    return row["count"]


def reset_warnings(user_id: int, guild_id: int) -> None:
    with get_conn() as conn:
        conn.execute(
            "DELETE FROM warnings WHERE user_id = ? AND guild_id = ?",
            (user_id, guild_id),
        )


def log_violation(user_id, guild_id, username, filename, confidence, method, action):
    now = datetime.utcnow()
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO violations
                (user_id, guild_id, username, filename, confidence, method, action, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, guild_id, username, filename, confidence, method, action, now))


def increment_stat(key: str, amount: int = 1) -> None:
    with get_conn() as conn:
        conn.execute("UPDATE stats SET value = value + ? WHERE key = ?", (amount, key))


def get_stats() -> dict:
    with get_conn() as conn:
        rows = conn.execute("SELECT key, value FROM stats").fetchall()
    return {row["key"]: row["value"] for row in rows}


def get_log_channel(guild_id: int):
    with get_conn() as conn:
        row = conn.execute(
            "SELECT log_channel_id FROM guild_settings WHERE guild_id = ?",
            (guild_id,),
        ).fetchone()
    return row["log_channel_id"] if row else None


def set_log_channel(guild_id: int, channel_id: int) -> None:
    now = datetime.utcnow()
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO guild_settings (guild_id, log_channel_id, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(guild_id) DO UPDATE SET
                log_channel_id = excluded.log_channel_id,
                updated_at = excluded.updated_at
        """, (guild_id, channel_id, now))
