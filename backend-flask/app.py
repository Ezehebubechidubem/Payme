# models.py
"""
Create the extra tables needed for PIN functionality:
 - pin_codes (ephemeral 6-digit codes)
 - user_pins (store hashed 4-digit PINs linked to user id)
 - pin_audit  (audit trail)
This module is intentionally DB-agnostic and uses utils.get_conn() to create tables.
"""

from datetime import datetime
import os
from utils import get_conn

DATABASE_URL = os.environ.get("DATABASE_URL")

def init_tables():
    """
    Create the tables needed by pin routes.
    Uses different DDL for Postgres vs SQLite to avoid incompatibilities.
    """
    conn = get_conn()
    cur = conn.cursor()

    if DATABASE_URL:
        # Postgres DDL
        cur.execute("""
        CREATE TABLE IF NOT EXISTS pin_codes (
            id SERIAL PRIMARY KEY,
            account_number TEXT NOT NULL,
            code TEXT NOT NULL,
            expires_at TIMESTAMP NOT NULL
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS user_pins (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            hashed_pin TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT now()
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS pin_audit (
            id SERIAL PRIMARY KEY,
            user_id INTEGER,
            event_type TEXT,
            meta JSONB,
            created_at TIMESTAMP DEFAULT now()
        )
        """)
    else:
        # SQLite DDL
        cur.execute("""
        CREATE TABLE IF NOT EXISTS pin_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_number TEXT NOT NULL,
            code TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS user_pins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            hashed_pin TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS pin_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            event_type TEXT,
            meta TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """)

    # If sqlite, commit immediately and close; if PGContext, commit happens on exit
    try:
        conn.commit()
    except Exception:
        # PGConnectionContext may not be real sqlite Connection - commit inside context manager
        pass
    try:
        conn.close()
    except Exception:
        pass

# Run on import to ensure tables exist (safe)
try:
    init_tables()
except Exception as e:
    # If DB isn't available at import, don't crash; table will be created on first route call
    print("models.init_tables() warning:", e)