# utils.py
import os
import sqlite3
import traceback
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

# Optional postgres support
DATABASE_URL = os.environ.get("DATABASE_URL")
SQLITE_DB_PATH = os.environ.get("SQLITE_DB_PATH", "payme.db")

# --------- Postgres cursor/connection wrapper (if DATABASE_URL set) ----------
# We keep this minimal and compatible with the rest of the code: it returns
# an object usable with "with get_conn() as conn: cur = conn.cursor(); cur.execute(...)"
class PGCursorWrapper:
    def __init__(self, cur):
        self._cur = cur

    def execute(self, sql, params=None):
        if params is None:
            return self._cur.execute(sql)
        # Accept ? placeholders in our code and convert to %s for psycopg2
        safe_sql = sql.replace("?", "%s")
        return self._cur.execute(safe_sql, params)

    def executemany(self, sql, seq_of_params):
        safe_sql = sql.replace("?", "%s")
        return self._cur.executemany(safe_sql, seq_of_params)

    def fetchone(self):
        return self._cur.fetchone()

    def fetchall(self):
        return self._cur.fetchall()

    def __getattr__(self, name):
        return getattr(self._cur, name)


class PGConnectionContext:
    def __init__(self, dsn):
        self.dsn = dsn
        self.conn = None

    def __enter__(self):
        try:
            import psycopg2
            import psycopg2.extras
        except Exception as e:
            raise RuntimeError("psycopg2 is required for PostgreSQL usage") from e
        self.conn = psycopg2.connect(self.dsn)
        self.conn.autocommit = False
        return self

    def cursor(self):
        import psycopg2.extras
        raw_cur = self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        return PGCursorWrapper(raw_cur)

    def commit(self):
        if self.conn:
            self.conn.commit()

    def rollback(self):
        if self.conn:
            self.conn.rollback()

    def close(self):
        if self.conn:
            try:
                self.conn.close()
            except:
                pass

    def __exit__(self, exc_type, exc, tb):
        try:
            if exc_type:
                try:
                    self.conn.rollback()
                except:
                    pass
            else:
                try:
                    self.conn.commit()
                except:
                    pass
        finally:
            try:
                self.conn.close()
            except:
                pass


def get_conn():
    """
    Returns either a PGConnectionContext (when DATABASE_URL set) or a sqlite3.Connection.
    Usage:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(...)
    For sqlite3, the returned object is the raw connection (not wrapper).
    """
    if DATABASE_URL:
        return PGConnectionContext(DATABASE_URL)
    else:
        conn = sqlite3.connect(SQLITE_DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        with conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
        return conn


# ----------------- PIN hashing helpers -----------------
def hash_pin(pin: str) -> str:
    """Use werkzeug password hasher (PBKDF2) - safe for small secrets."""
    return generate_password_hash(pin)


def check_pin(pin: str, hashed: str) -> bool:
    try:
        return check_password_hash(hashed, pin)
    except Exception:
        return False


# ----------------- small helpers -----------------
def now_iso():
    return datetime.utcnow().isoformat()

def debug_log(*args, **kwargs):
    # Helper to keep server logs consistent when printing exceptions
    print(*args, **kwargs)