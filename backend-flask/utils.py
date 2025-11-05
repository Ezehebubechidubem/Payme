# utils.py
import os
import sqlite3
import traceback
from datetime import datetime, timedelta
from functools import wraps

# For hashing pins
from werkzeug.security import generate_password_hash, check_password_hash

# Optional Postgres support
try:
    import psycopg2
    import psycopg2.extras
except Exception:
    psycopg2 = None
    psycopg2_extras = None

# Configuration (these match what app.py usually expects)
DATABASE_URL = os.environ.get("DATABASE_URL")
SQLITE_DB_PATH = os.environ.get("SQLITE_DB_PATH", "payme.db")

# TTL for generated (dev) 6-digit code (seconds)
CODE_TTL_SECONDS = int(os.environ.get("CODE_TTL_SECONDS", 10 * 60))

# Simple wrapper classes to support both sqlite and psycopg2
class PGCursorWrapper:
    def __init__(self, cur):
        self._cur = cur

    def execute(self, sql, params=None):
        if params is None:
            return self._cur.execute(sql)
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
        if psycopg2 is None:
            raise RuntimeError("psycopg2 not installed; cannot use PostgreSQL.")
        self.conn = psycopg2.connect(self.dsn)
        self.conn.autocommit = False
        return self

    def cursor(self):
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
            except Exception:
                pass

    def __exit__(self, exc_type, exc, tb):
        if exc_type:
            try:
                self.conn.rollback()
            except Exception:
                pass
        else:
            try:
                self.conn.commit()
            except Exception:
                pass
        try:
            self.conn.close()
        except Exception:
            pass

def get_conn():
    """
    Returns either a PGConnectionContext (if DATABASE_URL set) or a sqlite3.Connection.
    The returned sqlite connection is not a context manager that commits automatically,
    so we use it with 'with get_conn() as conn' for parity in pin_routes.
    """
    if DATABASE_URL:
        return PGConnectionContext(DATABASE_URL)
    else:
        # sqlite connection — we return an object that supports context manager semantics
        conn = sqlite3.connect(SQLITE_DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        # ensure PRAGMAs for SQLite
        with conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
        return conn

# PIN / lock helpers that operate on SQLAlchemy models (import models locally to avoid circular import)
def is_locked(user):
    """
    user: SQLAlchemy User object
    returns (locked:boolean, until:datetime or None)
    """
    from datetime import datetime as _dt
    if user.locked_until and user.locked_until > _dt.utcnow():
        return True, user.locked_until
    return False, None

def lock_user(user, DB, PinAudit, LOCK_DURATION=timedelta(hours=4)):
    """
    user: SQLAlchemy user instance
    DB: SQLAlchemy instance imported from models (models.DB)
    PinAudit: models.PinAudit class
    """
    from datetime import datetime as _dt
    user.locked_until = _dt.utcnow() + LOCK_DURATION
    user.failed_attempts = 0
    DB.session.add(user)
    DB.session.commit()
    DB.session.flush()
    DB.session.add(PinAudit(user_id=user.id, event_type='PIN_LOCK', meta={'locked_until': user.locked_until.isoformat()}))
    DB.session.commit()

def audit_event(user, event_type, DB=None, PinAudit=None, meta=None):
    """
    Write a PinAudit record (by default import models locally).
    If DB/PinAudit are provided, they are used; otherwise function imports models.
    """
    try:
        if DB is None or PinAudit is None:
            from models import DB as _DB, PinAudit as _PinAudit
            DB = _DB
            PinAudit = _PinAudit
        DB.session.add(PinAudit(user_id=user.id, event_type=event_type, meta=meta))
        DB.session.commit()
    except Exception:
        traceback.print_exc()

# Basic login_required decorator that supports JWT (Authorization: Bearer <token>) or session['user_id'].
def login_required(fn):
    """
    Decorator to allow either:
      - Authorization: Bearer <JWT> (flask_jwt_extended)
      - session['user_id'] (legacy)
    On success sets flask.g.current_user to SQLAlchemy User model instance.
    """
    from flask import session, g, jsonify
    try:
        from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
    except Exception:
        verify_jwt_in_request = None
        get_jwt_identity = None

    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = None
        # Delay import of models to avoid circular import at module import time
        from models import User as _User

        # 1) Try JWT
        try:
            if verify_jwt_in_request is not None:
                # optional=True not available on all versions; we'll catch exceptions
                try:
                    verify_jwt_in_request(optional=True)
                    identity = get_jwt_identity()
                    if identity:
                        user = _User.query.get(int(identity))
                except TypeError:
                    # older flask_jwt_extended versions: verify_jwt_in_request() requires token presence
                    try:
                        verify_jwt_in_request()
                        identity = get_jwt_identity()
                        if identity:
                            user = _User.query.get(int(identity))
                    except Exception:
                        user = None
                except Exception:
                    user = None
        except Exception:
            user = None

        # 2) fallback to session
        if not user:
            try:
                uid = session.get("user_id")
                if uid:
                    user = _User.query.get(int(uid))
            except Exception:
                user = None

        if not user:
            return jsonify({"success": False, "message": "User not logged in"}), 401

        # attach to g for handlers
        from flask import g as _g
        _g.current_user = user
        return fn(*args, **kwargs)
    return wrapper