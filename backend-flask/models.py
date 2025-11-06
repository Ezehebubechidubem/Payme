from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

DB = SQLAlchemy()


class User(DB.Model):
    __tablename__ = "users"
    id = DB.Column(DB.Integer, primary_key=True)
    username = DB.Column(DB.String(255), unique=True, nullable=True)
    phone = DB.Column(DB.String(32), unique=True, nullable=True)
    password = DB.Column(DB.String(255), nullable=True)  # hashed password
    account_number = DB.Column(DB.String(32), unique=True, nullable=True)
    balance = DB.Column(DB.Numeric, default=0)

    # PIN-related fields
    payment_pin = DB.Column(DB.String(255), nullable=True)  # hashed PIN
    failed_attempts = DB.Column(DB.Integer, default=0)
    locked_until = DB.Column(DB.DateTime, nullable=True)

    def __repr__(self):
        return f"<User {self.id} {self.username} {self.account_number}>"


class PinAudit(DB.Model):
    __tablename__ = "pin_audit"
    id = DB.Column(DB.Integer, primary_key=True)
    user_id = DB.Column(DB.Integer, DB.ForeignKey("users.id"), nullable=False)
    event_type = DB.Column(DB.String(80), nullable=False)  # e.g. PIN_SETUP, PIN_VERIFY_FAIL
    meta = DB.Column(DB.JSON, nullable=True)
    created_at = DB.Column(DB.DateTime, default=datetime.utcnow)


class PinCode(DB.Model):
    """
    Ephemeral 6-digit codes used to verify account ownership (dev/testing).
    In production you'd send the code via SMS and not return it in API responses.
    """
    __tablename__ = "pin_codes"
    id = DB.Column(DB.Integer, primary_key=True)
    account_number = DB.Column(DB.String(32), index=True, nullable=False)
    code = DB.Column(DB.String(6), nullable=False)
    expires_at = DB.Column(DB.DateTime, nullable=False)


class Transaction(DB.Model):
    __tablename__ = "transactions"
    id = DB.Column(DB.Integer, primary_key=True)
    from_user = DB.Column(DB.Integer, DB.ForeignKey("users.id"), nullable=False)
    to_account = DB.Column(DB.String(64), nullable=False)
    amount = DB.Column(DB.Numeric, nullable=False)
    status = DB.Column(DB.String(50), default="PENDING")
    created_at = DB.Column(DB.DateTime, default=datetime.utcnow)


# ----------------------------------------------------------------------
# Universal init_tables() — works on SQLite & PostgreSQL (Render safe)
# ----------------------------------------------------------------------
def init_tables():
    """Ensure tables required by PIN module exist — safe for both SQLite & PG."""
    try:
        from utils import get_conn
        with get_conn() as conn:
            cur = conn.cursor()

            stmts = [
                """
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT,
                    phone TEXT UNIQUE,
                    password TEXT,
                    account_number TEXT UNIQUE,
                    balance REAL DEFAULT 0
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS pin_audit (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER,
                    event_type TEXT,
                    meta TEXT,
                    created_at TEXT
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS pin_codes (
                    id SERIAL PRIMARY KEY,
                    account_number TEXT,
                    code TEXT,
                    expires_at TEXT
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS user_pins (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER,
                    hashed_pin TEXT,
                    created_at TEXT
                )
                """
            ]

            for sql in stmts:
                cur.execute(sql.strip())

        print("✅ init_tables(): ensured pin-related tables exist")
    except Exception as e:
        print("⚠️ init_tables() skipped or failed:", e)