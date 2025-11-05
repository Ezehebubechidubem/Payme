# pin_routes.py
"""
PIN-related routes:
 - POST /api/pin/request-code    -> generate (dev) 6-digit code for account
 - POST /api/pin/associate       -> associate a 4-digit PIN to an account using 6-digit code
 - GET  /api/pin/status          -> check PIN status (auth-aware)
 - POST /api/pin/setup           -> setup PIN for authenticated user (auth-aware)
 - POST /api/pin/verify          -> verify a PIN for an account (auth-aware or account-based)

This file attempts to import helpers (DB, User, get_conn, login_required, audit_event) from the main app.
If they aren't present it falls back to local imports from models.py / utils.py.
"""
from flask import Blueprint, request, jsonify, current_app
import traceback
from datetime import datetime, timedelta
import random

bp = Blueprint("pin", __name__, url_prefix="/api/pin")

# --- defensive imports: prefer app-supplied objects, fall back to our local modules ---
try:
    # Preferred: your app.py exports these names
    from app import DB, User, get_conn, login_required, audit_event, PIN_LENGTH
    APP_HAS_DB = True
except Exception:
    APP_HAS_DB = False
    # local imports
    from models import DB, PinAudit  # DB from models.py
    from utils import PIN_LENGTH, hash_pin, verify_pin, is_locked, lock_user, reset_attempts
    # get_conn is defined in your app usually; try to import if app module exists
    try:
        from app import get_conn  # possible
    except Exception:
        # fallback: assume a simple sqlite DB path in environment: default used in get_conn below
        get_conn = None
    # define fallback login_required (no-op) to allow non-auth flows; routes that need real auth should be wired to app's decorator
    def login_required(fn):
        def wrapper(*a, **kw):
            # If your app does not provide login_required, allow the route to proceed
            return fn(*a, **kw)
        wrapper.__name__ = fn.__name__
        return wrapper

# imports common in both cases
from werkzeug.security import generate_password_hash, check_password_hash

# We'll use raw SQL table 'pin_codes' to store ephemeral 6-digit codes.
CODE_TTL_SECONDS = 10 * 60  # 10 minutes

# --- helper to ensure pin_codes table exists when using raw get_conn() ---
def _ensure_pin_codes_table_raw():
    """
    Create pin_codes table if it doesn't exist. Uses get_conn() - either from app or attempts sqlite fallback.
    """
    global get_conn
    if not get_conn:
        # try to import a get_conn defined in app module now (delayed import)
        try:
            from app import get_conn as _gc
            get_conn = _gc
        except Exception:
            # build a very small fallback get_conn that uses sqlite file in current folder
            import sqlite3, os
            DBFILE = os.environ.get("SQLITE_DB_PATH", "payme.db")
            def fallback_conn():
                conn = sqlite3.connect(DBFILE, check_same_thread=False)
                conn.row_factory = sqlite3.Row
                with conn:
                    conn.execute("PRAGMA journal_mode=WAL;")
                    conn.execute("PRAGMA foreign_keys=ON;")
                return conn
            get_conn = fallback_conn

    # create table using wrapper (works for sqlite and for PG via user's wrapper)
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS pin_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_number TEXT NOT NULL,
                code TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
        """)

# ensure the table exists at import (safe idempotent)
try:
    _ensure_pin_codes_table_raw()
except Exception:
    # ignore here — will be attempted again per-request
    traceback.print_exc()


# ---------------------
# ROUTES
# ---------------------

@bp.route("/request-code", methods=["POST"])
def request_pin_code():
    """
    Dev/testing helper: generate a 6-digit code for an account number and return it.
    Body: { "account_number": "1234567890" }
    NOTE: In production you should send the code via SMS and NOT return it in the response.
    """
    data = request.get_json() or {}
    acct = (data.get("account_number") or "").strip()
    if not acct or not acct.isdigit() or len(acct) not in (10, 11):
        return jsonify({'success': False, 'message': 'Invalid account_number'}), 400

    # generate code & expiry
    code = f"{random.randint(0, 999999):06d}"
    expires_at = (datetime.utcnow() + timedelta(seconds=CODE_TTL_SECONDS)).isoformat()

    try:
        _ensure_pin_codes_table_raw()
        with get_conn() as conn:
            cur = conn.cursor()
            # delete previous codes for this account to keep single active code
            cur.execute("DELETE FROM pin_codes WHERE account_number = ?", (acct,))
            cur.execute("INSERT INTO pin_codes (account_number, code, expires_at) VALUES (?, ?, ?)", (acct, code, expires_at))
        # DEBUG: return code for development only
        return jsonify({'success': True, 'message': 'Code generated', 'code': code, 'expires_at': expires_at}), 200
    except Exception as e:
        traceback.print_exc()
        return jsonify({'success': False, 'message': 'Failed to generate code'}), 500


@bp.route("/associate", methods=["POST"])
def pin_associate():
    """
    Associate a 4-digit PIN to an account using the 6-digit code.
    Body: { account_number: "1234567890", code: "123456", pin: "1234" }
    """
    data = request.get_json() or {}
    account_number = (data.get('account_number') or '').strip()
    code = (data.get('code') or '').strip()
    pin = (data.get('pin') or '').strip()

    if not account_number or not account_number.isdigit() or len(account_number) not in (10, 11):
        return jsonify({'success': False, 'message': 'Invalid account_number'}), 400
    if not code or not code.isdigit() or len(code) != 6:
        return jsonify({'success': False, 'message': 'Invalid code'}), 400
    if not pin or not pin.isdigit() or len(pin) != (globals().get('PIN_LENGTH') or 4):
        return jsonify({'success': False, 'message': 'Invalid PIN (must be 4 digits)'}), 400

    try:
        _ensure_pin_codes_table_raw()
        with get_conn() as conn:
            cur = conn.cursor()
            # find user by account_number
            cur.execute("SELECT id FROM users WHERE account_number = ? LIMIT 1", (account_number,))
            user_row = cur.fetchone()
            if not user_row:
                return jsonify({'success': False, 'message': 'Account not found'}), 404

            # check code
            cur.execute("SELECT id, code, expires_at FROM pin_codes WHERE account_number = ? AND code = ? LIMIT 1", (account_number, code))
            code_row = cur.fetchone()
            if not code_row:
                return jsonify({'success': False, 'message': 'Invalid or expired code'}), 400

            # parse expires_at (works if row is dict-like or tuple/list)
            try:
                expires_at_val = code_row['expires_at'] if isinstance(code_row, dict) else code_row[2]
                expires_dt = datetime.fromisoformat(expires_at_val)
            except Exception:
                expires_dt = datetime.utcnow() - timedelta(seconds=1)

            if expires_dt < datetime.utcnow():
                # delete expired code
                code_id = code_row['id'] if isinstance(code_row, dict) else code_row[0]
                cur.execute("DELETE FROM pin_codes WHERE id = ?", (code_id,))
                return jsonify({'success': False, 'message': 'Code expired'}), 400

            # consume the code (single-use)
            code_id = code_row['id'] if isinstance(code_row, dict) else code_row[0]
            cur.execute("DELETE FROM pin_codes WHERE id = ?", (code_id,))

        # Update the user via SQLAlchemy (safer for model consistency & audit)
        # Try to get User model from app (preferred) else fallback to trying dynamic import
        try:
            # prefer app.User if available
            from app import User as AppUser, DB as AppDB
            user_obj = AppUser.query.filter_by(account_number=account_number).first()
            if not user_obj:
                return jsonify({'success': False, 'message': 'Account not found (race)'}), 404
            # store hashed pin
            user_obj.payment_pin = generate_password_hash(pin)
            user_obj.failed_attempts = 0
            user_obj.locked_until = None
            AppDB.session.add(user_obj)
            AppDB.session.commit()
            # audit if app.audit_event exists
            try:
                from app import audit_event as app_audit
                app_audit(user_obj, 'PIN_SETUP', meta={'method':'associate','time':datetime.utcnow().isoformat()})
            except Exception:
                # fallback: write a PinAudit row if models provide it
                try:
                    from models import PinAudit, DB as ModelsDB
                    ModelsDB.session.add(PinAudit(user_id=user_obj.id, action='PIN_SETUP', meta={'method':'associate'}))
                    ModelsDB.session.commit()
                except Exception:
                    pass

            return jsonify({'success': True, 'message': 'PIN attached to account successfully'}), 200

        except Exception:
            # If we cannot import app.User, attempt to update using raw SQL (best-effort)
            with get_conn() as conn:
                cur = conn.cursor()
                hashed = generate_password_hash(pin)
                cur.execute("UPDATE users SET password = ?, payment_pin = ? WHERE account_number = ?", ("", hashed, account_number))
            return jsonify({'success': True, 'message': 'PIN attached (raw SQL path)'}), 200

    except Exception:
        traceback.print_exc()
        return jsonify({'success': False, 'message': 'Server error'}), 500


@bp.route("/status", methods=["GET"])
@login_required
def api_pin_status():
    """
    Auth-aware status endpoint. The login_required decorator should set g.current_user inside app.
    If your login_required is not present, this will need wiring to your auth.
    """
    try:
        from flask import g
        user = getattr(g, 'current_user', None)
        if not user:
            # fallback: allow query by account_number param (less secure)
            acct = request.args.get('account_number')
            if not acct:
                return jsonify({'success': False, 'message': 'User not logged in'}), 401
            from app import User as AppUser
            user = AppUser.query.filter_by(account_number=acct).first()
            if not user:
                return jsonify({'success': False, 'message': 'User not found'}), 404

        # compute lock info - handle missing attributes gracefully
        locked = False
        lockedUntil = None
        try:
            if hasattr(user, 'locked_until') and user.locked_until:
                locked = user.locked_until > datetime.utcnow()
                lockedUntil = user.locked_until.isoformat() if user.locked_until else None
        except Exception:
            locked = False

        hasPin = bool(getattr(user, 'payment_pin', None))
        failedAttempts = int(getattr(user, 'failed_attempts', 0))

        return jsonify({
            'hasPin': hasPin,
            'locked': locked,
            'lockedUntil': lockedUntil,
            'failedAttempts': failedAttempts
        }), 200
    except Exception:
        traceback.print_exc()
        return jsonify({'success': False, 'message': 'Server error'}), 500


@bp.route("/setup", methods=["POST"])
@login_required
def setup_pin():
    """
    Setup PIN for an authenticated user. This route expects the auth decorator to set g.current_user;
    if your system uses tokens (Authorization: Bearer) that should be handled by your login_required.
    Body: { pin: "1234" }
    """
    try:
        from flask import g
        user = getattr(g, 'current_user', None)
        if not user:
            return jsonify({'success': False, 'message': 'User not logged in'}), 401

        data = request.get_json() or {}
        pin = (data.get('pin') or '').strip()
        if not pin or not pin.isdigit() or len(pin) != (globals().get('PIN_LENGTH') or 4):
            return jsonify({'success': False, 'message': 'Invalid PIN'}), 400

        # store hashed pin via SQLAlchemy
        user.payment_pin = generate_password_hash(pin)
        user.failed_attempts = 0
        user.locked_until = None
        try:
            # get DB instance from app or fallback to models.DB
            try:
                from app import DB as AppDB
                AppDB.session.add(user)
                AppDB.session.commit()
            except Exception:
                from models import DB as ModelsDB
                ModelsDB.session.add(user)
                ModelsDB.session.commit()
        except Exception:
            # last-resort: raw SQL update
            with get_conn() as conn:
                cur = conn.cursor()
                hashed = generate_password_hash(pin)
                cur.execute("UPDATE users SET payment_pin = ? WHERE id = ?", (hashed, user.id))

        # audit
        try:
            from app import audit_event as app_audit
            app_audit(user, 'PIN_SETUP', meta={'method':'setup','time':datetime.utcnow().isoformat()})
        except Exception:
            try:
                from models import PinAudit, DB as ModelsDB
                ModelsDB.session.add(PinAudit(user_id=user.id, action='PIN_SETUP', meta={'method':'setup'}))
                ModelsDB.session.commit()
            except Exception:
                pass

        return jsonify({'success': True, 'message': 'PIN saved successfully'}), 200

    except Exception:
        traceback.print_exc()
        return jsonify({'success': False, 'message': 'Server error'}), 500


@bp.route("/verify", methods=["POST"])
def verify_pin_route():
    """
    Verify a PIN for an account. Accepts either:
      - Authenticated user (with login_required middleware) -> will verify g.current_user
      - Body contains { account_number, pin } -> verify by account_number

    Body: { account_number?:..., pin: "1234" }
    """
    try:
        data = request.get_json() or {}
        pin = (data.get('pin') or '').strip()
        acct = (data.get('account_number') or '').strip()

        # try authenticated path first
        from flask import g
        user = getattr(g, 'current_user', None)
        if not user:
            if not acct:
                return jsonify({'success': False, 'message': 'Not logged in and no account_number provided'}), 400
            # find user via SQLAlchemy (prefer app.User)
            try:
                from app import User as AppUser
                user = AppUser.query.filter_by(account_number=acct).first()
            except Exception:
                # last-resort raw-sql
                with get_conn() as conn:
                    cur = conn.cursor()
                    cur.execute("SELECT id, payment_pin, failed_attempts, locked_until FROM users WHERE account_number = ? LIMIT 1", (acct,))
                    row = cur.fetchone()
                    if not row:
                        return jsonify({'success': False, 'message': 'Account not found'}), 404
                    # emulate a user-like object
                    class _Tmp:
                        pass
                    user = _Tmp()
                    # support both dict-like and tuple rows
                    try:
                        user.id = row['id']
                        user.payment_pin = row['payment_pin']
                        user.failed_attempts = row['failed_attempts'] or 0
                        user.locked_until = datetime.fromisoformat(row['locked_until']) if row['locked_until'] else None
                    except Exception:
                        user.id = row[0]
                        user.payment_pin = row[1]
                        user.failed_attempts = row[2] if len(row) > 2 else 0
                        user.locked_until = datetime.fromisoformat(row[3]) if len(row) > 3 and row[3] else None

        if not pin or not pin.isdigit() or len(pin) != (globals().get('PIN_LENGTH') or 4):
            return jsonify({'success': False, 'message': 'Invalid PIN'}), 400

        # check locked
        try:
            if user.locked_until and user.locked_until > datetime.utcnow():
                return jsonify({'success': False, 'message': 'Account locked', 'lockedUntil': user.locked_until.isoformat()}), 403
        except Exception:
            pass

        # verify
        try:
            ok = check_password_hash(user.payment_pin or "", pin)
        except Exception:
            ok = False

        if ok:
            # reset attempts
            try:
                user.failed_attempts = 0
                user.locked_until = None
                # commit to DB if SQLAlchemy-backed
                try:
                    from app import DB as AppDB
                    AppDB.session.add(user)
                    AppDB.session.commit()
                except Exception:
                    try:
                        from models import DB as ModelsDB
                        ModelsDB.session.add(user)
                        ModelsDB.session.commit()
                    except Exception:
                        # raw SQL update
                        with get_conn() as conn:
                            cur = conn.cursor()
                            cur.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", (user.id,))
            except Exception:
                pass
            return jsonify({'success': True, 'message': 'PIN verified'}), 200
        else:
            # increment failed attempts and lock if threshold reached
            try:
                user.failed_attempts = (getattr(user, 'failed_attempts', 0) or 0) + 1
                # threshold from utils or default 4
                threshold = getattr(current_app, 'PIN_LOCK_THRESHOLD', 4)
                if user.failed_attempts >= threshold:
                    user.locked_until = datetime.utcnow() + timedelta(hours=4)
                # persist changes
                try:
                    from app import DB as AppDB
                    AppDB.session.add(user)
                    AppDB.session.commit()
                except Exception:
                    try:
                        from models import DB as ModelsDB
                        ModelsDB.session.add(user)
                        ModelsDB.session.commit()
                    except Exception:
                        with get_conn() as conn:
                            cur = conn.cursor()
                            cur.execute("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                                        (user.failed_attempts, user.locked_until.isoformat() if user.locked_until else None, user.id))
            except Exception:
                pass
            return jsonify({'success': False, 'message': 'Incorrect PIN'}), 401

    except Exception:
        traceback.print_exc()
        return jsonify({'success': False, 'message': 'Server error'}), 500