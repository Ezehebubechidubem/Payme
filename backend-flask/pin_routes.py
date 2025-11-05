# pin_routes.py
import traceback
import random
from datetime import datetime, timedelta

from flask import Blueprint, request, jsonify, current_app, g
from werkzeug.security import generate_password_hash, check_password_hash

# These imports assume you will register this blueprint from your main app
# after DB and models (User) exist. If your app module is named differently,
# change "app" to your module name where DB, User, get_conn, audit_event, login_required live.
from app import DB, User, get_conn, audit_event, login_required, PIN_LENGTH

bp = Blueprint("pin_routes", __name__, url_prefix="/api/pin")

# TTL for 6-digit codes (seconds)
CODE_TTL_SECONDS = 10 * 60


def ensure_pin_codes_table():
    """Create simple pin_codes table (id, account_number, code, expires_at)."""
    try:
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
    except Exception:
        current_app.logger.exception("Failed to ensure pin_codes table")


def ensure_users_pin_columns():
    """
    Add missing columns to users table if they don't exist:
      - payment_pin (text)
      - failed_attempts (integer)
      - locked_until (text/datetime)
    This will try to ALTER TABLE for postgres and sqlite; errors are ignored.
    """
    try:
        with get_conn() as conn:
            cur = conn.cursor()
            # Try to add columns; ignore errors if they already exist
            try:
                cur.execute("ALTER TABLE users ADD COLUMN payment_pin TEXT")
            except Exception:
                pass
            try:
                cur.execute("ALTER TABLE users ADD COLUMN failed_attempts INTEGER DEFAULT 0")
            except Exception:
                pass
            try:
                # store as TEXT (ISO datetime string) to support both sqlite and postgres safely
                cur.execute("ALTER TABLE users ADD COLUMN locked_until TEXT")
            except Exception:
                pass
    except Exception:
        current_app.logger.exception("Failed to ensure users pin columns")


# Ensure tables/columns on import (safe to call; will be no-op if created)
ensure_pin_codes_table()
ensure_users_pin_columns()


@bp.route("/request-code", methods=["POST"])
def request_pin_code():
    """
    Dev/testing endpoint to generate a 6-digit code for an account_number.
    Body: { "account_number": "1234567890" }
    Returns the code (for dev/testing only) and expiration.
    In production you would send the code via SMS and NOT return it.
    """
    data = request.get_json() or {}
    acct = (data.get("account_number") or "").strip()
    if not acct or not acct.isdigit() or len(acct) not in (10, 11):
        return jsonify({"success": False, "message": "Invalid account_number"}), 400

    code = f"{random.randint(0, 999999):06d}"
    expires_at = (datetime.utcnow() + timedelta(seconds=CODE_TTL_SECONDS)).isoformat()

    try:
        with get_conn() as conn:
            cur = conn.cursor()
            # delete previous codes for account (single active code)
            cur.execute("DELETE FROM pin_codes WHERE account_number = ?", (acct,))
            cur.execute(
                "INSERT INTO pin_codes (account_number, code, expires_at) VALUES (?, ?, ?)",
                (acct, code, expires_at),
            )
        # For dev/testing: return code. In prod drop the code from the response.
        return jsonify({"success": True, "code": code, "expires_at": expires_at}), 200
    except Exception:
        current_app.logger.exception("Failed to create pin code")
        return jsonify({"success": False, "message": "Server error"}), 500


@bp.route("/associate", methods=["POST"])
def associate_pin_to_account():
    """
    Endpoint expected by your 'account + 6-digit code' frontend flow.
    Body: { account_number: "1234567890", code: "123456", pin: "1234" }

    Behavior:
      - validate input
      - check account exists
      - check a non-expired code exists in pin_codes table
      - delete code row
      - save hashed 4-digit PIN in users.payment_pin (SQLAlchemy model)
      - audit and return success
    """
    data = request.get_json() or {}
    account_number = (data.get("account_number") or "").strip()
    code = (data.get("code") or "").strip()
    pin = (data.get("pin") or "").strip()

    # validation
    if not account_number or not account_number.isdigit() or len(account_number) not in (10, 11):
        return jsonify({"success": False, "message": "Invalid account_number"}), 400
    if not code or not code.isdigit() or len(code) != 6:
        return jsonify({"success": False, "message": "Invalid code"}), 400
    if not pin or not pin.isdigit() or len(pin) != PIN_LENGTH:
        return jsonify({"success": False, "message": f"Invalid PIN (must be {PIN_LENGTH} digits)"}), 400

    try:
        with get_conn() as conn:
            cur = conn.cursor()
            # find user by account_number
            cur.execute("SELECT id FROM users WHERE account_number = ? LIMIT 1", (account_number,))
            user_row = cur.fetchone()
            if not user_row:
                return jsonify({"success": False, "message": "Account not found"}), 404

            # find code row
            cur.execute(
                "SELECT id, code, expires_at FROM pin_codes WHERE account_number = ? AND code = ? LIMIT 1",
                (account_number, code),
            )
            code_row = cur.fetchone()
            if not code_row:
                return jsonify({"success": False, "message": "Invalid or expired code"}), 400

            # parse expires_at (support dict-like or tuple)
            try:
                expires_at = code_row["expires_at"] if isinstance(code_row, dict) else code_row[2]
                expires_dt = datetime.fromisoformat(expires_at)
            except Exception:
                expires_dt = datetime.utcnow() - timedelta(seconds=1)

            if expires_dt < datetime.utcnow():
                # remove expired
                code_id = code_row["id"] if isinstance(code_row, dict) else code_row[0]
                cur.execute("DELETE FROM pin_codes WHERE id = ?", (code_id,))
                return jsonify({"success": False, "message": "Code expired"}), 400

            # delete the used code (single-use)
            code_id = code_row["id"] if isinstance(code_row, dict) else code_row[0]
            cur.execute("DELETE FROM pin_codes WHERE id = ?", (code_id,))

        # Update via SQLAlchemy so audit_event & other ORM logic works
        user_obj = User.query.filter_by(account_number=account_number).first()
        if not user_obj:
            return jsonify({"success": False, "message": "Account not found (race)"}), 404

        user_obj.payment_pin = generate_password_hash(pin)
        user_obj.failed_attempts = 0
        user_obj.locked_until = None
        DB.session.add(user_obj)
        DB.session.commit()

        audit_event(user_obj, "PIN_SETUP", meta={"method": "associate", "time": datetime.utcnow().isoformat()})
        return jsonify({"success": True, "message": "PIN attached to account successfully"}), 200

    except Exception:
        current_app.logger.exception("Error associating PIN")
        return jsonify({"success": False, "message": "Server error"}), 500


@bp.route("/status", methods=["GET"])
@login_required
def pin_status():
    """
    Auth-aware status endpoint. Uses your existing login_required wrapper.
    Returns JSON:
      { hasPin, locked, lockedUntil, failedAttempts }
    """
    user = g.current_user
    locked = False
    locked_until = None
    try:
        if getattr(user, "locked_until", None):
            try:
                locked_until_dt = user.locked_until
                # if string stored, try parse, else treat as datetime
                if isinstance(locked_until_dt, str):
                    locked_until_dt = datetime.fromisoformat(locked_until_dt)
                locked = locked_until_dt > datetime.utcnow()
                locked_until = locked_until_dt.isoformat()
            except Exception:
                locked = False
                locked_until = None
    except Exception:
        current_app.logger.exception("pin_status error")

    return jsonify({
        "hasPin": bool(getattr(user, "payment_pin", None)),
        "locked": locked,
        "lockedUntil": locked_until,
        "failedAttempts": int(getattr(user, "failed_attempts", 0))
    })


@bp.route("/setup", methods=["POST"])
@login_required
def pin_setup():
    """
    Auth-aware PIN setup for the currently authenticated user (session or JWT).
    Body: { pin: "1234" }
    """
    data = request.get_json() or {}
    pin = (data.get("pin") or "").strip()
    if not pin or not pin.isdigit() or len(pin) != PIN_LENGTH:
        return jsonify({"success": False, "message": "Invalid PIN"}), 400

    try:
        user = g.current_user
        user.payment_pin = generate_password_hash(pin)
        user.failed_attempts = 0
        user.locked_until = None
        DB.session.add(user)
        DB.session.commit()
        audit_event(user, "PIN_SETUP", meta={"method": "setup", "time": datetime.utcnow().isoformat()})
        return jsonify({"success": True, "message": "PIN saved successfully"}), 200
    except Exception:
        current_app.logger.exception("pin_setup error")
        return jsonify({"success": False, "message": "Server error"}), 500


@bp.route("/verify", methods=["POST"])
def pin_verify():
    """
    Verify a 4-digit PIN for a given account_number (use before an operation).
    Body: { account_number: "8167542829", pin: "1234" }
    Returns: { success: true } or 400/401 with message.
    """
    data = request.get_json() or {}
    account_number = (data.get("account_number") or "").strip()
    pin = (data.get("pin") or "").strip()

    if not account_number or not account_number.isdigit() or len(account_number) not in (10, 11):
        return jsonify({"success": False, "message": "Invalid account_number"}), 400
    if not pin or not pin.isdigit() or len(pin) != PIN_LENGTH:
        return jsonify({"success": False, "message": "Invalid PIN"}), 400

    try:
        user = User.query.filter_by(account_number=account_number).first()
        if not user:
            return jsonify({"success": False, "message": "Account not found"}), 404
        if not user.payment_pin:
            return jsonify({"success": False, "message": "No PIN set for this account"}), 400

        # Optional: check lockout
        try:
            if user.locked_until:
                lu = user.locked_until
                if isinstance(lu, str):
                    lu_dt = datetime.fromisoformat(lu)
                else:
                    lu_dt = lu
                if lu_dt > datetime.utcnow():
                    return jsonify({"success": False, "message": "Account locked due to failed attempts"}), 403
        except Exception:
            pass

        ok = check_password_hash(user.payment_pin, pin)
        if ok:
            # reset failed attempts
            user.failed_attempts = 0
            user.locked_until = None
            DB.session.add(user)
            DB.session.commit()
            audit_event(user, "PIN_VERIFY_SUCCESS", meta={"time": datetime.utcnow().isoformat()})
            return jsonify({"success": True}), 200
        else:
            # increment failed attempts and possibly lock
            user.failed_attempts = (user.failed_attempts or 0) + 1
            if user.failed_attempts >= 4:
                # lock for 4 hours (match your LOCK_DURATION)
                from app import LOCK_DURATION  # import here to avoid circular earlier
                user.locked_until = (datetime.utcnow() + LOCK_DURATION).isoformat()
                audit_event(user, "PIN_LOCK", meta={"locked_until": user.locked_until.isoformat() if hasattr(user.locked_until, 'isoformat') else user.locked_until})
            DB.session.add(user)
            DB.session.commit()
            audit_event(user, "PIN_VERIFY_FAIL", meta={"time": datetime.utcnow().isoformat(), "attempts": user.failed_attempts})
            return jsonify({"success": False, "message": "Invalid PIN", "failedAttempts": user.failed_attempts}), 401

    except Exception:
        current_app.logger.exception("pin_verify error")
        return jsonify({"success": False, "message": "Server error"}), 500