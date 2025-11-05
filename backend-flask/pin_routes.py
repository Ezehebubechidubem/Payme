# pin_routes.py
import random
import traceback
from datetime import datetime, timedelta

from flask import Blueprint, request, jsonify, g

from utils import get_conn, CODE_TTL_SECONDS, login_required, audit_event, is_locked
from werkzeug.security import generate_password_hash

# Import models on module load (they don't import app)
from models import DB, User, PinAudit

bp = Blueprint("pin_routes", __name__)

# Ensure pin_codes table exists (works for both SQLite and Postgres via get_conn)
def _ensure_pin_codes_table():
    with get_conn() as conn:
        cur = conn.cursor()
        # Use SQLite-friendly schema; wrapper will handle Postgres placeholders.
        # For Postgres the integer primary key will still work if using SERIAL when DB is set up via SQLAlchemy.
        cur.execute("""
            CREATE TABLE IF NOT EXISTS pin_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_number TEXT NOT NULL,
                code TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
        """)

# Run on import so the table exists
try:
    _ensure_pin_codes_table()
except Exception:
    traceback.print_exc()

@bp.route("/api/pin/request-code", methods=["POST"])
def request_pin_code():
    """
    Dev/testing endpoint to create a 6-digit code for an account_number.
    Body: { "account_number": "1234567890" }
    Returns: { success: true, code: "123456", expires_at: "ISO" }
    (In prod you'd send code by SMS and not return it)
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
            cur.execute("DELETE FROM pin_codes WHERE account_number = ?", (acct,))
            cur.execute(
                "INSERT INTO pin_codes (account_number, code, expires_at) VALUES (?, ?, ?)",
                (acct, code, expires_at),
            )
        # Return the code for development/testing
        return jsonify({"success": True, "message": "Code generated", "code": code, "expires_at": expires_at}), 200
    except Exception:
        traceback.print_exc()
        return jsonify({"success": False, "message": "Failed to generate code"}), 500

@bp.route("/api/pin/status", methods=["GET"])
@login_required
def api_pin_status():
    """
    Returns current user's PIN status and lock state.
    Frontend uses this to decide whether to show PIN creation modal.
    """
    user = g.current_user
    locked, until = is_locked(user)
    return jsonify({
        "hasPin": bool(user.payment_pin),
        "locked": locked,
        "lockedUntil": until.isoformat() if until else None,
        "failedAttempts": user.failed_attempts
    }), 200

@bp.route("/api/pin/setup", methods=["POST"])
@login_required
def setup_pin():
    """
    Setup a 4-digit PIN for the current authenticated user (session or JWT).
    Body: { pin: "1234" }
    """
    data = request.get_json() or {}
    pin = (data.get("pin") or "").strip()
    PIN_LENGTH = 4

    if not pin or not pin.isdigit() or len(pin) != PIN_LENGTH:
        return jsonify({"success": False, "message": "Invalid PIN (must be 4 digits)"}), 400

    try:
        user = g.current_user
        user.payment_pin = generate_password_hash(pin)
        user.failed_attempts = 0
        user.locked_until = None
        DB.session.add(user)
        DB.session.commit()
        audit_event(user, "PIN_SETUP", DB=DB, PinAudit=PinAudit, meta={"method": "setup", "time": datetime.utcnow().isoformat()})
        return jsonify({"success": True, "message": "PIN saved successfully"}), 200
    except Exception:
        traceback.print_exc()
        return jsonify({"success": False, "message": "Server error"}), 500

@bp.route("/api/pin/associate", methods=["POST"])
def pin_associate():
    """
    Associate a created 4-digit PIN with an account using a 6-digit code (frontend flow).
    Body: { account_number: "1234567890", code: "123456", pin: "1234" }
    """
    data = request.get_json() or {}
    account_number = (data.get("account_number") or "").strip()
    code = (data.get("code") or "").strip()
    pin = (data.get("pin") or "").strip()
    PIN_LENGTH = 4

    # Validate inputs
    if not account_number or not account_number.isdigit() or len(account_number) not in (10, 11):
        return jsonify({"success": False, "message": "Invalid account_number"}), 400
    if not code or not code.isdigit() or len(code) != 6:
        return jsonify({"success": False, "message": "Invalid code"}), 400
    if not pin or not pin.isdigit() or len(pin) != PIN_LENGTH:
        return jsonify({"success": False, "message": "Invalid PIN (must be 4 digits)"}), 400

    try:
        # 1) find user by account_number using raw SQL (works across DBs)
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, phone FROM users WHERE account_number = ? LIMIT 1", (account_number,))
            user_row = cur.fetchone()
            if not user_row:
                return jsonify({"success": False, "message": "Account not found"}), 404

            # 2) check code table
            cur.execute("SELECT id, code, expires_at FROM pin_codes WHERE account_number = ? AND code = ? LIMIT 1", (account_number, code))
            code_row = cur.fetchone()
            if not code_row:
                return jsonify({"success": False, "message": "Invalid or expired code"}), 400

            # extract expires_at (row can be dict-like or tuple)
            try:
                expires_at = code_row["expires_at"] if isinstance(code_row, dict) else code_row[2]
                expires_dt = datetime.fromisoformat(expires_at)
            except Exception:
                expires_dt = datetime.utcnow() - timedelta(seconds=1)

            if expires_dt < datetime.utcnow():
                # delete expired code
                cur_id = code_row["id"] if isinstance(code_row, dict) else code_row[0]
                cur.execute("DELETE FROM pin_codes WHERE id = ?", (cur_id,))
                return jsonify({"success": False, "message": "Code expired"}), 400

            # remove used code
            cur_id = code_row["id"] if isinstance(code_row, dict) else code_row[0]
            cur.execute("DELETE FROM pin_codes WHERE id = ?", (cur_id,))

        # 3) update user via SQLAlchemy (keeps audit & other app logic consistent)
        user_obj = User.query.filter_by(account_number=account_number).first()
        if not user_obj:
            return jsonify({"success": False, "message": "Account not found (race)"}), 404

        user_obj.payment_pin = generate_password_hash(pin)
        user_obj.failed_attempts = 0
        user_obj.locked_until = None
        DB.session.add(user_obj)
        DB.session.commit()

        audit_event(user_obj, "PIN_SETUP", DB=DB, PinAudit=PinAudit, meta={"method": "associate", "time": datetime.utcnow().isoformat()})
        return jsonify({"success": True, "message": "PIN attached to account successfully"}), 200

    except Exception:
        traceback.print_exc()
        return jsonify({"success": False, "message": "Server error"}), 500