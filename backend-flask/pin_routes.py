# pin_routes.py
from flask import Blueprint, request, jsonify, session, g
from utils import get_conn, hash_pin, check_pin, now_iso
from models import init_tables
from datetime import datetime, timedelta
import random
import traceback
import os

# jwt helpers (works only if your app initialized flask_jwt_extended.JWTManager)
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity

bp = Blueprint("pin_routes", __name__, url_prefix="/api/pin")

# TTL for 6-digit codes (seconds)
CODE_TTL_SECONDS = int(os.environ.get("PIN_CODE_TTL", 10 * 60))

# Ensure tables exist (safe no-op if already created)
try:
    init_tables()
except Exception:
    pass


def login_required(view):
    """
    Decorator that accepts either:
     - Authorization: Bearer <JWT token> (preferred)
     - session['user_id'] (legacy)
    On success, stores user row in g.current_user (dict-like).
    """
    from functools import wraps
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = None
        # 1) try JWT
        try:
            verify_jwt_in_request(optional=True)
            identity = get_jwt_identity()
            if identity:
                # try to load user row by id
                with get_conn() as conn:
                    cur = conn.cursor()
                    cur.execute("SELECT id, username, phone, account_number, balance FROM users WHERE id = ? LIMIT 1", (int(identity),))
                    row = cur.fetchone()
                    if row:
                        # row may be dict-like (PG) or sqlite Row; normalize to dict
                        if isinstance(row, dict):
                            user = row
                        else:
                            # sqlite row: (id, username, phone, account_number, balance)
                            user = {
                                "id": row[0],
                                "username": row[1],
                                "phone": row[2],
                                "account_number": row[3],
                                "balance": row[4]
                            }
        except Exception:
            user = None

        # 2) fallback to session
        if not user:
            try:
                user_id = session.get("user_id")
                if user_id:
                    with get_conn() as conn:
                        cur = conn.cursor()
                        cur.execute("SELECT id, username, phone, account_number, balance FROM users WHERE id = ? LIMIT 1", (int(user_id),))
                        row = cur.fetchone()
                        if row:
                            if isinstance(row, dict):
                                user = row
                            else:
                                user = {
                                    "id": row[0],
                                    "username": row[1],
                                    "phone": row[2],
                                    "account_number": row[3],
                                    "balance": row[4]
                                }
            except Exception:
                user = None

        if not user:
            return jsonify({"success": False, "message": "User not logged in"}), 401

        g.current_user = user
        return view(*args, **kwargs)
    return wrapped


# ---------------- Dev/testing: request a 6-digit code for account_number --------------
@bp.route("/request-code", methods=["POST"])
def request_pin_code():
    """
    Dev/testing endpoint that generates a 6-digit code for an account number.
    Body: { "account_number": "1234567890" }
    NOTE: in production you would SMS/EMAIL the code instead of returning it.
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
            # delete existing codes for account
            cur.execute("DELETE FROM pin_codes WHERE account_number = ?", (acct,))
            cur.execute("INSERT INTO pin_codes (account_number, code, expires_at) VALUES (?, ?, ?)", (acct, code, expires_at))
        # Return code for dev/testing (do not do this in production)
        return jsonify({"success": True, "message": "Code generated", "code": code, "expires_at": expires_at}), 200
    except Exception as e:
        traceback.print_exc()
        return jsonify({"success": False, "message": "Failed to generate code"}), 500


# ---------------- Status (auth-aware) ----------------
@bp.route("/status", methods=["GET"])
@login_required
def api_pin_status():
    """
    Returns if the authenticated user has a PIN set and basic lock state.
    Response:
      { hasPin: bool, locked: false, lockedUntil: null, failedAttempts: 0 }
    Note: we do not track per-user failedAttempts here beyond audit entries; extend if needed.
    """
    user = g.current_user
    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id FROM user_pins WHERE user_id = ? LIMIT 1", (user["id"],))
            row = cur.fetchone()
            has_pin = bool(row)
        # Minimal lock info (expand if you track attempts)
        return jsonify({
            "hasPin": has_pin,
            "locked": False,
            "lockedUntil": None,
            "failedAttempts": 0
        })
    except Exception:
        traceback.print_exc()
        return jsonify({"success": False, "message": "Server error"}), 500


# ---------------- Setup PIN for authenticated user ----------------
@bp.route("/setup", methods=["POST"])
@login_required
def setup_pin():
    """
    Body: { pin: "1234" }
    Authenticated route (JWT or session). Stores hashed PIN in user_pins.
    """
    data = request.get_json() or {}
    pin = (data.get("pin") or "").strip()
    if not pin or not pin.isdigit() or len(pin) != 4:
        return jsonify({"success": False, "message": "Invalid PIN"}), 400

    user = g.current_user
    hashed = hash_pin(pin)

    try:
        with get_conn() as conn:
            cur = conn.cursor()
            # check if existing
            cur.execute("SELECT id FROM user_pins WHERE user_id = ? LIMIT 1", (user["id"],))
            r = cur.fetchone()
            if r:
                cur.execute("UPDATE user_pins SET hashed_pin = ?, created_at = ? WHERE user_id = ?", (hashed, now_iso(), user["id"]))
                event = "PIN_UPDATED"
            else:
                cur.execute("INSERT INTO user_pins (user_id, hashed_pin, created_at) VALUES (?, ?, ?)", (user["id"], hashed, now_iso()))
                event = "PIN_CREATED"
        # audit
        try:
            with get_conn() as conn2:
                c2 = conn2.cursor()
                c2.execute("INSERT INTO pin_audit (user_id, event_type, meta, created_at) VALUES (?, ?, ?, ?)",
                           (user["id"], event, f"'method':'setup'", now_iso()))
        except Exception:
            pass

        return jsonify({"success": True, "message": "PIN saved successfully"}), 200
    except Exception:
        traceback.print_exc()
        return jsonify({"success": False, "message": "Server error"}), 500


# ---------------- Associate PIN via account_number + code ----------------
@bp.route("/associate", methods=["POST"])
def pin_associate():
    """
    Frontend uses this flow:
      - user creates 4-digit PIN locally
      - frontend requests backend to associate PIN with account by sending:
            { account_number: "1234567890", code: "123456", pin: "1234" }
    This endpoint:
      - validates account exists
      - checks that pin_codes row exists and not expired
      - inserts hashed PIN into user_pins for that user_id (single-use)
      - removes used code from pin_codes
    """
    data = request.get_json() or {}
    account_number = (data.get("account_number") or "").strip()
    code = (data.get("code") or "").strip()
    pin = (data.get("pin") or "").strip()

    if not account_number or not account_number.isdigit() or len(account_number) not in (10, 11):
        return jsonify({"success": False, "message": "Invalid account_number"}), 400
    if not code or not code.isdigit() or len(code) != 6:
        return jsonify({"success": False, "message": "Invalid code"}), 400
    if not pin or not pin.isdigit() or len(pin) != 4:
        return jsonify({"success": False, "message": "Invalid PIN"}), 400

    try:
        with get_conn() as conn:
            cur = conn.cursor()
            # find user by account_number
            cur.execute("SELECT id FROM users WHERE account_number = ? LIMIT 1", (account_number,))
            urow = cur.fetchone()
            if not urow:
                return jsonify({"success": False, "message": "Account not found"}), 404
            user_id = urow["id"] if isinstance(urow, dict) else urow[0]

            # find matching code
            cur.execute("SELECT id, code, expires_at FROM pin_codes WHERE account_number = ? AND code = ? LIMIT 1", (account_number, code))
            crow = cur.fetchone()
            if not crow:
                return jsonify({"success": False, "message": "Invalid or expired code"}), 400

            # parse expiry
            expires_at = crow["expires_at"] if isinstance(crow, dict) else crow[2]
            try:
                from datetime import datetime
                exp_dt = datetime.fromisoformat(expires_at) if isinstance(expires_at, str) else expires_at
            except Exception:
                exp_dt = datetime.utcnow() - timedelta(seconds=1)
            if exp_dt < datetime.utcnow():
                # remove expired
                code_id = crow["id"] if isinstance(crow, dict) else crow[0]
                cur.execute("DELETE FROM pin_codes WHERE id = ?", (code_id,))
                return jsonify({"success": False, "message": "Code expired"}), 400

            # delete used code (single use)
            code_id = crow["id"] if isinstance(crow, dict) else crow[0]
            cur.execute("DELETE FROM pin_codes WHERE id = ?", (code_id,))

        # update user_pins (use a new conn so commit separate)
        hashed = hash_pin(pin)
        with get_conn() as conn2:
            c2 = conn2.cursor()
            c2.execute("SELECT id FROM user_pins WHERE user_id = ? LIMIT 1", (user_id,))
            existing = c2.fetchone()
            if existing:
                c2.execute("UPDATE user_pins SET hashed_pin = ?, created_at = ? WHERE user_id = ?", (hashed, now_iso(), user_id))
            else:
                c2.execute("INSERT INTO user_pins (user_id, hashed_pin, created_at) VALUES (?, ?, ?)", (user_id, hashed, now_iso()))
            # audit
            c2.execute("INSERT INTO pin_audit (user_id, event_type, meta, created_at) VALUES (?, ?, ?, ?)",
                       (user_id, "PIN_ASSOCIATE", f"account:{account_number}", now_iso()))
        return jsonify({"success": True, "message": "PIN attached to account successfully"}), 200

    except Exception:
        traceback.print_exc()
        return jsonify({"success": False, "message": "Server error"}), 500


# ---------------- Verify PIN for transaction ----------------
# ---------------- Verify PIN for transaction ----------------
@bp.route("/verify", methods=["POST"])
def verify_pin_for_tx():
    """
    Body: { account_number: '1234567890', pin: '1234' }
    Supports 10 max failed attempts; locks for 4 hours if exceeded.
    """
    MAX_ATTEMPTS = 10
    LOCK_HOURS = 4

    data = request.get_json() or {}
    account_number = (data.get("account_number") or "").strip()
    pin = (data.get("pin") or "").strip()
    if not account_number or not account_number.isdigit() or not pin or not pin.isdigit():
        return jsonify({"success": False, "message": "Invalid input"}), 400

    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT u.id, up.hashed_pin, up.failed_attempts, up.locked_until
                FROM users u
                JOIN user_pins up ON up.user_id = u.id
                WHERE u.account_number = ?
                LIMIT 1
            """, (account_number,))
            row = cur.fetchone()

            if not row:
                return jsonify({"success": False, "message": "PIN not set for this account"}), 404

            # Normalize data
            if isinstance(row, dict):
                user_id = row["id"]
                hashed = row["hashed_pin"]
                failed = row.get("failed_attempts", 0) or 0
                locked_until = row.get("locked_until")
            else:
                user_id, hashed, failed, locked_until = row[0], row[1], row[2] or 0, row[3]

            # Check if locked
            if locked_until:
                try:
                    lock_time = datetime.fromisoformat(locked_until) if isinstance(locked_until, str) else locked_until
                    if lock_time > datetime.utcnow():
                        remain = lock_time - datetime.utcnow()
                        mins = int(remain.total_seconds() // 60)
                        return jsonify({
                            "success": False,
                            "message": f"Too many failed attempts. Try again in {mins} minutes."
                        }), 403
                except Exception:
                    pass

            ok = check_pin(pin, hashed)

            if ok:
                # Reset failed attempts
                cur.execute("UPDATE user_pins SET failed_attempts = 0, locked_until = NULL WHERE user_id = ?", (user_id,))
                # Audit success
                cur.execute(
                    "INSERT INTO pin_audit (user_id, event_type, meta, created_at) VALUES (?, ?, ?, ?)",
                    (user_id, "PIN_VERIFY_SUCCESS", f"account:{account_number}", now_iso())
                )
                conn.commit()
                return jsonify({"success": True, "message": "PIN verified"}), 200

            else:
                failed += 1
                locked_until_val = None
                msg = "Invalid PIN"
                if failed >= MAX_ATTEMPTS:
                    locked_until_val = (datetime.utcnow() + timedelta(hours=LOCK_HOURS)).isoformat()
                    msg = f"Too many failed attempts. Locked for {LOCK_HOURS} hours."

                cur.execute(
                    "UPDATE user_pins SET failed_attempts = ?, locked_until = ? WHERE user_id = ?",
                    (failed, locked_until_val, user_id)
                )
                # Audit fail
                cur.execute(
                    "INSERT INTO pin_audit (user_id, event_type, meta, created_at) VALUES (?, ?, ?, ?)",
                    (user_id, "PIN_VERIFY_FAIL", f"attempts:{failed}", now_iso())
                )
                conn.commit()

                return jsonify({"success": False, "message": msg}), 401

    except Exception as e:
        traceback.print_exc()
        return jsonify({"success": False, "message": "Server error"}), 500