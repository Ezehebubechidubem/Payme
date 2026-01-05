# pin_routes.py
import random
import traceback
import os
from datetime import datetime, timedelta

from flask import Blueprint, request, jsonify, session, g
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity

from utils import get_conn, hash_pin, check_pin, now_iso
from models import init_tables

bp = Blueprint("pin_routes", __name__, url_prefix="/api/pin")

# TTL for 6-digit codes (seconds)
CODE_TTL_SECONDS = int(os.environ.get("PIN_CODE_TTL", 10 * 60))

# Security: lock defaults
LOCK_THRESHOLD = int(os.environ.get("PIN_LOCK_THRESHOLD", 3))
LOCK_HOURS = int(os.environ.get("PIN_LOCK_HOURS", 4))

# Ensure pin-related tables exist
try:
    init_tables()
except Exception:
    # don't crash if init fails here; app will create on next attempt
    traceback.print_exc()


def _row_get(row, key_or_index):
    """
    Helper to read either dict-like rows (Postgres RealDictCursor) or sqlite rows.
    If key_or_index is str, try dict access; otherwise treat as index.
    """
    if row is None:
        return None
    try:
        if isinstance(row, dict):
            return row.get(key_or_index)
        # sqlite3.Row supports mapping by name, but sometimes it's tuple-like
        try:
            return row[key_or_index]
        except Exception:
            # fallback: if key_or_index is string, attempt mapping via row[key]
            if isinstance(key_or_index, str) and hasattr(row, "keys"):
                try:
                    return row[key_or_index]
                except Exception:
                    pass
        # last fallback: if index exists
        if not isinstance(key_or_index, int):
            return None
        return row[key_or_index]
    except Exception:
        return None


def login_required(view):
    """
    Decorator that accepts either:
     - Authorization: Bearer <JWT token> (preferred, optional)
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
                with get_conn() as conn:
                    cur = conn.cursor()
                    cur.execute(
                        "SELECT id, username, phone, account_number, balance FROM users WHERE id = ? LIMIT 1",
                        (int(identity),),
                    )
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
                                "balance": row[4],
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
                        cur.execute(
                            "SELECT id, username, phone, account_number, balance FROM users WHERE id = ? LIMIT 1",
                            (int(user_id),),
                        )
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
                                    "balance": row[4],
                                }
            except Exception:
                user = None

        if not user:
            return jsonify({"success": False, "message": "User not logged in"}), 401

        g.current_user = user
        return view(*args, **kwargs)

    return wrapped


# ---------------- Helpers: ensure columns for lock/tracking ----------------
def _ensure_user_pins_columns():
    """
    Best-effort: add failed_attempts and locked_until columns to user_pins table if missing.
    Errors are ignored to avoid crashing production.
    """
    try:
        with get_conn() as conn:
            cur = conn.cursor()
            # SQLite / Postgres tolerant ALTER attempts inside try/except
            try:
                cur.execute("ALTER TABLE user_pins ADD COLUMN failed_attempts INTEGER DEFAULT 0")
            except Exception:
                pass
            try:
                cur.execute("ALTER TABLE user_pins ADD COLUMN locked_until TEXT DEFAULT NULL")
            except Exception:
                pass
            try:
                conn.commit()
            except Exception:
                pass
    except Exception:
        traceback.print_exc()


# ensure schema columns exist (best-effort)
try:
    _ensure_user_pins_columns()
except Exception:
    pass


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
            cur.execute(
                "INSERT INTO pin_codes (account_number, code, expires_at) VALUES (?, ?, ?)",
                (acct, code, expires_at),
            )
        # Return code for dev/testing (do not do this in production)
        return jsonify({"success": True, "message": "Code generated", "code": code, "expires_at": expires_at}), 200
    except Exception:
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
    """
    user = g.current_user
    try:
        # Try to ensure lock columns exist
        try:
            _ensure_user_pins_columns()
        except Exception:
            pass

        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT up.id, up.failed_attempts, up.locked_until
                FROM user_pins up
                WHERE up.user_id = ?
                LIMIT 1
                """,
                (user["id"],),
            )
            row = cur.fetchone()
            has_pin = bool(row)
            failed = 0
            locked_until = None
            if row:
                failed = _row_get(row, "failed_attempts") if isinstance(row, dict) else (_row_get(row, 1) if len(row) > 1 else 0)
                locked_until = _row_get(row, "locked_until") if isinstance(row, dict) else (_row_get(row, 2) if len(row) > 2 else None)

        locked = False
        lockedUntil = None
        if locked_until:
            try:
                dt = datetime.fromisoformat(locked_until) if isinstance(locked_until, str) else locked_until
                if dt > datetime.utcnow():
                    locked = True
                    lockedUntil = dt.isoformat()
            except Exception:
                pass

        return jsonify({"hasPin": has_pin, "locked": locked, "lockedUntil": lockedUntil, "failedAttempts": int(failed or 0)}), 200
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
        # ensure columns
        try:
            _ensure_user_pins_columns()
        except Exception:
            pass

        with get_conn() as conn:
            cur = conn.cursor()
            # check if existing
            cur.execute("SELECT id FROM user_pins WHERE user_id = ? LIMIT 1", (user["id"],))
            r = cur.fetchone()
            if r:
                # reset failed attempts & locked_until when updating PIN
                cur.execute("UPDATE user_pins SET hashed_pin = ?, created_at = ?, failed_attempts = 0, locked_until = NULL WHERE user_id = ?", (hashed, now_iso(), user["id"]))
                event = "PIN_UPDATED"
            else:
                cur.execute("INSERT INTO user_pins (user_id, hashed_pin, created_at, failed_attempts, locked_until) VALUES (?, ?, ?, ?, ?)", (user["id"], hashed, now_iso(), 0, None))
                event = "PIN_CREATED"
            try:
                conn.commit()
            except Exception:
                pass
        # audit
        try:
            with get_conn() as conn2:
                c2 = conn2.cursor()
                c2.execute(
                    "INSERT INTO pin_audit (user_id, event_type, meta, created_at) VALUES (?, ?, ?, ?)",
                    (user["id"], event, "'method':'setup'", now_iso()),
                )
                try:
                    conn2.commit()
                except Exception:
                    pass
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
    This endpoint validates account exists, checks code, then stores hashed PIN for that user.
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
            user_id = _row_get(urow, 0) if not isinstance(urow, dict) else urow.get("id")

            # find matching code
            cur.execute("SELECT id, code, expires_at FROM pin_codes WHERE account_number = ? AND code = ? LIMIT 1", (account_number, code))
            crow = cur.fetchone()
            if not crow:
                return jsonify({"success": False, "message": "Invalid or expired code"}), 400

            expires_at = _row_get(crow, "expires_at") or _row_get(crow, 2)
            try:
                exp_dt = datetime.fromisoformat(expires_at) if isinstance(expires_at, str) else expires_at
            except Exception:
                exp_dt = datetime.utcnow() - timedelta(seconds=1)
            if exp_dt < datetime.utcnow():
                # remove expired
                code_id = _row_get(crow, "id") or _row_get(crow, 0)
                cur.execute("DELETE FROM pin_codes WHERE id = ?", (code_id,))
                return jsonify({"success": False, "message": "Code expired"}), 400

            # delete used code (single use)
            code_id = _row_get(crow, "id") or _row_get(crow, 0)
            cur.execute("DELETE FROM pin_codes WHERE id = ?", (code_id,))
            try:
                conn.commit()
            except Exception:
                pass

        # update user_pins (use separate conn so commit is separate)
        # ensure columns exist
        try:
            _ensure_user_pins_columns()
        except Exception:
            pass

        hashed = hash_pin(pin)
        with get_conn() as conn2:
            c2 = conn2.cursor()
            c2.execute("SELECT id FROM user_pins WHERE user_id = ? LIMIT 1", (user_id,))
            existing = c2.fetchone()
            if existing:
                c2.execute("UPDATE user_pins SET hashed_pin = ?, created_at = ?, failed_attempts = 0, locked_until = NULL WHERE user_id = ?", (hashed, now_iso(), user_id))
            else:
                c2.execute("INSERT INTO user_pins (user_id, hashed_pin, created_at, failed_attempts, locked_until) VALUES (?, ?, ?, ?, ?)", (user_id, hashed, now_iso(), 0, None))
            # audit
            c2.execute(
                "INSERT INTO pin_audit (user_id, event_type, meta, created_at) VALUES (?, ?, ?, ?)",
                (user_id, "PIN_ASSOCIATE", f"account:{account_number}", now_iso()),
            )
            try:
                conn2.commit()
            except Exception:
                pass
        return jsonify({"success": True, "message": "PIN attached to account successfully"}), 200

    except Exception:
        traceback.print_exc()
        return jsonify({"success": False, "message": "Server error"}), 500


# ---------------- Verify PIN for transaction ----------------
@bp.route("/verify", methods=["POST"])
def verify_pin():
    """
    Body: { account_number: '1234567890', pin: '1234' }
    Returns success true/false. Stateless: no login required.

    Server-side enforces failed-attempt counting and an account lock:
      - LOCK_THRESHOLD attempts allowed (3)
      - lock for LOCK_HOURS hours (4)
    """
    try:
        data = request.get_json() or {}
        account_number = str(data.get("account_number", "")).strip()
        pin = str(data.get("pin", "")).strip()

        if not account_number or not pin:
            return jsonify({"success": False, "message": "Missing account number or PIN"}), 400

        # ensure lock columns exist (best-effort)
        try:
            _ensure_user_pins_columns()
        except Exception:
            pass

        # fetch user pin row + metadata
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT up.hashed_pin, up.failed_attempts, up.locked_until, u.id
                FROM user_pins up
                JOIN users u ON u.id = up.user_id
                WHERE u.account_number = ?
                LIMIT 1
                """,
                (account_number,),
            )
            row = cur.fetchone()

            # If row not found, there is no PIN for this account yet
            if not row:
                return jsonify({"success": False, "message": "PIN not set for this account"}), 404

            # Try to read columns robustly (works with dict-like or tuple rows)
            stored_hash = None
            failed_attempts = None
            locked_until = None
            user_id = None

            if isinstance(row, dict):
                stored_hash = row.get("hashed_pin")
                failed_attempts = row.get("failed_attempts")
                locked_until = row.get("locked_until")
                user_id = row.get("id")
            else:
                # tuple-like: assumed order per SELECT
                # 0 -> hashed_pin, 1 -> failed_attempts, 2 -> locked_until, 3 -> user.id
                try:
                    stored_hash = row[0]
                except Exception:
                    stored_hash = None
                try:
                    failed_attempts = row[1]
                except Exception:
                    failed_attempts = None
                try:
                    locked_until = row[2]
                except Exception:
                    locked_until = None
                try:
                    user_id = row[3]
                except Exception:
                    user_id = None

            # If stored_hash missing -> error
            if not stored_hash:
                return jsonify({"success": False, "message": "PIN data missing"}), 500

            # normalize values
            try:
                failed_attempts = int(failed_attempts or 0)
            except Exception:
                failed_attempts = 0

            # parse locked_until if present
            locked_dt = None
            if locked_until:
                try:
                    locked_dt = datetime.fromisoformat(locked_until) if isinstance(locked_until, str) else locked_until
                except Exception:
                    locked_dt = None

            now = datetime.utcnow()
            # If account is currently locked, prevent verification
            if locked_dt and locked_dt > now:
                return (
                    jsonify({
                        "success": False,
                        "message": "Too many failed attempts. Try again later.",
                        "lockedUntil": locked_dt.isoformat()
                    }),
                    403,
                )

            # check PIN
            ok = check_pin(pin, stored_hash)

                 # update attempt counters & locked state in same connection
            if ok:
                # reset failed attempts / lock
                try:
                    cur.execute("UPDATE user_pins SET failed_attempts = 0, locked_until = NULL WHERE user_id = ?", (user_id,))
                    try:
                        conn.commit()
                    except Exception:
                        pass
                except Exception:
                    # ignore update failures but continue
                    traceback.print_exc()
            else:
                # increment failed attempts
                failed_attempts = (failed_attempts or 0) + 1
                new_locked_until = None
                if failed_attempts >= LOCK_THRESHOLD:
                    new_locked_until_dt = now + timedelta(hours=LOCK_HOURS)
                    new_locked_until = new_locked_until_dt.isoformat()
                try:
                    cur.execute(
                        "UPDATE user_pins SET failed_attempts = ?, locked_until = ? WHERE user_id = ?",
                        (failed_attempts, new_locked_until, user_id),
                    )
                    try:
                        conn.commit()
                    except Exception:
                        pass
                except Exception:
                    traceback.print_exc()

        # audit the attempt (separate conn so it won't be affected by above)
        try:
            with get_conn() as conn2:
                c2 = conn2.cursor()
                c2.execute(
                    "INSERT INTO pin_audit (user_id, event_type, meta, created_at) VALUES (?, ?, ?, ?)",
                    (user_id, "PIN_VERIFY_SUCCESS" if ok else "PIN_VERIFY_FAIL", f"account:{account_number}", now_iso()),
                )
                try:
                    conn2.commit()
                except Exception:
                    pass
        except Exception:
            # audit failure shouldn't break verification
            traceback.print_exc()

        if ok:
            return jsonify({"success": True, "message": "PIN verified successfully"}), 200
        else:
            # If we just locked the account, return 403 with lockedUntil
            if failed_attempts >= LOCK_THRESHOLD:
                locked_until_iso = (now + timedelta(hours=LOCK_HOURS)).isoformat()
                return (
                    jsonify({
                        "success": False,
                        "message": "Too many failed attempts. Account locked.",
                        "lockedUntil": locked_until_iso
                    }),
                    403,
                )
            # normal invalid PIN
            return jsonify({"success": False, "message": "Invalid PIN"}), 401

    except Exception as e:
        traceback.print_exc()
        return jsonify({"success": False, "message": f"Server error: {str(e)}"}), 500