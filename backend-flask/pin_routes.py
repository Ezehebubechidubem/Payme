# pin_routes.py
from flask import Blueprint, request, jsonify, session, g
from datetime import datetime, timedelta
import random, traceback

from models import DB, User, PinAudit, PinCode
from utils import (
    PIN_LENGTH,
    CODE_TTL_SECONDS,
    hash_pin,
    verify_pin_hash,
    is_locked,
    register_failed_attempt,
    reset_attempts_and_unlock,
    LOCK_DURATION,
    LOCK_THRESHOLD,
)

# Try to import JWT helpers if the main app enabled flask_jwt_extended.
# If not available, fallback is session-based auth.
try:
    from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
    _HAS_JWT = True
except Exception:
    _HAS_JWT = False

bp = Blueprint("pin_routes", __name__, url_prefix="/api/pin")


# -----------------------
# Auth helper (local)
# -----------------------
def _get_user_from_auth():
    """
    Try to get a current user:
      1) If JWT is available and a valid token present, use it (expects identity == user.id)
      2) Fallback to session['user_id'] if present
    Returns SQLAlchemy User instance or None.
    """
    user = None
    # 1) JWT path
    if _HAS_JWT:
        try:
            # verify_jwt_in_request will raise if token invalid; we want to catch and fallback
            verify_jwt_in_request(optional=True)
            identity = get_jwt_identity()
            if identity:
                try:
                    user = User.query.get(int(identity))
                except Exception:
                    user = None
        except Exception:
            user = None

    # 2) Session fallback
    if not user:
        uid = session.get("user_id")
        if uid:
            try:
                user = User.query.get(int(uid))
            except Exception:
                user = None

    return user


def login_required(fn):
    """
    Decorator that requires a logged-in user (jwt or session).
    Sets g.current_user on success.
    """
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = _get_user_from_auth()
        if not user:
            return jsonify({"success": False, "message": "User not logged in"}), 401
        g.current_user = user
        return fn(*args, **kwargs)
    return wrapper


# -----------------------
# Dev / Test endpoint: request a 6-digit code (would be SMS in production)
# POST body: { "account_number": "1234567890" }
# Returns { success: true, code: "123456", expires_at: "ISO" } (dev only)
# -----------------------
@bp.route("/request-code", methods=["POST"])
def request_code():
    try:
        data = request.get_json() or {}
        acct = (data.get("account_number") or "").strip()
        if not acct or not acct.isdigit() or len(acct) not in (10, 11):
            return jsonify({"success": False, "message": "Invalid account_number (expect 10 digits)"}), 400

        # Generate 6-digit code
        code = f"{random.randint(0, 999999):06d}"
        expires_at = datetime.utcnow() + timedelta(seconds=CODE_TTL_SECONDS)

        # Remove existing codes for this account (single active)
        DB.session.query(PinCode).filter_by(account_number=acct).delete()
        DB.session.add(PinCode(account_number=acct, code=code, expires_at=expires_at))
        DB.session.commit()

        # IMPORTANT: in production you would NOT return the code in the API response.
        return jsonify({"success": True, "message": "Code generated", "code": code, "expires_at": expires_at.isoformat()}), 200

    except Exception as e:
        traceback.print_exc()
        DB.session.rollback()
        return jsonify({"success": False, "message": "Server error"}), 500


# -----------------------
# Associate a 4-digit PIN with an account using the 6-digit code (frontend flow)
# POST body: { account_number: "1234567890", code: "123456", pin: "1234" }
# -----------------------
@bp.route("/associate", methods=["POST"])
def associate():
    try:
        data = request.get_json() or {}
        account_number = (data.get("account_number") or "").strip()
        code = (data.get("code") or "").strip()
        pin = (data.get("pin") or "").strip()

        # Basic validation
        if not account_number or not account_number.isdigit() or len(account_number) not in (10, 11):
            return jsonify({"success": False, "message": "Invalid account_number"}), 400
        if not code or not code.isdigit() or len(code) != 6:
            return jsonify({"success": False, "message": "Invalid code"}), 400
        if not pin or not pin.isdigit() or len(pin) != PIN_LENGTH:
            return jsonify({"success": False, "message": f"Invalid PIN (must be {PIN_LENGTH} digits)"}), 400

        # Find user by account_number
        user = User.query.filter_by(account_number=account_number).first()
        if not user:
            return jsonify({"success": False, "message": "Account not found"}), 404

        # Find code row
        code_row = DB.session.query(PinCode).filter_by(account_number=account_number, code=code).first()
        if not code_row:
            return jsonify({"success": False, "message": "Invalid or expired code"}), 400

        # Check expiration
        if code_row.expires_at < datetime.utcnow():
            DB.session.delete(code_row)
            DB.session.commit()
            return jsonify({"success": False, "message": "Code expired"}), 400

        # All good -> consume code and set hashed PIN on user
        DB.session.delete(code_row)
        user.payment_pin = hash_pin(pin)
        user.failed_attempts = 0
        user.locked_until = None
        DB.session.add(user)
        DB.session.add(PinAudit(user_id=user.id, event_type="PIN_SETUP", meta={"method": "associate"}))
        DB.session.commit()

        return jsonify({"success": True, "message": "PIN attached to account successfully"}), 200

    except Exception:
        traceback.print_exc()
        DB.session.rollback()
        return jsonify({"success": False, "message": "Server error"}), 500


# -----------------------
# PIN status for the current user (auth required)
# GET => { hasPin, locked, lockedUntil, failedAttempts }
# -----------------------
@bp.route("/status", methods=["GET"])
@login_required
def status():
    user = g.current_user
    locked, until = is_locked(user)
    return jsonify({
        "hasPin": bool(user.payment_pin),
        "locked": locked,
        "lockedUntil": until.isoformat() if until else None,
        "failedAttempts": user.failed_attempts or 0
    }), 200


# -----------------------
# Setup PIN for logged-in user (auth required)
# POST body: { pin: "1234" }
# -----------------------
@bp.route("/setup", methods=["POST"])
@login_required
def setup_pin():
    try:
        data = request.get_json() or {}
        pin = (data.get("pin") or "").strip()
        if not pin or not pin.isdigit() or len(pin) != PIN_LENGTH:
            return jsonify({"success": False, "message": f"Invalid PIN (must be {PIN_LENGTH} digits)"}), 400

        user = g.current_user
        user.payment_pin = hash_pin(pin)
        user.failed_attempts = 0
        user.locked_until = None
        DB.session.add(user)
        DB.session.add(PinAudit(user_id=user.id, event_type="PIN_SETUP", meta={"method": "setup"}))
        DB.session.commit()

        return jsonify({"success": True, "message": "PIN saved successfully"}), 200

    except Exception:
        traceback.print_exc()
        DB.session.rollback()
        return jsonify({"success": False, "message": "Server error"}), 500


# -----------------------
# Verify a PIN for an account (used before a transaction)
# POST body: { account_number: "...", pin: "1234" }
# Response: success true/false + messages
# -----------------------
@bp.route("/verify", methods=["POST"])
def verify_pin():
    try:
        data = request.get_json() or {}
        account_number = (data.get("account_number") or "").strip()
        pin = (data.get("pin") or "").strip()

        if not account_number or not pin:
            return jsonify({"success": False, "message": "account_number and pin are required"}), 400

        user = User.query.filter_by(account_number=account_number).first()
        if not user:
            return jsonify({"success": False, "message": "Account not found"}), 404

        # locked?
        locked, until = is_locked(user)
        if locked:
            return jsonify({"success": False, "message": "Account locked", "lockedUntil": until.isoformat()}), 403

        # verify hashed pin
        ok = verify_pin_hash(user.payment_pin or "", pin)
        if ok:
            # reset attempts on success
            reset_attempts_and_unlock(user, DB)
            DB.session.add(PinAudit(user_id=user.id, event_type="PIN_VERIFY_SUCCESS", meta=None))
            DB.session.commit()
            return jsonify({"success": True, "message": "PIN verified"}), 200
        else:
            # register failed attempt and maybe lock
            register_failed_attempt(user, DB)
            DB.session.add(PinAudit(user_id=user.id, event_type="PIN_VERIFY_FAIL", meta=None))
            DB.session.commit()
            return jsonify({"success": False, "message": "Incorrect PIN"}), 401

    except Exception:
        traceback.print_exc()
        DB.session.rollback()
        return jsonify({"success": False, "message": "Server error"}), 500