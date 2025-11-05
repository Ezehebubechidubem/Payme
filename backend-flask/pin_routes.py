# pin_routes.py
from flask import Blueprint, request, jsonify
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

# Import from existing app — safe since we do it late
from app import DB, User

from utils import (
    PIN_LENGTH, MAX_FAILED_ATTEMPTS, is_locked, lock_user,
    reset_attempts, hash_pin, verify_pin
)

bp = Blueprint("pin", __name__, url_prefix="/api/pin")


@bp.route("/status", methods=["GET"])
def pin_status():
    account_number = request.args.get("account_number")
    if not account_number:
        return jsonify({"success": False, "message": "Missing account number"}), 400

    user = User.query.filter_by(account_number=account_number).first()
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404

    locked, until = is_locked(user)
    return jsonify({
        "hasPin": bool(user.payment_pin),
        "locked": locked,
        "lockedUntil": until.isoformat() if until else None,
        "failedAttempts": user.failed_attempts
    }), 200


@bp.route("/setup", methods=["POST"])
def setup_pin():
    data = request.get_json() or {}
    account_number = (data.get("account_number") or "").strip()
    pin = (data.get("pin") or "").strip()

    if not account_number or not pin:
        return jsonify({"success": False, "message": "Missing fields"}), 400

    if len(pin) != PIN_LENGTH or not pin.isdigit():
        return jsonify({"success": False, "message": "Invalid PIN"}), 400

    user = User.query.filter_by(account_number=account_number).first()
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404

    hashed = hash_pin(pin)
    user.payment_pin = hashed
    user.failed_attempts = 0
    user.locked_until = None

    DB.session.commit()
    return jsonify({"success": True, "message": "PIN saved successfully"}), 200


@bp.route("/verify", methods=["POST"])
def verify_user_pin():
    data = request.get_json() or {}
    account_number = (data.get("account_number") or "").strip()
    pin = (data.get("pin") or "").strip()

    if not account_number or not pin:
        return jsonify({"success": False, "message": "Missing fields"}), 400

    user = User.query.filter_by(account_number=account_number).first()
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404

    locked, until = is_locked(user)
    if locked:
        return jsonify({
            "success": False,
            "message": f"Account locked until {until.strftime('%Y-%m-%d %H:%M:%S')}"
        }), 403

    if verify_pin(user.payment_pin, pin):
        reset_attempts(user, DB)
        return jsonify({"success": True, "message": "PIN verified"}), 200
    else:
        user.failed_attempts += 1
        if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
            lock_user(user, DB)
            return jsonify({"success": False, "message": "Account temporarily locked"}), 403

        DB.session.commit()
        return jsonify({"success": False, "message": "Incorrect PIN"}), 401