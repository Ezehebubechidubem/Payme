# towallet_backend.py
from flask import Blueprint, request, jsonify, current_app
import os
import requests
import uuid
import time

towallet_bp = Blueprint("towallet", __name__)

FLW_SECRET_KEY = os.environ.get("FLW_SECRET_KEY")  # Must be set for real Flutterwave calls

def _try_parse_json(resp):
    try:
        return resp.json()
    except Exception:
        return None

@towallet_bp.route("/resolve-account", methods=["POST"])
def resolve_account():
    """
    POST JSON: { account_number, bank_code }
    Returns { status, provider, account_name, account_number, bank_code, raw? }
    """
    data = request.get_json(silent=True) or {}
    account_number = str(data.get("account_number", "")).strip()
    bank_code = str(data.get("bank_code", "")).strip()

    if not account_number.isdigit() or len(account_number) != 10:
        return jsonify({"status":"error","message":"Invalid account number"}), 400

    # Bypass for internal PayMe code
    if bank_code == "00023":
        return jsonify({
            "status":"success",
            "provider":"payme",
            "account_name":"Internal PayMe user",
            "account_number": account_number,
            "bank_code": bank_code
        }), 200

    # Ensure Flutterwave key exists for live resolves
    if not FLW_SECRET_KEY:
        return jsonify({"status":"error","message":"FLW_SECRET_KEY not configured on server"}), 500

    flw_url = "https://api.flutterwave.com/v3/accounts/resolve"
    payload = {"account_number": account_number, "account_bank": bank_code}
    headers = {
        "Authorization": f"Bearer {FLW_SECRET_KEY}",
        "Content-Type": "application/json",
        "User-Agent": "towallet-backend/1.0"
    }

    try:
        flw_res = requests.post(flw_url, json=payload, headers=headers, timeout=12)
    except requests.RequestException as e:
        current_app.logger.exception("Flutterwave network error")
        return jsonify({"status":"error","provider":"flutterwave","message": f"Network error contacting Flutterwave: {str(e)}"}), 502

    flw_json = _try_parse_json(flw_res)
    status_code = flw_res.status_code

    if flw_json and (flw_json.get("status") == "success" or str(status_code).startswith("2")):
        acct_name = None
        if isinstance(flw_json.get("data"), dict):
            acct_name = flw_json["data"].get("account_name") or flw_json["data"].get("accountName")
        if not acct_name:
            acct_name = flw_json.get("account_name") or (flw_json.get("data") or {}).get("account_name")

        if acct_name:
            return jsonify({
                "status":"success",
                "provider":"flutterwave",
                "account_name": acct_name,
                "account_number": account_number,
                "bank_code": bank_code,
                "raw": flw_json
            }), 200

        return jsonify({
            "status":"error",
            "provider":"flutterwave",
            "message":"Flutterwave returned success but no account_name",
            "raw": flw_json
        }), 400

    # Non-success: surface message or text preview
    if flw_json:
        msg = flw_json.get("message") or flw_json.get("error") or str(flw_json)
        raw = flw_json
    else:
        msg = f"Flutterwave returned non-JSON (status {status_code})"
        raw = (flw_res.text or "")[:1500]
    return jsonify({"status":"error","provider":"flutterwave","message": msg, "raw": raw}), status_code if status_code >= 400 else 400


@towallet_bp.route("/send_money", methods=["POST"])
def send_money():
    """
    POST JSON: { sender_phone, receiver_acc, amount, receiver_bank }
    Deducts sender balance and records a transaction.
    Returns: { status, message, transaction_id, balance }
    """
    data = request.get_json(silent=True) or {}
    sender_phone = str(data.get("sender_phone") or "").strip()
    receiver_acc = str(data.get("receiver_acc") or "").strip()
    receiver_bank = str(data.get("receiver_bank") or "").strip()
    try:
        amount = float(data.get("amount", 0) or 0)
    except Exception:
        return jsonify({"status":"error","message":"Invalid amount"}), 400

    # Validate
    if not sender_phone:
        return jsonify({"status":"error","message":"Missing sender_phone"}), 400
    if not receiver_acc or not receiver_acc.isdigit() or len(receiver_acc) != 10:
        return jsonify({"status":"error","message":"Invalid receiver account"}), 400
    if amount <= 0:
        return jsonify({"status":"error","message":"Invalid amount"}), 400

    # Do not process internal PayMe via this external route
    if receiver_bank == "00023":
        return jsonify({"status":"error","message":"Internal transfers to PayMe must use the internal route"}), 400

    # Import services dynamically (avoid circular imports)
    try:
        from services import (
            get_user_by_phone,
            get_user_by_account,
            get_balance,
            update_balance,
            create_transaction,
            log_transaction
        )
    except Exception as e:
        current_app.logger.exception("Missing services module")
        return jsonify({"status":"error","message":"Server configuration error (services unavailable)"}), 500

    # Ensure sender exists
    sender = get_user_by_phone(sender_phone)
    if not sender:
        return jsonify({"status":"error","message":"Sender not found"}), 404

    balance = get_balance(sender_phone)
    if amount > balance:
        # record failed attempt
        log_transaction(sender_phone, receiver_acc, amount, "failed", receiver_bank, "Insufficient funds")
        return jsonify({"status":"error","message":"Insufficient funds"}), 400

    # Determine if receiver maps to a local user (may be a phone used as account)
    receiver_local = get_user_by_account(receiver_acc)  # may be None

    # Deduct and create transaction atomically inside services
    try:
        new_balance = update_balance(sender_phone, -amount)
        tx_id = create_transaction({
            "type": "transfer_out",
            "sender_phone": sender_phone,
            "receiver_acc": receiver_acc,
            "receiver_bank": receiver_bank,
            "amount": amount,
            "status": "initiated",
            "metadata": {
                "receiver_local": bool(receiver_local),
                "treated_as_internal": False  # external route
            }
        })
        # also log a human-friendly history entry
        log_transaction(sender_phone, receiver_acc, amount, "success", receiver_bank, "Transfer initiated")

        return jsonify({
            "status":"success",
            "message": f"Transfer of ₦{amount} initiated",
            "transaction_id": tx_id,
            "balance": new_balance
        }), 200

    except Exception as e:
        current_app.logger.exception("Error processing send_money")
        # Attempt to roll-back would be implemented in DB-backed services.
        return jsonify({"status":"error","message":"Internal server error"}), 500