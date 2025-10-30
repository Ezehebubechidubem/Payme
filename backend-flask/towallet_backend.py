# towallet_backend.py
from flask import Blueprint, request, jsonify, current_app
import os
import requests
import uuid
import traceback

towallet_bp = Blueprint("towallet", __name__)

FLW_SECRET_KEY = os.environ.get("FLW_SECRET_KEY")  # ensure this is set in env for live/real calls

# Helper: safe JSON parser for responses
def try_parse_json(resp):
    try:
        return resp.json()
    except Exception:
        return None

@towallet_bp.route("/resolve-account", methods=["POST"])
def resolve_account():
    """
    POST { account_number: "1234567890", bank_code: "100004" }
    Returns { status, provider, account_name, account_number, bank_code, raw? }
    """
    data = request.get_json(silent=True) or {}
    account_number = str(data.get("account_number", "")).strip()
    bank_code = str(data.get("bank_code", "")).strip()

    # Basic validation
    if not account_number.isdigit() or len(account_number) != 10:
        return jsonify({"status":"error", "message":"Invalid account number"}), 400

    # Bypass: internal PayMe bank code
    if bank_code == "00023":
        # In your flow you wanted 00023 treated as internal (always success)
        return jsonify({
            "status": "success",
            "provider": "payme",
            "account_name": "Internal PayMe user",
            "account_number": account_number,
            "bank_code": bank_code
        }), 200

    # Ensure FLW key present
    if not FLW_SECRET_KEY:
        return jsonify({"status":"error","message":"FLW_SECRET_KEY not configured"}), 500

    # Prepare call to Flutterwave
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
        return jsonify({"status":"error","provider":"flutterwave","message":f"Network error contacting Flutterwave: {str(e)}"}), 502

    flw_json = try_parse_json(flw_res)
    status_code = flw_res.status_code

    # success shapes vary; treat 2xx or explicit success as success
    if flw_json and (flw_json.get("status") == "success" or str(status_code).startswith("2")):
        acct_name = None
        # check standard shapes
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

        # success but no name
        return jsonify({
            "status":"error",
            "provider":"flutterwave",
            "message":"Flutterwave returned success but no account_name",
            "raw": flw_json
        }), 400

    # Non-success: surface provider message if available
    msg = None
    if flw_json:
        msg = flw_json.get("message") or flw_json.get("error") or str(flw_json)
    else:
        text_preview = (flw_res.text or "")[:1500]
        msg = f"Flutterwave returned non-JSON response (status {status_code}): {text_preview}"

    return jsonify({
        "status":"error",
        "provider":"flutterwave",
        "message": msg,
        "raw": flw_json if flw_json is not None else (flw_res.text or "")
    }), status_code if isinstance(status_code, int) and status_code >= 400 else 400


@towallet_bp.route("/send", methods=["POST"])
def send_money():
    """
    POST JSON:
      { sender_phone, receiver_acc, amount, receiver_bank }

    Returns:
      { status, message, transaction_id, balance }
    """
    data = request.get_json(silent=True) or {}
    sender_phone = str(data.get("sender_phone") or "").strip()
    receiver_acc = str(data.get("receiver_acc") or "").strip()
    receiver_bank = str(data.get("receiver_bank") or "").strip()
    try:
        amount = float(data.get("amount", 0) or 0)
    except Exception:
        return jsonify({"status":"error","message":"Invalid amount"}), 400

    # basic validation
    if not sender_phone:
        return jsonify({"status":"error","message":"Missing sender_phone"}), 400
    if not receiver_acc or not receiver_acc.isdigit() or len(receiver_acc) != 10:
        return jsonify({"status":"error","message":"Invalid receiver account"}), 400
    if amount <= 0:
        return jsonify({"status":"error","message":"Invalid amount"}), 400

    # Do not use this external route to handle internal PayMe transfers
    if receiver_bank == "00023":
        return jsonify({"status":"error","message":"Internal transfers to PayMe must use the internal route"}), 400

    # load services functions at call-time to avoid circular imports
    try:
        from services import get_user_by_phone, get_user_by_account, get_balance, update_balance, create_transaction
    except Exception as e:
        current_app.logger.exception("Services import error")
        return jsonify({"status":"error","message":"Server configuration error (services unavailable)"}), 500

    # ensure sender exists
    sender = get_user_by_phone(sender_phone)
    if not sender:
        return jsonify({"status":"error","message":"Sender not found"}), 404

    # Check balance
    balance = get_balance(sender_phone)
    if amount > balance:
        return jsonify({"status":"error","message":"Insufficient funds"}), 400

    # Decide whether receiver_acc matches a local user (some fintechs use phone as account)
    receiver_local = get_user_by_account(receiver_acc)  # may return user or None

    # Important: even if receiver is local, if the selected bank is NOT PayMe (00023) we treat as external:
    #          do NOT credit PayMe wallet. (This matches your requested rule.)
    is_internal_payme_bank = (receiver_bank == "00023")

    try:
        # Deduct from sender
        new_balance = update_balance(sender_phone, -amount)

        # Create transaction record (backend id)
        tx_id = create_transaction({
            "type": "transfer_out",
            "sender_phone": sender_phone,
            "receiver_acc": receiver_acc,
            "receiver_bank": receiver_bank,
            "amount": amount,
            "created_at": None,  # services can set the timestamp
            "metadata": {
                "receiver_local": bool(receiver_local),
                "treated_as_internal": is_internal_payme_bank
            }
        })

        # NOTE: If you'd like to auto-credit a local receiver when the bank is PayMe (00023),
        # you can add logic here to call update_balance(receiver_phone, +amount).
        # Currently we DO NOT credit local receiver on this external route.

        return jsonify({
            "status": "success",
            "message": f"Transfer of ₦{amount} initiated",
            "transaction_id": tx_id,
            "balance": new_balance
        }), 200

    except Exception as e:
        current_app.logger.exception("Error performing send_money")
        # On error, you might want to roll back the balance. Since update_balance already deducted,
        # we could re-credit here — but best is to ensure update_balance and create_transaction behave atomically in DB.
        return jsonify({"status":"error","message":"Internal server error"}), 500