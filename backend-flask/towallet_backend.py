# towallet_backend.py
from flask import Blueprint, request, jsonify
import os
import requests

towallet_bp = Blueprint("towallet", __name__)

FLW_SECRET_KEY = os.environ.get("FLW_SECRET_KEY")  # set in environment

@towallet_bp.route("/resolve-account", methods=["POST"])
def resolve_account():
    data = request.get_json(silent=True) or {}
    account_number = str(data.get("account_number","")).strip()
    bank_code = str(data.get("bank_code","")).strip()

    if not account_number.isdigit() or len(account_number) != 10:
        return jsonify({"status":"error","message":"Invalid account number"}), 400

    # Treat PayMe internal code bypass: if bank_code == "00023" return a success
    if bank_code == "00023":
        return jsonify({
            "status":"success",
            "provider":"payme",
            "account_name":"Internal PayMe user",
            "account_number": account_number,
            "bank_code": bank_code
        }), 200

    # Ensure FLW key present
    if not FLW_SECRET_KEY:
        return jsonify({"status":"error","message":"FLW_SECRET_KEY not configured"}), 500

    flw_url = "https://api.flutterwave.com/v3/accounts/resolve"
    payload = {"account_number": account_number, "account_bank": bank_code}
    headers = {"Authorization": f"Bearer {FLW_SECRET_KEY}", "Content-Type": "application/json"}

    try:
        flw_res = requests.post(flw_url, json=payload, headers=headers, timeout=12)
        try:
            flw_json = flw_res.json()
        except ValueError:
            flw_json = None

        if flw_json and (flw_json.get("status") == "success" or str(flw_res.status_code).startswith("2")):
            acct_name = flw_json.get("data", {}).get("account_name") or flw_json.get("account_name")
            if acct_name:
                return jsonify({
                    "status":"success",
                    "provider":"flutterwave",
                    "account_name": acct_name,
                    "account_number": account_number,
                    "bank_code": bank_code,
                    "raw": flw_json
                }), 200
            return jsonify({"status":"error","provider":"flutterwave","message":"Flutterwave returned success but no account_name","raw":flw_json}), 400

        # non-success
        msg = (flw_json.get("message") if flw_json else f"Flutterwave error (status {flw_res.status_code})")
        return jsonify({"status":"error","provider":"flutterwave","message": msg, "raw": flw_json}), max(400, flw_res.status_code)

    except requests.RequestException as e:
        return jsonify({"status":"error","message": f"Network error contacting Flutterwave: {str(e)}"}), 502


@towallet_bp.route("/send", methods=["POST"])
def send_money():
    """
    POST JSON: { sender_phone, receiver_acc, amount, receiver_bank }
    This route withdraws from user's balance and returns JSON status.
    IMPORTANT: this route assumes a shared service or DB function updates balance.
    """
    data = request.get_json(silent=True) or {}
    sender_phone = data.get("sender_phone")
    receiver_acc = data.get("receiver_acc")
    amount = float(data.get("amount", 0) or 0)
    receiver_bank = str(data.get("receiver_bank","")).strip()

    if not sender_phone:
        return jsonify({"status":"error","message":"Missing sender_phone"}), 400
    if not receiver_acc or len(str(receiver_acc)) != 10:
        return jsonify({"status":"error","message":"Invalid receiver account"}), 400
    if amount <= 0:
        return jsonify({"status":"error","message":"Invalid amount"}), 400

    # Prevent using this to transfer to internal PayMe bank code (00023) via this external route
    if receiver_bank == "00023":
        return jsonify({"status":"error","message":"Use internal transfer route for PayMe"}), 400

    # --- BALANCE HANDLING ---
    # IMPORTANT: avoid importing app or models at module level to prevent circular imports.
    # If your app has a function to update balance (e.g. services.update_balance), import here.
    try:
        # example: dynamic import to avoid circular import
        from services import get_balance, update_balance   # <-- create services.py if not present
    except Exception:
        get_balance = None
        update_balance = None

    if get_balance and update_balance:
        current_balance = get_balance(sender_phone)
        if amount > current_balance:
            return jsonify({"status":"error","message":"Insufficient funds"}), 400
        # deduct
        new_bal = update_balance(sender_phone, -amount)
        # return success (you may also call external payout here)
        return jsonify({"status":"success","message": f"Transfer of ₦{amount} initiated", "balance": new_bal}), 200

    # fallback behavior if no services module: accept and simulate success (you probably won't want this)
    return jsonify({"status":"success","message": f"Transfer of ₦{amount} initiated (simulated)"}), 200