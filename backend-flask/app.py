from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import json
import os
from pathlib import Path
from datetime import datetime

# Paths
BASE_DIR = Path(__file__).resolve().parent
DB_FILE = BASE_DIR / "users.json"

app = Flask(__name__)
CORS(app)

# Load DB
if DB_FILE.exists():
    try:
        with DB_FILE.open("r", encoding="utf-8") as f:
            users = json.load(f)
    except Exception:
        users = []
else:
    users = []

def save_users():
    with DB_FILE.open("w", encoding="utf-8") as f:
        json.dump(users, f, indent=2, ensure_ascii=False)

# Helpers
def digits_only(s):
    return "".join([c for c in (s or "") if c.isdigit()])

def account_number_from_phone(phone):
    d = digits_only(phone)
    if len(d) == 11 and d.startswith("0"):
        return d[1:]
    return d[-10:]

def find_user_by_id(uid):
    return next((u for u in users if int(u.get("id", 0)) == int(uid)), None)

def find_user_by_account(acc):
    return next((u for u in users if u.get("accountNumber") == str(acc)), None)

def is_unique(username, email, phone, acc):
    for u in users:
        if (u.get("username", "").lower() == (username or "").lower() or
            u.get("email", "").lower() == (email or "").lower() or
            u.get("phone") == phone or
            u.get("accountNumber") == acc):
            return False
    return True

def next_id():
    try:
        return max([int(u.get("id", 0)) for u in users]) + 1
    except ValueError:
        return 1
    except Exception:
        return 1

def now_iso():
    return datetime.utcnow().isoformat() + "Z"

# Routes
@app.route("/")
def home():
    return jsonify({"message": "PayMe API running (Flask)"}), 200

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    username = data.get("username")
    email = data.get("email")
    phone = data.get("phone")
    password = data.get("password")

    if not username or not email or not phone or not password:
        return jsonify({"message": "All fields are required: username, email, phone, password"}), 400

    acc = account_number_from_phone(phone)
    if len(acc) != 10:
        return jsonify({"message": "Invalid phone number. Could not derive a 10-digit account number."}), 400

    phone_digits = digits_only(phone)
    if not is_unique(username, email, phone_digits, acc):
        return jsonify({"message": "Username, email, phone or account number already in use"}), 400

    user = {
        "id": next_id(),
        "username": username,
        "email": email,
        "phone": phone_digits,
        "accountNumber": acc,
        "password": password,   # NOTE: plain text for demo only — not safe for production
        "balance": 0,
        "transactions": []
    }
    users.append(user)
    save_users()
    safe_user = {k: v for k, v in user.items() if k != "password"}
    return jsonify({"message": "Registration successful", "user": safe_user}), 201

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")
    if not email or not password:
        return jsonify({"message": "Email and password are required"}), 400

    user = next((u for u in users if u.get("email","").lower() == email.lower() and u.get("password") == password), None)
    if not user:
        return jsonify({"message": "Invalid credentials"}), 400
    safe_user = {k: v for k, v in user.items() if k != "password"}
    return jsonify({"message": "Login successful", "user": safe_user}), 200

@app.route("/update-balance", methods=["POST"])
def update_balance():
    data = request.get_json() or {}
    userId = data.get("userId")
    amount = data.get("amount")
    try:
        uid = int(userId)
        amt = float(amount)
    except Exception:
        return jsonify({"message": "Invalid userId or amount"}), 400

    user = find_user_by_id(uid)
    if not user:
        return jsonify({"message": "User not found"}), 400
    if amt <= 0:
        return jsonify({"message": "Amount must be a positive number"}), 400

    user["balance"] = float(user.get("balance", 0)) + amt
    user.setdefault("transactions", []).append({
        "type": "add",
        "amount": amt,
        "timestamp": now_iso(),
        "details": "Wallet top-up"
    })
    save_users()
    return jsonify({"message": "Money added successfully!", "balance": user["balance"]}), 200

@app.route("/send", methods=["POST"])
def send():
    data = request.get_json() or {}
    try:
        senderId = int(data.get("senderId"))
        receiverAcc = str(data.get("receiverAccountNumber", "")).strip()
        amt = float(data.get("amount"))
    except Exception:
        return jsonify({"message": "Invalid input"}), 400

    sender = find_user_by_id(senderId)
    receiver = find_user_by_account(receiverAcc)
    if not sender:
        return jsonify({"message": "Sender not found"}), 400
    if not receiver:
        return jsonify({"message": "Receiver not found"}), 400
    if sender.get("id") == receiver.get("id"):
        return jsonify({"message": "Cannot send to your own account"}), 400
    if amt <= 0:
        return jsonify({"message": "Amount must be a positive number"}), 400
    if float(sender.get("balance", 0)) < amt:
        return jsonify({"message": "Insufficient balance"}), 400

    sender["balance"] = float(sender.get("balance", 0)) - amt
    receiver["balance"] = float(receiver.get("balance", 0)) + amt
    ts = now_iso()
    sender.setdefault("transactions", []).append({
        "type": "send",
        "amount": amt,
        "timestamp": ts,
        "details": f"Sent to {receiver.get('username')} ({receiver.get('accountNumber')})"
    })
    receiver.setdefault("transactions", []).append({
        "type": "receive",
        "amount": amt,
        "timestamp": ts,
        "details": f"Received from {sender.get('username')} ({sender.get('accountNumber')})"
    })
    save_users()
    return jsonify({"message": f"Sent ₦{amt} to {receiver.get('username')}!", "balance": sender["balance"]}), 200

@app.route("/transfer", methods=["POST"])
def transfer():
    data = request.get_json() or {}
    try:
        uid = int(data.get("userId"))
        amt = float(data.get("amount"))
    except Exception:
        return jsonify({"message": "Invalid input"}), 400

    user = find_user_by_id(uid)
    if not user:
        return jsonify({"message": "User not found"}), 400
    if amt <= 0:
        return jsonify({"message": "Amount must be a positive number"}), 400
    if float(user.get("balance", 0)) < amt:
        return jsonify({"message": "Insufficient balance"}), 400

    user["balance"] = float(user.get("balance", 0)) - amt
    user.setdefault("transactions", []).append({
        "type": "transfer",
        "amount": amt,
        "timestamp": now_iso(),
        "details": "Transfer to bank"
    })
    save_users()
    return jsonify({"message": f"Transferred ₦{amt} to bank!", "balance": user["balance"]}), 200

@app.route("/airtime", methods=["POST"])
def airtime():
    data = request.get_json() or {}
    try:
        uid = int(data.get("userId"))
        amt = float(data.get("amount"))
    except Exception:
        return jsonify({"message": "Invalid input"}), 400

    user = find_user_by_id(uid)
    if not user:
        return jsonify({"message": "User not found"}), 400
    if amt <= 0:
        return jsonify({"message": "Amount must be a positive number"}), 400
    if float(user.get("balance", 0)) < amt:
        return jsonify({"message": "Insufficient balance"}), 400

    user["balance"] = float(user.get("balance", 0)) - amt
    user.setdefault("transactions", []).append({
        "type": "airtime",
        "amount": amt,
        "timestamp": now_iso(),
        "details": "Airtime purchase"
    })
    save_users()
    return jsonify({"message": f"Airtime ₦{amt} purchased!", "balance": user["balance"]}), 200

@app.route("/resolve-account/<accountNumber>", methods=["GET"])
def resolve_account(accountNumber):
    acc = str(accountNumber or "").strip()
    if len(acc) != 10:
        return jsonify({"message": "Account number must be 10 digits"}), 400
    user = find_user_by_account(acc)
    if not user:
        return jsonify({"exists": False, "name": None}), 200
    return jsonify({"exists": True, "name": user.get("username")}), 200

@app.route("/user/<int:uid>", methods=["GET"])
def get_user(uid):
    user = find_user_by_id(uid)
    if not user:
        return jsonify({"message": "User not found"}), 404
    safe_user = {k: v for k, v in user.items() if k != "password"}
    return jsonify(safe_user), 200

# Optional: serve the users.json for debugging (remove in production)
@app.route("/_db", methods=["GET"])
def dump_db():
    return jsonify(users), 200

if __name__ == "__main__":
    # Use PORT environment variable on Render
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
