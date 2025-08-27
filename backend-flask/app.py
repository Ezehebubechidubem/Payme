from flask import Flask, request, jsonify
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

# --- Helpers ---
def digits_only(s):
    return "".join([c for c in (s or "") if c.isdigit()])

def account_number_from_phone(phone):
    d = digits_only(phone)
    return d[-10:] if len(d) >= 10 else None

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
    except Exception:
        return 1

def now_iso():
    return datetime.utcnow().isoformat() + "Z"

# --- ROUTES ---
@app.route("/")
def home():
    return jsonify({"message": "PayMe API running (Flask)"}), 200

# --- Registration ---
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    username = data.get("username")
    email = data.get("email")
    phone = data.get("phone")
    password = data.get("password")

    if not username or not email or not phone or not password:
        return jsonify({"message": "All fields are required"}), 400

    acc = account_number_from_phone(phone)
    phone_digits = digits_only(phone)
    if not acc or len(acc) != 10 or not is_unique(username, email, phone_digits, acc):
        return jsonify({"message": "Invalid or duplicate account info"}), 400

    user = {
        "id": next_id(),
        "username": username,
        "email": email,
        "phone": phone_digits,
        "accountNumber": acc,
        "password": password,  # Plain text for demo
        "balance": 0,
        "transactions": []
    }
    users.append(user)
    save_users()
    safe_user = {k: v for k, v in user.items() if k != "password"}
    return jsonify({"message": "Registration successful", "user": safe_user}), 201

# --- Login ---
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")
    if not email or not password:
        return jsonify({"message": "Email and password required"}), 400

    user = next((u for u in users if u.get("email","").lower() == email.lower() and u.get("password") == password), None)
    if not user:
        return jsonify({"message": "Invalid credentials"}), 400
    safe_user = {k: v for k, v in user.items() if k != "password"}
    return jsonify({"message": "Login successful", "user": safe_user}), 200

# --- Resolve account ---
@app.route("/resolve-account/<accountNumber>", methods=["GET"])
def resolve_account(accountNumber):
    acc = str(accountNumber or "").strip()
    if len(acc) != 10:
        return jsonify({"message": "Account number must be 10 digits"}), 400
    user = find_user_by_account(acc)
    if not user:
        return jsonify({"exists": False, "name": None, "id": None}), 200
    return jsonify({"exists": True, "name": user.get("username"), "id": user.get("id")}), 200

# --- Add Money ---
@app.route("/update-balance", methods=["POST"])
def update_balance():
    data = request.get_json() or {}
    try:
        userId = int(data.get("userId"))
        amount = float(data.get("amount"))
    except Exception:
        return jsonify({"message": "Invalid input"}), 400

    user = find_user_by_id(userId)
    if not user:
        return jsonify({"message": "User not found"}), 404
    if amount <= 0:
        return jsonify({"message": "Amount must be positive"}), 400

    user["balance"] += amount
    user.setdefault("transactions", []).append({
        "type": "add",
        "amount": amount,
        "timestamp": now_iso(),
        "details": "Wallet top-up"
    })
    save_users()
    return jsonify({"message": f"₦{amount} added successfully", "balance": user["balance"]}), 200

# --- Send to another wallet ---
@app.route("/send", methods=["POST"])
def send():
    data = request.get_json() or {}
    try:
        sender_id = int(data.get("userId"))
        receiver_id = int(data.get("receiverId"))
        amount = float(data.get("amount"))
    except Exception:
        return jsonify({"message": "Invalid input"}), 400

    sender = find_user_by_id(sender_id)
    receiver = find_user_by_id(receiver_id)
    if not sender or not receiver:
        return jsonify({"message": "User not found"}), 404
    if sender['id'] == receiver['id']:
        return jsonify({"message": "Cannot send to self"}), 400
    if sender['balance'] < amount:
        return jsonify({"message": "Insufficient balance"}), 400

    sender['balance'] -= amount
    receiver['balance'] += amount
    ts = now_iso()
    sender.setdefault("transactions", []).append({
        "type": "send",
        "amount": amount,
        "timestamp": ts,
        "details": f"Sent to {receiver.get('username')} ({receiver.get('accountNumber')})"
    })
    receiver.setdefault("transactions", []).append({
        "type": "receive",
        "amount": amount,
        "timestamp": ts,
        "details": f"Received from {sender.get('username')} ({sender.get('accountNumber')})"
    })
    save_users()
    return jsonify({"message": f"₦{amount} sent to {receiver['username']}", "balance": sender['balance']}), 200

# --- Send to Bank ---
@app.route('/send-to-bank', methods=['POST'])
def send_to_bank():
    data = request.json
    try:
        sender_id = int(data.get('userId'))
        amount = float(data.get('amount'))
        bank_name = data.get('bankName')
        account_number = data.get('accountNumber')
    except Exception:
        return jsonify({'message': 'Invalid input'}), 400

    sender = find_user_by_id(sender_id)
    if not sender:
        return jsonify({'message': 'User not found'}), 404
    if sender['balance'] < amount:
        return jsonify({'message': 'Insufficient funds'}), 400

    sender['balance'] -= amount
    ts = now_iso()
    sender.setdefault("transactions", []).append({
        "type": "send-to-bank",
        "amount": amount,
        "timestamp": ts,
        "details": f"Sent to {bank_name} ({account_number})"
    })
    save_users()
    return jsonify({'message': f'₦{amount} sent to {bank_name} ({account_number})', 'balance': sender['balance']}), 200

# --- Optional DB dump for debugging ---
@app.route("/_db", methods=["GET"])
def dump_db():
    return jsonify(users), 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
