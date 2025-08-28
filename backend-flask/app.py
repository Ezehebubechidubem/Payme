# app.py
from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import os
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent
DB_FILE = BASE_DIR / "users.json"

app = Flask(__name__)
CORS(app)

# Load DB
if DB_FILE.exists():
    try:
        with DB_FILE.open("r", encoding="utf-8") as f:
            users = json.load(f)
    except:
        users = []
else:
    users = []

def save_users():
    with DB_FILE.open("w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)

def next_id():
    try:
        return max([u.get("id",0) for u in users]) + 1
    except:
        return 1

def find_user_by_id(uid):
    return next((u for u in users if u.get("id") == uid), None)

def find_user_by_email(email):
    return next((u for u in users if u.get("email","").lower() == email.lower()), None)

def find_user_by_account(acc):
    return next((u for u in users if u.get("accountNumber") == acc), None)

def account_number_from_phone(phone):
    digits = "".join([c for c in phone if c.isdigit()])
    return digits[-10:] if len(digits) >= 10 else None

def now_iso():
    return datetime.utcnow().isoformat() + "Z"

@app.route("/")
def home():
    return jsonify({"message":"PayMe API running"}),200

# Registration
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    username = data.get("username")
    email = data.get("email")
    phone = data.get("phone")
    password = data.get("password")

    if not username or not email or not phone or not password:
        return jsonify({"message":"All fields required"}),400

    phone_digits = "".join([c for c in phone if c.isdigit()])
    if len(phone_digits) != 11:
        return jsonify({"message":"Phone must be 11 digits"}),400

    acc = account_number_from_phone(phone_digits)  # last 10 digits

    # Check duplicates
    for u in users:
        if (
            u.get("email","").lower() == email.lower()
            or u.get("username","").lower() == username.lower()
            or u.get("phone") == phone_digits
            or u.get("accountNumber") == acc
        ):
            return jsonify({"message":"Email, username, phone, or account already exists"}),400

    user = {
        "id": next_id(),
        "username": username,
        "email": email,
        "phone": phone_digits,
        "accountNumber": acc,
        "password": password,
        "balance": 0.0,
        "transactions": []
    }
    users.append(user)
    save_users()
    safe_user = {k:v for k,v in user.items() if k!="password"}
    return jsonify({"message":"Registration successful","user":safe_user}),201

# Login
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")
    if not email or not password:
        return jsonify({"message":"Email & password required"}),400
    user = find_user_by_email(email)
    if not user or user.get("password") != password:
        return jsonify({"message":"Invalid credentials"}),400
    safe_user = {k:v for k,v in user.items() if k!="password"}
    return jsonify({"message":"Login successful","user":safe_user}),200

# Get user by ID
@app.route("/user/<int:userId>")
def get_user(userId):
    user = find_user_by_id(userId)
    if not user: return jsonify({"message":"User not found"}),404
    safe_user = {k:v for k,v in user.items() if k!="password"}
    return jsonify(safe_user),200

# Add money
@app.route("/update-balance", methods=["POST"])
def update_balance():
    data = request.get_json() or {}
    try:
        userId = int(data.get("userId"))
        amount = float(data.get("amount"))
    except:
        return jsonify({"message":"Invalid input"}),400
    user = find_user_by_id(userId)
    if not user: return jsonify({"message":"User not found"}),404
    if amount <= 0: return jsonify({"message":"Amount must be positive"}),400
    user["balance"] = round(user.get("balance",0.0) + amount, 2)
    user.setdefault("transactions",[]).append({
        "type":"add",
        "amount":amount,
        "timestamp":now_iso(),
        "details":"Wallet top-up"
    })
    save_users()
    return jsonify({"message":f"₦{amount} added","balance":user["balance"]}),200

# Send to another wallet (by receiver account number)
@app.route("/send", methods=["POST"])
def send():
    data = request.get_json() or {}
    try:
        sender_id = int(data.get("userId"))
        receiver_acc = str(data.get("receiverAccount") or "")
        amount = float(data.get("amount"))
    except:
        return jsonify({"message":"Invalid input"}),400

    sender = find_user_by_id(sender_id)
    receiver = find_user_by_account(receiver_acc)
    if not sender: return jsonify({"message":"Sender not found"}),404
    if not receiver: return jsonify({"message":"Receiver not found"}),404
    if sender["id"] == receiver["id"]: return jsonify({"message":"Cannot send to self"}),400
    if amount <= 0: return jsonify({"message":"Amount must be positive"}),400
    if sender["balance"] < amount: return jsonify({"message":"Insufficient balance"}),400

    sender["balance"] = round(sender["balance"] - amount, 2)
    receiver["balance"] = round(receiver["balance"] + amount, 2)
    ts = now_iso()

    sender.setdefault("transactions",[]).append({
        "type":"send",
        "amount":amount,
        "timestamp":ts,
        "details":f"Sent to {receiver.get('username')} ({receiver.get('accountNumber')})"
    })
    receiver.setdefault("transactions",[]).append({
        "type":"receive",
        "amount":amount,
        "timestamp":ts,
        "details":f"Received from {sender.get('username')} ({sender.get('accountNumber')})"
    })
    save_users()
    return jsonify({"message":f"₦{amount} sent to {receiver.get('username')}","balance":sender["balance"]}),200

# Optional: Send to Bank (user-to-user by ID)
@app.route("/send-to-bank", methods=["POST"])
def send_to_bank():
    data = request.get_json() or {}
    try:
        sender_id = int(data.get("senderId"))
        receiver_id = int(data.get("receiverId"))
        amount = float(data.get("amount"))
    except:
        return jsonify({"message":"Invalid input"}),400
    sender = find_user_by_id(sender_id)
    receiver = find_user_by_id(receiver_id)
    if not sender or not receiver: return jsonify({"message":"User not found"}),404
    if amount <= 0: return jsonify({"message":"Amount must be positive"}),400
    if sender["balance"] < amount: return jsonify({"message":"Insufficient funds"}),400

    sender["balance"] = round(sender["balance"] - amount, 2)
    receiver["balance"] = round(receiver["balance"] + amount, 2)
    ts = now_iso()
    sender.setdefault("transactions",[]).append({
        "type":"send-to-bank",
        "amount":amount,
        "timestamp":ts,
        "details":f"Sent to {receiver.get('username')} ({receiver.get('accountNumber')})"
    })
    receiver.setdefault("transactions",[]).append({
        "type":"receive-from-bank",
        "amount":amount,
        "timestamp":ts,
        "details":f"Received from {sender.get('username')} ({sender.get('accountNumber')})"
    })
    save_users()
    return jsonify({"message":f"₦{amount} sent to {receiver['username']}","balance":sender["balance"]}),200

if __name__=="__main__":
    port = int(os.environ.get("PORT", 3000))  # Replit uses PORT env var
    app.run(host="0.0.0.0", port=port, debug=True)