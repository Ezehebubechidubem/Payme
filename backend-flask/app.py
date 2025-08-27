from flask import Flask, request, jsonify
from flask_cors import CORS
import json, os

app = Flask(__name__)
CORS(app)

DB_FILE = "users.json"

# Load DB
if os.path.exists(DB_FILE):
    with open(DB_FILE, "r") as f:
        try:
            users = json.load(f)
        except:
            users = []
else:
    users = []

def save_users():
    with open(DB_FILE, "w") as f:
        json.dump(users, f, indent=2)

def digits_only(s): return "".join([c for c in s if c.isdigit()])

def account_number_from_phone(phone):
    d = digits_only(phone)
    if len(d) == 11 and d.startswith("0"): return d[1:]
    return d[-10:]

def find_user_by_id(uid): return next((u for u in users if u["id"] == uid), None)
def find_user_by_account(acc): return next((u for u in users if u["accountNumber"] == acc), None)

def is_unique(username, email, phone, acc):
    for u in users:
        if (u["username"].lower() == username.lower() or
            u["email"].lower() == email.lower() or
            u["phone"] == phone or
            u["accountNumber"] == acc):
            return False
    return True

def next_id(): return max([u["id"] for u in users], default=0) + 1

@app.route("/")
def home(): return "PayMe API running (Flask)"

@app.post("/register")
def register():
    data = request.json
    username, email, phone, password = [data.get(k) for k in ["username","email","phone","password"]]
    if not username or not email or not phone or not password:
        return jsonify({"message": "All fields are required"}), 400
    acc = account_number_from_phone(phone)
    if len(acc) != 10:
        return jsonify({"message":"Invalid phone number"}), 400
    if not is_unique(username, email, digits_only(phone), acc):
        return jsonify({"message":"Username, email, phone or account already in use"}), 400

    user = {
        "id": next_id(),
        "username": username,
        "email": email,
        "phone": digits_only(phone),
        "accountNumber": acc,
        "password": password,
        "balance": 0,
        "transactions": []
    }
    users.append(user)
    save_users()
    safe_user = {k:v for k,v in user.items() if k!="password"}
    return jsonify({"message":"Registration successful","user":safe_user})

@app.post("/login")
def login():
    data = request.json
    email, password = data.get("email"), data.get("password")
    user = next((u for u in users if u["email"].lower()==email.lower() and u["password"]==password), None)
    if not user: return jsonify({"message":"Invalid credentials"}), 400
    safe_user = {k:v for k,v in user.items() if k!="password"}
    return jsonify({"message":"Login successful","user":safe_user})

@app.post("/update-balance")
def update_balance():
    data = request.json
    uid, amt = int(data.get("userId",0)), float(data.get("amount",0))
    user = find_user_by_id(uid)
    if not user: return jsonify({"message":"User not found"}),400
    if amt<=0: return jsonify({"message":"Amount must be positive"}),400
    user["balance"] += amt
    user["transactions"].append({"type":"add","amount":amt,"details":"Wallet top-up"})
    save_users()
    return jsonify({"message":"Money added successfully!","balance":user["balance"]})

# Other routes (send, transfer, airtime) can be added exactly the same way...
