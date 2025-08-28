# app.py
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import re
import os

app = Flask(__name__)
CORS(app)

# SQLite DB (file-based) so data persists across restarts
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(BASE_DIR, "payme.db")
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{db_path}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ---------- Models ----------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    account_number = db.Column(db.String(20), unique=True, nullable=False)  # last 10 digits
    password_hash = db.Column(db.String(128), nullable=False)
    balance = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "phone": self.phone,
            "accountNumber": self.account_number,
            "balance": round(self.balance,2),
            "created_at": self.created_at.isoformat()
        }

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    type = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.String(255))
    counterparty_id = db.Column(db.Integer, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "userId": self.user_id,
            "type": self.type,
            "amount": round(self.amount,2),
            "timestamp": self.timestamp.isoformat(),
            "details": self.details,
            "counterpartyId": self.counterparty_id
        }

# ---------- Helpers ----------
def normalize_phone(phone):
    if not phone:
        return None
    digits = "".join([c for c in phone if c.isdigit()])
    if len(digits) >= 10:
        return digits
    return None

def account_from_phone(phone_digits):
    if not phone_digits:
        return None
    return phone_digits[-10:]

def ensure_db():
    db.create_all()

# ---------- Routes ----------
@app.route("/")
def home():
    return jsonify({"message": "PayMe API running"}), 200

# Register endpoint
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    print("Incoming register data:", data)  # Debugging

    username = (data.get("username") or "").strip()
    phone_raw = (data.get("phone") or "").strip()
    password = data.get("password") or ""

    if not username or not phone_raw or not password:
        return jsonify({"message":"All fields required"}), 400

    phone_digits = normalize_phone(phone_raw)
    if not phone_digits or len(phone_digits) < 10:
        return jsonify({"message":"Phone must contain at least 10 digits"}), 400

    stored_phone = phone_digits
    acc = account_from_phone(phone_digits)
    if not acc:
        return jsonify({"message":"Invalid phone/account"}), 400

    # Check duplicates
    if User.query.filter((User.username.ilike(username)) | (User.phone == stored_phone) | (User.account_number == acc)).first():
        return jsonify({"message":"Username, phone or account already exists"}), 400

    # Create user
    pwd_hash = generate_password_hash(password)
    user = User(username=username, phone=stored_phone, account_number=acc, password_hash=pwd_hash, balance=0.0)
    db.session.add(user)
    db.session.commit()

    return jsonify({"message":"Registration successful", "user": user.to_dict()}), 201

# Login endpoint
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    identifier = (data.get("identifier") or "").strip()
    password = data.get("password") or ""

    if not identifier or not password:
        return jsonify({"message":"Identifier and password required"}), 400

    maybe_phone = normalize_phone(identifier)
    user = None
    if maybe_phone:
        user = User.query.filter((User.phone == maybe_phone) | (User.account_number == maybe_phone[-10:])).first()
    if not user:
        user = User.query.filter(User.username.ilike(identifier)).first()

    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"message":"Invalid credentials"}), 401

    return jsonify({"message":"Login successful", "user": user.to_dict()}), 200

# All your other endpoints remain unchanged...
# (get_user, get_user_by_account, update_profile, update_balance, send, transfer_to_bank,
# service_handler, get_transactions, list_users)

if __name__ == "__main__":
    ensure_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)