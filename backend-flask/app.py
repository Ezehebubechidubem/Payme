from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)
CORS(app)

# Database
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(BASE_DIR, "payme.db")
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{db_path}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    account_number = db.Column(db.String(10), unique=True, nullable=False)
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

# Helpers
def normalize_phone(phone):
    digits = "".join([c for c in phone if c.isdigit()])
    return digits[-10:] if len(digits) >= 10 else None

def ensure_db():
    db.create_all()

# Routes
@app.route("/")
def home():
    return jsonify({"message":"PayMe API running"}), 200

# Register
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    phone_raw = (data.get("phone") or "").strip()
    password = data.get("password") or ""

    if not username or not phone_raw or not password:
        return jsonify({"message":"All fields required"}), 400

    phone_digits = normalize_phone(phone_raw)
    if not phone_digits or len(phone_digits) != 10:
        return jsonify({"message":"Phone must be at least 10 digits"}), 400

    account_number = phone_digits[-10:]

    if User.query.filter((User.username.ilike(username)) | (User.phone==phone_digits) | (User.account_number==account_number)).first():
        return jsonify({"message":"Username, phone or account already exists"}), 400

    pwd_hash = generate_password_hash(password)
    user = User(username=username, phone=phone_digits, account_number=account_number, password_hash=pwd_hash)
    db.session.add(user)
    db.session.commit()
    return jsonify({"message":"Registration successful"}), 201

# Login
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    identifier = (data.get("identifier") or "").strip()
    password = data.get("password") or ""

    if not identifier or not password:
        return jsonify({"message":"Identifier and password required"}), 400

    user = None
    phone = normalize_phone(identifier)
    if phone:
        user = User.query.filter((User.phone==phone) | (User.account_number==phone)).first()
    if not user:
        user = User.query.filter(User.username.ilike(identifier)).first()

    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"message":"Invalid credentials"}), 401

    return jsonify({"message":"Login successful", "user": user.to_dict()}), 200

# Update profile
@app.route("/update-profile", methods=["POST"])
def update_profile():
    data = request.get_json() or {}
    user_id = data.get("userId")
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    user = User.query.get(user_id)
    if not user: return jsonify({"message":"User not found"}), 404

    if username:
        if User.query.filter(User.username.ilike(username), User.id != user.id).first():
            return jsonify({"message":"Username already taken"}), 400
        user.username = username
    if password:
        user.password_hash = generate_password_hash(password)

    db.session.commit()
    return jsonify({"message":"Profile updated", "user": user.to_dict()}), 200

# Add money
@app.route("/update-balance", methods=["POST"])
def update_balance():
    data = request.get_json() or {}
    user_id = data.get("userId")
    amount = data.get("amount")
    try: amount = float(amount)
    except: return jsonify({"message":"Invalid amount"}), 400
    if amount <= 0: return jsonify({"message":"Amount must be positive"}), 400

    user = User.query.get(user_id)
    if not user: return jsonify({"message":"User not found"}), 404

    user.balance += amount
    db.session.add(Transaction(user_id=user.id, type="deposit", amount=amount, details="Wallet top-up"))
    db.session.commit()
    return jsonify({"message":f"₦{amount} added", "balance": round(user.balance,2)}), 200

# Send money to another user
@app.route("/send", methods=["POST"])
def send():
    data = request.get_json() or {}
    sender_id = data.get("userId")
    amount = data.get("amount")
    receiver_id = data.get("receiverId")

    try: amount = float(amount)
    except: return jsonify({"message":"Invalid amount"}), 400

    sender = User.query.get(sender_id)
    receiver = User.query.get(receiver_id)
    if not sender or not receiver: return jsonify({"message":"User not found"}),404
    if sender.id == receiver.id: return jsonify({"message":"Cannot send to self"}),400
    if sender.balance < amount: return jsonify({"message":"Insufficient balance"}),400

    sender.balance -= amount
    receiver.balance += amount

    db.session.add(Transaction(user_id=sender.id, type="send", amount=amount, details=f"Sent to {receiver.username}", counterparty_id=receiver.id))
    db.session.add(Transaction(user_id=receiver.id, type="receive", amount=amount, details=f"Received from {sender.username}", counterparty_id=sender.id))
    db.session.commit()

    return jsonify({"message":f"₦{amount} sent to {receiver.username}", "balance": round(sender.balance,2)}), 200

# Get all users (for frontend live search)
@app.route("/users", methods=["GET"])
def list_users():
    users = User.query.all()
    return jsonify([u.to_dict() for u in users]), 200

# Transaction history
@app.route("/transactions/<int:user_id>", methods=["GET"])
def get_transactions(user_id):
    txs = Transaction.query.filter_by(user_id=user_id).order_by(Transaction.timestamp.desc()).all()
    return jsonify([t.to_dict() for t in txs]), 200

if __name__ == "__main__":
    ensure_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT",5000)), debug=True)