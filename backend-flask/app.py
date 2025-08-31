# app.py
from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
import re

app = Flask(__name__)
CORS(app)

# --- Database config (SQLite) ---
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///payme.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# --- Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120))
    username = db.Column(db.String(80), unique=True, nullable=False)
    phone = db.Column(db.String(30), unique=True, nullable=False)  # stored digits only
    email = db.Column(db.String(120), unique=True, nullable=True)
    password = db.Column(db.String(200), nullable=False)
    balance = db.Column(db.Float, default=0.0)
    account_number = db.Column(db.String(40), unique=True, nullable=False)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    userId = db.Column(db.Integer, db.ForeignKey("user.id"))
    type = db.Column(db.String(64))  # Deposit, Sent, Received
    amount = db.Column(db.Float)
    date = db.Column(db.String(50))
    sender = db.Column(db.String(120))
    receiver = db.Column(db.String(120))
    details = db.Column(db.String(255))

with app.app_context():
    db.create_all()

# --- Helpers ---
def sanitize_phone(phone):
    if not phone:
        return None
    digits = re.sub(r'\D', '', str(phone))
    return digits or None

def user_to_dict(user):
    return {
        "id": user.id,
        "name": user.name,
        "username": user.username,
        "phone": user.phone,
        "email": user.email,
        "balance": float(user.balance),
        "account_number": user.account_number
    }

# --- Routes ---

@app.route("/")
def home():
    return jsonify({"status": "PayMe backend running"})

# Register: expects JSON { username, number (phone), email, password, name (optional) }
@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json() or {}
    username = data.get("username")
    phone = data.get("number") or data.get("phone")
    email = data.get("email")
    password = data.get("password")
    name = data.get("name") or ""

    if not (username and phone and password):
        return jsonify({"success": False, "message": "username, phone (number) and password are required"}), 400

    phone_digits = sanitize_phone(phone)
    if not phone_digits or len(phone_digits) < 10:
        return jsonify({"success": False, "message": "phone number invalid; need at least 10 digits"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"success": False, "message": "username already taken"}), 400
    if email and User.query.filter_by(email=email).first():
        return jsonify({"success": False, "message": "email already taken"}), 400
    if User.query.filter_by(phone=phone_digits).first():
        return jsonify({"success": False, "message": "phone already registered"}), 400

    base_acct = phone_digits[-10:]
    acct = base_acct
    suffix = 1
    while User.query.filter_by(account_number=acct).first():
        acct = f"{base_acct}{suffix}"
        suffix += 1

    new_user = User(
        name=name,
        username=username,
        phone=phone_digits,
        email=email,
        password=password,
        balance=0.0,
        account_number=acct
    )
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"success": True, "message": "User registered", "user": user_to_dict(new_user)}), 200

# Login: accept { username, number, password } — username OR number (last10) + password
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get("username")
    number = data.get("number") or data.get("phone")
    password = data.get("password")

    if not password:
        return jsonify({"success": False, "message": "password is required"}), 400

    user = None
    if username:
        user = User.query.filter_by(username=username).first()
        if user and user.password != password:
            user = None

    if (not user) and number:
        digits = sanitize_phone(number)
        if digits:
            acct_tail = digits[-10:]
            user = User.query.filter(User.account_number.like(f"{acct_tail}%")).first()
            if user and user.password != password:
                user = None

    if not user:
        return jsonify({"success": False, "message": "Invalid credentials"}), 401

    return jsonify({"success": True, "message": "Login successful", "user": user_to_dict(user)}), 200

# Lookup user by account number for preview before send
@app.route("/user-by-account", methods=["POST"])
def user_by_account():
    data = request.get_json() or {}
    acct = str(data.get("accountNumber") or data.get("account") or data.get("acct") or "")
    if not acct:
        return jsonify({"success": False, "message": "accountNumber required"}), 400
    user = User.query.filter_by(account_number=acct).first()
    if user:
        return jsonify({"success": True, "username": user.username, "userId": user.id}), 200
    return jsonify({"success": False, "message": "User not found"}), 404

# Get user by id (returns user + transactions)
@app.route("/user/<int:user_id>", methods=["GET"])
def get_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404
    txs = Transaction.query.filter_by(userId=user.id).order_by(Transaction.id.desc()).all()
    tx_list = [{"id": t.id, "type": t.type, "amount": t.amount, "date": t.date, "sender": t.sender, "receiver": t.receiver, "details": t.details} for t in txs]
    return jsonify({"success": True, "user": user_to_dict(user), "transactions": tx_list}), 200

# Transactions: POST { userId } or GET ?user_id=
@app.route("/transactions", methods=["GET", "POST"])
def transactions_endpoint():
    if request.method == "GET":
        user_id = request.args.get("user_id") or request.args.get("userId")
    else:
        data = request.get_json() or {}
        user_id = data.get("userId") or data.get("user_id")
    try:
        uid = int(user_id)
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "user_id required"}), 400
    user = User.query.get(uid)
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404
    txs = Transaction.query.filter_by(userId=user.id).order_by(Transaction.id.desc()).all()
    tx_list = [{"id": t.id, "type": t.type, "amount": t.amount, "date": t.date, "sender": t.sender, "receiver": t.receiver, "details": t.details} for t in txs]
    return jsonify(tx_list), 200

# Update balance (deposit): { userId, amount }
@app.route("/update-balance", methods=["POST"])
def update_balance():
    data = request.get_json() or {}
    user_id = data.get("userId") or data.get("user_id")
    try:
        uid = int(user_id)
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "userId required"}), 400
    user = User.query.get(uid)
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404
    try:
        amount = float(data.get("amount", 0))
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "Invalid amount"}), 400
    if amount <= 0:
        return jsonify({"success": False, "message": "Amount must be positive"}), 400
    user.balance = float(user.balance) + amount
    tx = Transaction(type="Deposit", amount=amount, userId=user.id, sender="System", receiver=user.username, date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"), details=f"Deposit ₦{amount}")
    db.session.add(tx)
    db.session.commit()
    return jsonify({"success": True, "message": "Balance updated", "balance": float(user.balance), "user": user_to_dict(user)}), 200

# Transfer by account number: { from_id, to_account, amount }
@app.route("/transfer", methods=["POST"])
def transfer():
    data = request.get_json() or {}
    sender_id = data.get("from_id") or data.get("userId") or data.get("senderId") or data.get("user_id")
    to_account = data.get("to_account") or data.get("to") or data.get("receiverAccount") or data.get("accountNumber")
    try:
        amount = float(data.get("amount", 0))
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "Invalid amount"}), 400
    if not sender_id or not to_account:
        return jsonify({"success": False, "message": "from_id and to_account required"}), 400
    try:
        sid = int(sender_id)
    except (ValueError, TypeError):
        return jsonify({"success": False, "message": "Invalid sender id"}), 400
    sender = User.query.get(sid)
    if not sender:
        return jsonify({"success": False, "message": "Sender not found"}), 404
    receiver = User.query.filter_by(account_number=str(to_account)).first()
    if not receiver:
        return jsonify({"success": False, "message": "Receiver account not found"}), 404
    if amount <= 0:
        return jsonify({"success": False, "message": "Amount must be > 0"}), 400
    if float(sender.balance) < amount:
        return jsonify({"success": False, "message": "Insufficient funds!"}), 400
    sender.balance = float(sender.balance) - amount
    receiver.balance = float(receiver.balance) + amount
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    tx1 = Transaction(type="Sent", amount=amount, userId=sender.id, sender=sender.username, receiver=receiver.username, date=now, details=f"Sent ₦{amount} to {receiver.account_number}")
    tx2 = Transaction(type="Received", amount=amount, userId=receiver.id, sender=sender.username, receiver=receiver.username, date=now, details=f"Received ₦{amount} from {sender.account_number}")
    db.session.add_all([tx1, tx2])
    db.session.commit()
    return jsonify({"success": True, "message": f"₦{amount} sent to {receiver.username}", "new_balance": float(sender.balance), "sender": user_to_dict(sender), "receiver": user_to_dict(receiver)}), 200

# Refresh: returns user + transactions
@app.route("/refresh", methods=["POST"])
def refresh():
    data = request.get_json() or {}
    uid = data.get("userId") or data.get("user_id")
    try:
        uid = int(uid)
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "userId required"}), 400
    user = User.query.get(uid)
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404
    txs = Transaction.query.filter_by(userId=user.id).order_by(Transaction.id.desc()).all()
    tx_list = [{"id": t.id, "type": t.type, "amount": t.amount, "date": t.date, "sender": t.sender, "receiver": t.receiver, "details": t.details} for t in txs]
    return jsonify({"success": True, "message": "refreshed", "balance": float(user.balance), "user": user_to_dict(user), "transactions": tx_list}), 200

# Balance GET
@app.route("/balance", methods=["GET"])
def get_balance():
    uid = request.args.get("user_id") or request.args.get("userId") or request.args.get("username")
    if not uid:
        return jsonify({"success": False, "message": "user_id or username required"}), 400
    user = None
    try:
        user = User.query.get(int(uid))
    except:
        user = User.query.filter_by(username=uid).first()
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404
    return jsonify({"success": True, "balance": float(user.balance), "username": user.username}), 200

if __name__ == "__main__":
    app.run(debug=True)