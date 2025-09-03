# app.py
from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3, os
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import jwt
from functools import wraps

# ---------------- CONFIG ----------------
app = Flask(__name__)
CORS(app)

DB_PATH = os.path.join(os.path.dirname(__file__), "paygo.db")
app.config["SECRET_KEY"] = "super-secret-key-change-this"

def _conn():
    # fresh connection per request
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

# ---------------- DB INIT / SAFE MIGRATIONS ----------------
def init_db():
    conn = _conn()
    c = conn.cursor()
    # users table: keep full_name, username, password, phone, account_number, email, balance, created_at
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        full_name TEXT,
        phone TEXT,
        account_number TEXT,
        email TEXT,
        balance REAL DEFAULT 0,
        created_at TEXT
    )
    """)
    # transactions table: modern shape stores account numbers
    c.execute("""
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_account TEXT,
        receiver_account TEXT,
        amount REAL,
        timestamp TEXT
    )
    """)
    conn.commit()
    conn.close()

init_db()

# ---------------- HELPERS ----------------
def normalize_digits(s: str) -> str:
    if not s: return ""
    return "".join(ch for ch in s if ch.isdigit())

def last_n(s: str, n: int) -> str:
    if not s: return ""
    return s[-n:] if len(s) >= n else s

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get("Authorization", "")
        if auth_header:
            parts = auth_header.split()
            if len(parts) == 2 and parts[0].lower() == "bearer":
                token = parts[1]
        if not token:
            return jsonify({"success": False, "message": "Token is missing"}), 401
        try:
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            current_user = data.get("username")
        except jwt.ExpiredSignatureError:
            return jsonify({"success": False, "message": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"success": False, "message": "Invalid token"}), 401
        return f(current_user, *args, **kwargs)
    return decorated

def create_token(username: str) -> str:
    payload = {"username": username, "exp": datetime.utcnow() + timedelta(hours=1)}
    tok = jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")
    if isinstance(tok, bytes):
        tok = tok.decode("utf-8")
    return tok

def table_has_column(table: str, column: str) -> bool:
    conn = _conn(); c = conn.cursor()
    try:
        rows = c.execute(f"PRAGMA table_info({table})").fetchall()
        cols = [r["name"] for r in rows]
        return column in cols
    finally:
        conn.close()

# ---------------- ROUTES ----------------

@app.route("/register", methods=["POST"])
def register():
    data = request.json or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    full_name = (data.get("full_name") or username).strip()
    phone_raw = (data.get("phone") or "").strip()
    email = (data.get("email") or "").strip()

    if not username or not password or not phone_raw:
        return jsonify({"success": False, "message": "username, password and phone are required"}), 400

    phone_digits = normalize_digits(phone_raw)
    account_number = last_n(phone_digits, 10)

    conn = _conn()
    c = conn.cursor()
    try:
        hashed_pw = generate_password_hash(password)
        created_at = datetime.utcnow().isoformat()
        # START BALANCE = 0.0
        c.execute("""
            INSERT INTO users (username, password, full_name, phone, account_number, email, balance, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (username, hashed_pw, full_name, phone_digits, account_number, email, 0.0, created_at))
        conn.commit()
        return jsonify({"success": True, "message": "User registered"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "message": "User already exists"}), 400
    finally:
        conn.close()

@app.route("/login", methods=["POST"])
def login():
    data = request.json or {}
    # accept either "username" or "loginUsername" for compatibility
    username = (data.get("username") or data.get("loginUsername") or "").strip()
    password = (data.get("password") or data.get("loginPassword") or "").strip()

    if not username or not password:
        return jsonify({"success": False, "message": "username and password are required"}), 400

    conn = _conn()
    c = conn.cursor()
    c.execute("SELECT password FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()

    if not row:
        return jsonify({"success": False, "message": "User not found"}), 404

    hashed_pw = row["password"]
    if not check_password_hash(hashed_pw, password):
        return jsonify({"success": False, "message": "Invalid password"}), 401

    token = create_token(username)
    return jsonify({"success": True, "message": "Login successful", "token": token}), 200

@app.route("/user/profile", methods=["GET"])
@token_required
def profile(current_user):
    conn = _conn(); c = conn.cursor()
    c.execute("SELECT username, full_name, phone, account_number, email, balance, created_at FROM users WHERE username=?", (current_user,))
    row = c.fetchone()
    conn.close()
    if row:
        return jsonify({
            "success": True,
            "username": row["username"],
            "full_name": row["full_name"],
            "phone": row["phone"],
            "account_number": row["account_number"],
            "email": row["email"],
            "balance": row["balance"],
            "created_at": row["created_at"]
        }), 200
    return jsonify({"success": False, "message": "User not found"}), 404

# public lookup endpoint for quick preview by account number (used by frontend)
@app.route("/user/lookup", methods=["GET"])
def user_lookup():
    account = (request.args.get("account") or "").strip()
    if not account:
        return jsonify({"success": False, "message": "account query param required"}), 400
    digits = normalize_digits(account)
    acct = last_n(digits, 10)
    conn = _conn(); c = conn.cursor()
    c.execute("SELECT username, full_name, account_number FROM users WHERE account_number=?", (acct,))
    row = c.fetchone()
    conn.close()
    if row:
        return jsonify({"success": True, "username": row["username"], "full_name": row["full_name"], "account_number": row["account_number"]}), 200
    return jsonify({"success": False, "message": "Account not found"}), 404

@app.route("/balance", methods=["GET"])
@token_required
def balance(current_user):
    conn = _conn(); c = conn.cursor()
    c.execute("SELECT balance FROM users WHERE username=?", (current_user,))
    row = c.fetchone()
    conn.close()
    if row:
        return jsonify({"success": True, "username": current_user, "balance": row["balance"]}), 200
    return jsonify({"success": False, "message": "User not found"}), 404

@app.route("/transfer", methods=["POST"])
@token_required
def transfer(current_user):
    data = request.json or {}
    receiver_raw = (data.get("receiver") or "").strip()
    try:
        amount = float(data.get("amount"))
    except Exception:
        return jsonify({"success": False, "message": "receiver and numeric amount are required"}), 400

    if not receiver_raw:
        return jsonify({"success": False, "message": "receiver is required"}), 400
    if amount <= 0:
        return jsonify({"success": False, "message": "Amount must be greater than 0"}), 400

    # Normalize receiver account: accept raw digits or account
    recv_digits = normalize_digits(receiver_raw)
    recv_acct = last_n(recv_digits, 10)
    conn = _conn(); c = conn.cursor()

    # get sender details
    c.execute("SELECT username, balance, full_name, account_number FROM users WHERE username=?", (current_user,))
    s_row = c.fetchone()
    if not s_row:
        conn.close()
        return jsonify({"success": False, "message": "Sender not found"}), 404
    s_balance = s_row["balance"]
    s_name = s_row["full_name"]
    s_acct = s_row["account_number"]

    # find receiver by account_number
    c.execute("SELECT username, balance, full_name, account_number FROM users WHERE account_number=?", (recv_acct,))
    r_row = c.fetchone()
    if not r_row:
        conn.close()
        return jsonify({"success": False, "message": "Receiver not found"}), 404

    # Prevent self transfer (by account)
    if r_row["username"] == current_user:
        conn.close()
        return jsonify({"success": False, "message": "Cannot transfer to self"}), 400

    if s_balance < amount:
        conn.close()
        return jsonify({"success": False, "message": "Insufficient funds"}), 400

    try:
        # Update balances (sender by username, receiver by account_number)
        c.execute("UPDATE users SET balance = balance - ? WHERE username=?", (amount, current_user))
        c.execute("UPDATE users SET balance = balance + ? WHERE account_number=?", (amount, recv_acct))

        # Insert transaction — modern shape uses sender_account / receiver_account
        timestamp = datetime.utcnow().isoformat()
        c.execute("INSERT INTO transactions (sender_account, receiver_account, amount, timestamp) VALUES (?, ?, ?, ?)",
                  (s_acct, recv_acct, amount, timestamp))
        conn.commit()

        # fetch updated balances
        c.execute("SELECT balance FROM users WHERE username=?", (current_user,))
        new_sender_balance = c.fetchone()["balance"]
        c.execute("SELECT balance FROM users WHERE account_number=?", (recv_acct,))
        new_receiver_balance = c.fetchone()["balance"]
    finally:
        conn.close()

    return jsonify({
        "success": True,
        "message": "Transfer successful",
        "sender": {"username": current_user, "full_name": s_name, "account_number": s_acct, "balance": new_sender_balance},
        "receiver": {"username": r_row["username"], "full_name": r_row["full_name"], "account_number": recv_acct, "balance": new_receiver_balance}
    }), 200

@app.route("/transactions", methods=["GET"])
@token_required
def transactions(current_user):
    conn = _conn(); c = conn.cursor()
    # fetch current user's account number
    c.execute("SELECT account_number FROM users WHERE username=?", (current_user,))
    ur = c.fetchone()
    if not ur:
        conn.close()
        return jsonify({"success": False, "message": "User not found"}), 404
    acct = ur["account_number"]

    # Query modern transactions (sender_account / receiver_account)
    c.execute("""
        SELECT t.sender_account, su.full_name as sender_name,
               t.receiver_account, ru.full_name as receiver_name,
               t.amount, t.timestamp
        FROM transactions t
        LEFT JOIN users su ON su.account_number = t.sender_account
        LEFT JOIN users ru ON ru.account_number = t.receiver_account
        WHERE t.sender_account=? OR t.receiver_account=?
        ORDER BY timestamp DESC
    """, (acct, acct))
    rows = c.fetchall()
    conn.close()

    txns = []
    for r in rows:
        txns.append({
            "sender_account": r["sender_account"],
            "sender_name": r["sender_name"] or r["sender_account"],
            "receiver_account": r["receiver_account"],
            "receiver_name": r["receiver_name"] or r["receiver_account"],
            "amount": r["amount"],
            "timestamp": r["timestamp"]
        })
    return jsonify({"success": True, "transactions": txns}), 200

# ---------------- RUN ----------------
if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))