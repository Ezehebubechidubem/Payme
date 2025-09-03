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
app.config["SECRET_KEY"] = "super-secret-key"  # change to something secure in production

def _conn():
    return sqlite3.connect(DB_PATH)

# ---------------- DB INIT / MIGRATE ----------------
def init_db():
    conn = _conn()
    c = conn.cursor()

    # create users table with columns we need
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

    # create transactions table
    c.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT,
            receiver TEXT,
            amount REAL,
            timestamp TEXT
        )
    """)

    # Ensure columns exist if upgrading from older DB
    # (SQLite ignores ALTER TABLE ADD COLUMN if it already exists — but we'll check)
    existing_cols = {row[1] for row in c.execute("PRAGMA table_info(users)").fetchall()}
    if "account_number" not in existing_cols:
        try:
            c.execute("ALTER TABLE users ADD COLUMN account_number TEXT")
        except Exception:
            pass
    if "phone" not in existing_cols:
        try:
            c.execute("ALTER TABLE users ADD COLUMN phone TEXT")
        except Exception:
            pass
    if "email" not in existing_cols:
        try:
            c.execute("ALTER TABLE users ADD COLUMN email TEXT")
        except Exception:
            pass

    conn.commit()
    conn.close()

# Call on startup
init_db()

# ---------------- HELPERS ----------------
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

def create_token(username):
    payload = {
        "username": username,
        "exp": datetime.utcnow() + timedelta(hours=1)
    }
    token = jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token

def normalize_phone(phone_str):
    """Return only digits string"""
    if not phone_str:
        return ""
    digits = "".join(ch for ch in phone_str if ch.isdigit())
    return digits

def last_n(s, n):
    if not s:
        return ""
    return s[-n:]

# ---------------- ROUTES ----------------
@app.route("/register", methods=["POST"])
def register():
    data = request.json or {}
    # frontend sends: username, password, full_name, phone, email
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    full_name = (data.get("full_name") or username).strip()
    phone_raw = (data.get("phone") or "").strip()
    email = (data.get("email") or "").strip()

    if not username or not password:
        return jsonify({"success": False, "message": "username and password are required"}), 400

    phone_digits = normalize_phone(phone_raw)
    account_number = last_n(phone_digits, 10) if phone_digits else ""

    conn = _conn()
    c = conn.cursor()
    try:
        hashed_pw = generate_password_hash(password)
        created_at = datetime.utcnow().isoformat()
        # New accounts start with 0 balance by default (user requested)
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
    # frontend posts { username, password }
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()

    if not username or not password:
        return jsonify({"success": False, "message": "username and password are required"}), 400

    conn = _conn()
    c = conn.cursor()
    c.execute("SELECT password FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()

    if not row:
        return jsonify({"success": False, "message": "User not found"}), 404

    hashed_pw = row[0]
    if not check_password_hash(hashed_pw, password):
        return jsonify({"success": False, "message": "Invalid password"}), 401

    token = create_token(username)
    return jsonify({"success": True, "message": "Login successful", "token": token}), 200

@app.route("/user/profile", methods=["GET"])
@token_required
def profile(current_user):
    conn = _conn()
    c = conn.cursor()
    c.execute("""
        SELECT username, full_name, phone, account_number, email, balance, created_at
        FROM users WHERE username=?
    """, (current_user,))
    row = c.fetchone()
    conn.close()
    if row:
        return jsonify({
            "success": True,
            "username": row[0],
            "full_name": row[1],
            "phone": row[2],
            "account_number": row[3],
            "email": row[4],
            "balance": row[5],
            "created_at": row[6]
        }), 200
    return jsonify({"success": False, "message": "User not found"}), 404

@app.route("/balance", methods=["GET"])
@token_required
def balance(current_user):
    conn = _conn()
    c = conn.cursor()
    c.execute("SELECT balance FROM users WHERE username=?", (current_user,))
    row = c.fetchone()
    conn.close()
    if row:
        return jsonify({"success": True, "username": current_user, "balance": row[0]}), 200
    return jsonify({"success": False, "message": "User not found"}), 404

@app.route("/transfer", methods=["POST"])
@token_required
def transfer(current_user):
    data = request.json or {}
    # frontend sends { receiver, amount } where receiver can be username or account_number (phone last 10)
    receiver_raw = (data.get("receiver") or "").strip()
    if receiver_raw == "":
        return jsonify({"success": False, "message": "receiver is required"}), 400
    try:
        amount = float(data.get("amount"))
    except Exception:
        return jsonify({"success": False, "message": "receiver and numeric amount are required"}), 400

    if amount <= 0:
        return jsonify({"success": False, "message": "Amount must be greater than 0"}), 400

    conn = _conn()
    c = conn.cursor()

    # Resolve receiver: if numeric and length >=10, try account_number lookup first
    receiver = None
    if receiver_raw.isdigit() and len(receiver_raw) >= 6:
        # allow partial or last 10 — try exact match on account_number (we store last10)
        rn = last_n(normalize_phone(receiver_raw), 10)
        c.execute("SELECT username FROM users WHERE account_number=?", (rn,))
        rr = c.fetchone()
        if rr:
            receiver = rr[0]

    # fallback: treat as username
    if not receiver:
        c.execute("SELECT username FROM users WHERE username=?", (receiver_raw,))
        rr = c.fetchone()
        if rr:
            receiver = rr[0]

    if not receiver:
        conn.close()
        return jsonify({"success": False, "message": "Sender or receiver not found"}), 404

    if receiver == current_user:
        conn.close()
        return jsonify({"success": False, "message": "Cannot transfer to self"}), 400

    # Fetch balances and full names
    c.execute("SELECT balance, full_name FROM users WHERE username=?", (current_user,))
    s_row = c.fetchone()
    c.execute("SELECT balance, full_name FROM users WHERE username=?", (receiver,))
    r_row = c.fetchone()

    if not s_row or not r_row:
        conn.close()
        return jsonify({"success": False, "message": "Sender or receiver not found"}), 404

    s_balance, s_name = s_row[0], s_row[1]
    r_balance, r_name = r_row[0], r_row[1]

    if s_balance < amount:
        conn.close()
        return jsonify({"success": False, "message": "Insufficient funds"}), 400

    try:
        # Update balances
        c.execute("UPDATE users SET balance = balance - ? WHERE username=?", (amount, current_user))
        c.execute("UPDATE users SET balance = balance + ? WHERE username=?", (amount, receiver))

        # Save transaction
        timestamp = datetime.utcnow().isoformat()
        c.execute("INSERT INTO transactions (sender, receiver, amount, timestamp) VALUES (?, ?, ?, ?)",
                  (current_user, receiver, amount, timestamp))

        conn.commit()

        # Fetch updated balances
        c.execute("SELECT balance FROM users WHERE username=?", (current_user,))
        new_sender_balance = c.fetchone()[0]
        c.execute("SELECT balance FROM users WHERE username=?", (receiver,))
        new_receiver_balance = c.fetchone()[0]
    finally:
        conn.close()

    return jsonify({
        "success": True,
        "message": "Transfer successful",
        "sender": {"username": current_user, "full_name": s_name, "balance": new_sender_balance},
        "receiver": {"username": receiver, "full_name": r_name, "balance": new_receiver_balance}
    }), 200

@app.route("/transactions", methods=["GET"])
@token_required
def transactions(current_user):
    conn = _conn()
    c = conn.cursor()
    # join to retrieve full names for display
    c.execute("""
        SELECT t.sender,
               COALESCE(su.full_name, t.sender) AS sender_name,
               t.receiver,
               COALESCE(ru.full_name, t.receiver) AS receiver_name,
               t.amount,
               t.timestamp
        FROM transactions t
        LEFT JOIN users su ON su.username = t.sender
        LEFT JOIN users ru ON ru.username = t.receiver
        WHERE t.sender=? OR t.receiver=?
        ORDER BY timestamp DESC
    """, (current_user, current_user))
    rows = c.fetchall()
    conn.close()

    txns = []
    for r in rows:
        txns.append({
            "sender": r[0],
            "sender_name": r[1],
            "receiver": r[2],
            "receiver_name": r[3],
            "amount": r[4],
            "timestamp": r[5]
        })
    return jsonify({"success": True, "transactions": txns}), 200

# ---------------- RUN ----------------
if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))