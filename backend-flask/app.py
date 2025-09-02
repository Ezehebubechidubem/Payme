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
app.config["SECRET_KEY"] = "super-secret-key"  # change to something secure

def _conn():
    return sqlite3.connect(DB_PATH)

# ---------------- DB INIT ----------------
def init_db():
    conn = _conn()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            full_name TEXT,
            phone TEXT,
            email TEXT,
            balance REAL DEFAULT 0,
            created_at TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT,
            receiver TEXT,
            amount REAL,
            timestamp TEXT
        )
    """)
    conn.commit()
    conn.close()

# Call this on startup
init_db()

# ---------------- HELPERS ----------------
def token_required(f):
    """Decorator to protect routes with JWT"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            auth_header = request.headers["Authorization"]
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]

        if not token:
            return jsonify({"error": "Token is missing"}), 401

        try:
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            current_user = data["username"]
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        return f(current_user, *args, **kwargs)
    return decorated

def create_token(username):
    """Generate JWT with 1h expiry"""
    payload = {
        "username": username,
        "exp": datetime.utcnow() + timedelta(hours=1)
    }
    return jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")

# ---------------- ROUTES ----------------
@app.route("/register", methods=["POST"])
def register():
    data = request.json or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    full_name = (data.get("full_name") or username).strip()
    phone = (data.get("phone") or "").strip()
    email = (data.get("email") or "").strip()

    if not username or not password:
        return jsonify({"success": False, "message": "username and password are required"}), 400

    conn = _conn()
    c = conn.cursor()
    try:
        hashed_pw = generate_password_hash(password)
        created_at = datetime.utcnow().isoformat()
        c.execute("""
            INSERT INTO users (username, password, full_name, phone, email, balance, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (username, hashed_pw, full_name, phone, email, 1000.0, created_at))
        conn.commit()
        return jsonify({"success": True, "message": "User registered"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "message": "User already exists"}), 400
    finally:
        conn.close()

@app.route("/login", methods=["POST"])
def login():
    data = request.json or {}
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
    c.execute("SELECT username, full_name, phone, email, balance, created_at FROM users WHERE username=?", (current_user,))
    row = c.fetchone()
    conn.close()
    if row:
        return jsonify({
            "success": True,
            "username": row[0],
            "full_name": row[1],
            "phone": row[2],
            "email": row[3],
            "balance": row[4],
            "created_at": row[5]
        })
    return jsonify({"success": False, "message": "User not found"}), 404

@app.route("/transfer", methods=["POST"])
@token_required
def transfer(current_user):
    data = request.json or {}
    try:
        receiver = (data.get("receiver") or "").strip()
        amount = float(data.get("amount"))
    except Exception:
        return jsonify({"success": False, "message": "receiver and numeric amount are required"}), 400

    if not receiver:
        return jsonify({"success": False, "message": "receiver is required"}), 400
    if amount <= 0:
        return jsonify({"success": False, "message": "Amount must be greater than 0"}), 400
    if current_user == receiver:
        return jsonify({"success": False, "message": "Cannot transfer to self"}), 400

    conn = _conn()
    c = conn.cursor()
    c.execute("SELECT balance, full_name FROM users WHERE username=?", (current_user,))
    s_row = c.fetchone()
    c.execute("SELECT balance, full_name FROM users WHERE username=?", (receiver,))
    r_row = c.fetchone()

    if not s_row or not r_row:
        conn.close()
        return jsonify({"success": False, "message": "Sender or receiver not found"}), 404

    s_balance, s_name = s_row
    r_balance, r_name = r_row

    if s_balance < amount:
        conn.close()
        return jsonify({"success": False, "message": "Insufficient funds"}), 400

    try:
        c.execute("UPDATE users SET balance = balance - ? WHERE username=?", (amount, current_user))
        c.execute("UPDATE users SET balance = balance + ? WHERE username=?", (amount, receiver))
        timestamp = datetime.utcnow().isoformat()
        c.execute("INSERT INTO transactions (sender, receiver, amount, timestamp) VALUES (?, ?, ?, ?)",
                  (current_user, receiver, amount, timestamp))
        conn.commit()
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
    c.execute("""
        SELECT sender, receiver, amount, timestamp
        FROM transactions
        WHERE sender=? OR receiver=?
        ORDER BY timestamp DESC
    """, (current_user, current_user))
    rows = c.fetchall()
    conn.close()

    txns = [{"sender": r[0], "receiver": r[1], "amount": r[2], "timestamp": r[3]} for r in rows]
    return jsonify({"success": True, "transactions": txns})

# ---------------- RUN ----------------
if __name__ == "__main__":
    init_db()
    app.run(debug=True)