from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
import sqlite3
from datetime import datetime
import os
import sys
import traceback

# -------------------------------------------------
# App & CORS
# -------------------------------------------------
app = Flask(__name__)

# Allow all origins by default (works with file:// or any SPA host)
# If you want to restrict, set CORS_ORIGINS env var to comma-separated list.
cors_origins = os.environ.get("CORS_ORIGINS", "*")
CORS(app, resources={r"/*": {"origins": cors_origins}}, supports_credentials=True)

# SQLite file (persisted on Render disk; resets on redeploy unless using a Disk)
DB = os.environ.get("SQLITE_DB_PATH", "payme.db")


# -------------------------------------------------
# DB helpers
# -------------------------------------------------
def get_conn():
    """
    Open a SQLite connection with thread check disabled for WSGI servers.
    WAL mode improves concurrency for reads/writes.
    """
    conn = sqlite3.connect(DB, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    with conn:  # pragma config is safe in a transaction
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def init_db():
    with get_conn() as conn:
        cur = conn.cursor()
        # Users table
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                phone TEXT UNIQUE,
                password TEXT,
                account_number TEXT UNIQUE,
                balance REAL DEFAULT 0
            )
            """
        )
        # Transactions table
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS transactions(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                type TEXT,
                amount REAL,
                other_party TEXT,
                date TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )


# -------------------------------------------------
# Utilities
# -------------------------------------------------
def json_required(keys):
    """
    Validate JSON presence and required keys.
    Returns (data, error_response) where error_response is a Flask response or None.
    """
    if not request.is_json:
        return None, jsonify({"status": "error", "message": "Content-Type must be application/json"}), 400
    data = request.get_json(silent=True) or {}
    missing = [k for k in keys if data.get(k) in (None, "")]
    if missing:
        return None, jsonify({"status": "error", "message": f"Missing fields: {', '.join(missing)}"}), 400
    return data, None, None


def to_user_dict(row):
    return {
        "id": row["id"],
        "username": row["username"],
        "phone": row["phone"],
        "account_number": row["account_number"],
        "balance": row["balance"],
    }


# -------------------------------------------------
# Global error & logging
# -------------------------------------------------
@app.before_request
def _log_request():
    # lightweight request log to stdout (visible in Render logs)
    print(f"> {request.method} {request.path}", file=sys.stdout, flush=True)


@app.errorhandler(Exception)
def _handle_exception(e):
    # Log full traceback to Render logs
    traceback.print_exc()
    # Return JSON error so the frontend sees details while you debug
    return jsonify({"status": "error", "message": str(e)}), 500


@app.after_request
def _security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-XSS-Protection"] = "1; mode=block"
    return resp


# Generic preflight responder (optional—Flask-CORS usually covers this)
@app.route("/", methods=["OPTIONS"])
@app.route("/<path:_any>", methods=["OPTIONS"])
def options(_any=None):
    return make_response(("", 204))


# -------------------------------------------------
# Health
# -------------------------------------------------
@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "✅ PayMe backend is running"}), 200


# -------------------------------------------------
# Auth & User
# -------------------------------------------------
@app.route("/register", methods=["POST"])
def register():
    data, err, code = json_required(["username", "phone", "password"])
    if err:
        return err, code

    username = data["username"].strip()
    phone = data["phone"].strip()
    password = data["password"]

    if not phone.isdigit() or len(phone) != 11:
        return jsonify({"status": "error", "message": "Phone must be exactly 11 digits"}), 400

    account_number = phone[-10:]

    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO users (username, phone, password, account_number, balance) VALUES (?, ?, ?, ?, ?)",
                (username, phone, password, account_number, 0.0),
            )
        return jsonify({"status": "success", "account_number": account_number}), 200
    except sqlite3.IntegrityError as ie:
        # username OR phone uniqueness violation
        msg = "User already exists"
        if "username" in str(ie).lower():
            msg = "Username already exists"
        elif "phone" in str(ie).lower():
            msg = "Phone already exists"
        return jsonify({"status": "error", "message": msg}), 400


@app.route("/login", methods=["POST"])
def login():
    data, err, code = json_required(["login", "password"])
    if err:
        return err, code

    login_value = data["login"].strip()
    password = data["password"]

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, username, phone, password, account_number, balance "
            "FROM users WHERE (username = ? OR phone = ?) AND password = ?",
            (login_value, login_value, password),
        )
        row = cur.fetchone()

    if not row:
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401

    user = {
        "id": row["id"],
        "username": row["username"],
        "phone": row["phone"],
        "account_number": row["account_number"],
        "balance": row["balance"],
    }
    return jsonify({"status": "success", "user": user}), 200


# -------------------------------------------------
# Money
# -------------------------------------------------
@app.route("/balance/<int:user_id>", methods=["GET"])
def balance(user_id: int):
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT balance FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
    return jsonify({"balance": (row["balance"] if row else 0.0)}), 200


@app.route("/add_money", methods=["POST"])
def add_money():
    data, err, code = json_required(["user_id", "amount"])
    if err:
        return err, code

    try:
        user_id = int(data["user_id"])
        amount = float(data["amount"])
    except Exception:
        return jsonify({"status": "error", "message": "user_id must be int, amount must be number"}), 400

    if amount <= 0:
        return jsonify({"status": "error", "message": "Amount must be > 0"}), 400

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, user_id))
        cur.execute(
            "INSERT INTO transactions (user_id, type, amount, other_party, date) VALUES (?, ?, ?, ?, ?)",
            (user_id, "Deposit", amount, "Self", datetime.now().isoformat()),
        )
    return jsonify({"status": "success", "message": f"₦{amount} added"}), 200


@app.route("/send_money", methods=["POST"])
def send_money():
    data, err, code = json_required(["sender_id", "receiver_acc", "amount"])
    if err:
        return err, code

    try:
        sender_id = int(data["sender_id"])
        receiver_acc = str(data["receiver_acc"]).strip()
        amount = float(data["amount"])
    except Exception:
        return jsonify({"status": "error", "message": "Invalid payload types"}), 400

    if amount <= 0:
        return jsonify({"status": "error", "message": "Amount must be > 0"}), 400
    if not receiver_acc.isdigit() or len(receiver_acc) != 10:
        return jsonify({"status": "error", "message": "receiver_acc must be a 10-digit account number"}), 400

    with get_conn() as conn:
        cur = conn.cursor()

        # Check sender balance
        cur.execute("SELECT balance FROM users WHERE id = ?", (sender_id,))
        sender_row = cur.fetchone()
        if (not sender_row) or (sender_row["balance"] < amount):
            return jsonify({"status": "error", "message": "Insufficient funds"}), 400

        # Deduct from sender
        cur.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, sender_id))
        cur.execute(
            "INSERT INTO transactions (user_id, type, amount, other_party, date) VALUES (?, ?, ?, ?, ?)",
            (sender_id, "Transfer Out", amount, receiver_acc, datetime.now().isoformat()),
        )

        # Credit receiver (if exists locally)
        cur.execute("SELECT id FROM users WHERE account_number = ?", (receiver_acc,))
        recv = cur.fetchone()
        if recv:
            recv_id = recv["id"]
            cur.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, recv_id))
            cur.execute(
                "INSERT INTO transactions (user_id, type, amount, other_party, date) VALUES (?, ?, ?, ?, ?)",
                (recv_id, "Transfer In", amount, str(sender_id), datetime.now().isoformat()),
            )

    return jsonify({"status": "success", "message": f"₦{amount} sent"}), 200


@app.route("/transactions/<int:user_id>", methods=["GET"])
def transactions(user_id: int):
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT type, amount, other_party, date FROM transactions WHERE user_id = ? ORDER BY id DESC",
            (user_id,),
        )
        rows = cur.fetchall()
    result = [
        {"type": r["type"], "amount": r["amount"], "other_party": r["other_party"], "date": r["date"]}
        for r in rows
    ]
    return jsonify(result), 200


# -------------------------------------------------
# Entry
# -------------------------------------------------
if __name__ != "__main__":  # gunicorn case
    with app.app_context():
        init_db()

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)