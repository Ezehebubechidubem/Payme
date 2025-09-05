from flask import Flask, request, jsonify
import sqlite3
from datetime import datetime

app = Flask(__name__)
DB = "payme.db"


def init_db():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    # Users table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        phone TEXT UNIQUE,
        password TEXT,
        account_number TEXT UNIQUE,
        balance REAL DEFAULT 0
    )
    """)
    # Transactions table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS transactions(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        type TEXT,
        amount REAL,
        other_party TEXT,
        date TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)
    conn.commit()
    conn.close()


@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    phone = data.get("phone")
    password = data.get("password")

    account_number = phone[-10:]

    try:
        conn = sqlite3.connect(DB)
        cur = conn.cursor()
        cur.execute("INSERT INTO users (username, phone, password, account_number, balance) VALUES (?, ?, ?, ?, ?)",
                    (username, phone, password, account_number, 0))
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "account_number": account_number})
    except sqlite3.IntegrityError:
        return jsonify({"status": "error", "message": "User already exists"}), 400


@app.route("/login", methods=["POST"])
def login():
    data = request.json
    login = data.get("login")
    password = data.get("password")

    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE (username=? OR phone=?) AND password=?", (login, login, password))
    user = cur.fetchone()
    conn.close()

    if user:
        return jsonify({
            "status": "success",
            "user": {
                "id": user[0],
                "username": user[1],
                "phone": user[2],
                "account_number": user[4],
                "balance": user[5]
            }
        })
    return jsonify({"status": "error", "message": "Invalid credentials"}), 401


@app.route("/balance/<int:user_id>")
def balance(user_id):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT balance FROM users WHERE id=?", (user_id,))
    row = cur.fetchone()
    conn.close()
    return jsonify({"balance": row[0] if row else 0})


@app.route("/add_money", methods=["POST"])
def add_money():
    data = request.json
    user_id = data.get("user_id")
    amount = float(data.get("amount"))

    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("UPDATE users SET balance = balance + ? WHERE id=?", (amount, user_id))
    cur.execute("INSERT INTO transactions (user_id, type, amount, other_party, date) VALUES (?, ?, ?, ?, ?)",
                (user_id, "Deposit", amount, "Self", datetime.now().isoformat()))
    conn.commit()
    conn.close()
    return jsonify({"status": "success", "message": f"₦{amount} added"})


@app.route("/send_money", methods=["POST"])
def send_money():
    data = request.json
    sender_id = data.get("sender_id")
    receiver_acc = data.get("receiver_acc")
    amount = float(data.get("amount"))

    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    # Check sender balance
    cur.execute("SELECT balance FROM users WHERE id=?", (sender_id,))
    row = cur.fetchone()
    if not row or row[0] < amount:
        return jsonify({"status": "error", "message": "Insufficient funds"}), 400

    # Deduct from sender
    cur.execute("UPDATE users SET balance = balance - ? WHERE id=?", (amount, sender_id))
    cur.execute("INSERT INTO transactions (user_id, type, amount, other_party, date) VALUES (?, ?, ?, ?, ?)",
                (sender_id, "Transfer Out", amount, receiver_acc, datetime.now().isoformat()))

    # Credit receiver
    cur.execute("SELECT id FROM users WHERE account_number=?", (receiver_acc,))
    recv = cur.fetchone()
    if recv:
        recv_id = recv[0]
        cur.execute("UPDATE users SET balance = balance + ? WHERE id=?", (amount, recv_id))
        cur.execute("INSERT INTO transactions (user_id, type, amount, other_party, date) VALUES (?, ?, ?, ?, ?)",
                    (recv_id, "Transfer In", amount, str(sender_id), datetime.now().isoformat()))

    conn.commit()
    conn.close()
    return jsonify({"status": "success", "message": f"₦{amount} sent"})


@app.route("/transactions/<int:user_id>")
def transactions(user_id):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT type, amount, other_party, date FROM transactions WHERE user_id=? ORDER BY id DESC", (user_id,))
    rows = cur.fetchall()
    conn.close()
    return jsonify([{"type": r[0], "amount": r[1], "other_party": r[2], "date": r[3]} for r in rows])


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
