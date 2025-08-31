from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime

app = Flask(__name__)
CORS(app)

# Temporary "database"
users = {}  # {username: {"password": "...", "balance": 1000, "transactions": []}}

@app.route("/")
def home():
    return {"status": "PayGo Backend Running"}

# ---------------- SIGNUP ----------------
@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400
    
    if username in users:
        return jsonify({"error": "User already exists"}), 400

    users[username] = {"password": password, "balance": 1000, "transactions": []}
    return jsonify({"message": "Signup successful", "user": username}), 200

# ---------------- LOGIN ----------------
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    user = users.get(username)
    if not user or user["password"] != password:
        return jsonify({"error": "Invalid credentials"}), 401

    return jsonify({"message": "Login successful", "user": username}), 200

# ---------------- BALANCE ----------------
@app.route("/balance", methods=["GET"])
def get_balance():
    username = request.args.get("username")
    user = users.get(username)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"balance": user["balance"]}), 200

# ---------------- SEND MONEY ----------------
@app.route("/send", methods=["POST"])
def send_money():
    data = request.json
    sender = data.get("sender")
    receiver = data.get("receiver")
    amount = int(data.get("amount", 0))

    if sender not in users or receiver not in users:
        return jsonify({"error": "Invalid sender or receiver"}), 404

    if users[sender]["balance"] < amount:
        return jsonify({"error": "Insufficient funds"}), 400

    # Deduct and add
    users[sender]["balance"] -= amount
    users[receiver]["balance"] += amount

    # Record transaction
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    users[sender]["transactions"].append({"type": "Sent", "to": receiver, "amount": amount, "time": now})
    users[receiver]["transactions"].append({"type": "Received", "from": sender, "amount": amount, "time": now})

    return jsonify({"message": f"Sent {amount} to {receiver}"}), 200

# ---------------- TRANSACTION HISTORY ----------------
@app.route("/transactions", methods=["GET"])
def transactions():
    username = request.args.get("username")
    user = users.get(username)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"transactions": user["transactions"]}), 200

# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(debug=True)