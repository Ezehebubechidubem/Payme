# app.py
from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime

app = Flask(__name__)
CORS(app)

# ----------------- In-memory database (demo only) -----------------
users = {}       # user_id : {username, full_name, password, balance, transactions}
next_id = 1

# ----------------- Helper Functions -----------------
def find_user_by_username(username):
    for uid, user in users.items():
        if user["username"] == username:
            return uid, user
    return None, None

# ----------------- Routes -----------------

# Register
@app.route("/register", methods=["POST"])
def register():
    global next_id
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    full_name = data.get("full_name")
    
    if not username or not password or not full_name:
        return jsonify({"success": False, "message": "All fields are required"}), 400
    
    # Check if username exists
    _, existing_user = find_user_by_username(username)
    if existing_user:
        return jsonify({"success": False, "message": "Username already exists"}), 409
    
    # Create user
    users[next_id] = {
        "username": username,
        "full_name": full_name,
        "password": password,
        "balance": 0.0,
        "transactions": []
    }
    next_id += 1
    
    return jsonify({"success": True, "message": "User registered successfully"})

# Login
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    
    uid, user = find_user_by_username(username)
    if not user or user["password"] != password:
        return jsonify({"success": False, "message": "Invalid credentials"}), 401
    
    return jsonify({"success": True, "user_id": uid, "full_name": user["full_name"], "balance": user["balance"]})

# Get Dashboard Info
@app.route("/dashboard/<int:user_id>", methods=["GET"])
def dashboard(user_id):
    user = users.get(user_id)
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404
    
    return jsonify({
        "success": True,
        "full_name": user["full_name"],
        "balance": user["balance"],
        "transactions": user["transactions"]
    })

# Check Receiver Name Before Sending
@app.route("/get_receiver", methods=["POST"])
def get_receiver():
    data = request.get_json()
    username = data.get("username")
    
    if not username:
        return jsonify({"success": False, "message": "No username provided"}), 400
    
    uid, user = find_user_by_username(username)
    if user:
        return jsonify({"success": True, "full_name": user["full_name"]})
    
    return jsonify({"success": False, "message": "User not found"}), 404

# Send Money
@app.route("/send_money", methods=["POST"])
def send_money():
    data = request.get_json()
    sender_id = data.get("sender_id")
    receiver_username = data.get("receiver_username")
    amount = float(data.get("amount", 0))
    
    if not sender_id or not receiver_username or amount <= 0:
        return jsonify({"success": False, "message": "Invalid data"}), 400
    
    sender = users.get(sender_id)
    if not sender:
        return jsonify({"success": False, "message": "Sender not found"}), 404
    
    receiver_id, receiver = find_user_by_username(receiver_username)
    if not receiver:
        return jsonify({"success": False, "message": "Receiver not found"}), 404
    
    if sender["balance"] < amount:
        return jsonify({"success": False, "message": "Insufficient balance"}), 400
    
    # Perform transaction
    sender["balance"] -= amount
    receiver["balance"] += amount
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Log transaction for sender
    sender["transactions"].append({
        "type": "Sent",
        "amount": amount,
        "to": receiver["full_name"],
        "timestamp": timestamp
    })
    
    # Log transaction for receiver
    receiver["transactions"].append({
        "type": "Received",
        "amount": amount,
        "from": sender["full_name"],
        "timestamp": timestamp
    })
    
    return jsonify({"success": True, "message": f"Sent ₦{amount} to {receiver['full_name']}"})

# Deposit Money
@app.route("/deposit", methods=["POST"])
def deposit():
    data = request.get_json()
    user_id = data.get("user_id")
    amount = float(data.get("amount", 0))
    
    user = users.get(user_id)
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404
    if amount <= 0:
        return jsonify({"success": False, "message": "Invalid amount"}), 400
    
    user["balance"] += amount
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user["transactions"].append({
        "type": "Deposit",
        "amount": amount,
        "timestamp": timestamp
    })
    
    return jsonify({"success": True, "balance": user["balance"], "message": f"Deposited ₦{amount}"})

# Withdraw Money
@app.route("/withdraw", methods=["POST"])
def withdraw():
    data = request.get_json()
    user_id = data.get("user_id")
    amount = float(data.get("amount", 0))
    
    user = users.get(user_id)
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404
    if amount <= 0 or amount > user["balance"]:
        return jsonify({"success": False, "message": "Invalid amount"}), 400
    
    user["balance"] -= amount
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user["transactions"].append({
        "type": "Withdraw",
        "amount": amount,
        "timestamp": timestamp
    })
    
    return jsonify({"success": True, "balance": user["balance"], "message": f"Withdrew ₦{amount}"})

# Run app
if __name__ == "__main__":
    app.run(debug=True)