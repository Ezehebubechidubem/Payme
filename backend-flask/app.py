from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

users = {}  # key: user_id, value: dict
transactions = {}  # key: user_id, value: list of dicts
next_id = 1

@app.route("/signup", methods=["POST"])
def signup():
    global next_id
    data = request.json
    email = data.get("email")
    if any(u["email"] == email for u in users.values()):
        return jsonify({"success": False, "message": "Email already exists"})
    
    user = {
        "id": next_id,
        "name": data.get("name"),
        "email": email,
        "password": data.get("password"),
        "balance": 0
    }
    users[next_id] = user
    transactions[next_id] = []
    next_id += 1
    return jsonify({"success": True, "message": "Signup successful!"})

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    email = data.get("email")
    password = data.get("password")
    for uid, user in users.items():
        if user["email"] == email and user["password"] == password:
            return jsonify({"success": True, "user": user})
    return jsonify({"success": False, "message": "Invalid credentials"})

@app.route("/balance", methods=["GET"])
def balance():
    user_id = int(request.args.get("user_id"))
    return jsonify({"balance": users[user_id]["balance"]})

@app.route("/transactions", methods=["GET"])
def get_transactions():
    user_id = int(request.args.get("user_id"))
    return jsonify(transactions[user_id])

@app.route("/add_money", methods=["POST"])
def add_money():
    """Add money to user account (fund wallet)."""
    data = request.json
    user_id = int(data.get("user_id"))
    amount = float(data.get("amount", 0))
    if amount <= 0:
        return jsonify({"success": False, "message": "Invalid amount"})
    
    users[user_id]["balance"] += amount
    transactions[user_id].append({
        "type": "Credit",
        "amount": amount,
        "description": "Wallet funding"
    })
    return jsonify({"success": True, "balance": users[user_id]["balance"]})

@app.route("/send_money", methods=["POST"])
def send_money():
    """Send money from one user to another."""
    data = request.json
    from_id = int(data.get("from_id"))
    to_email = data.get("to_email")
    amount = float(data.get("amount", 0))

    if amount <= 0:
        return jsonify({"success": False, "message": "Invalid amount"})

    if users[from_id]["balance"] < amount:
        return jsonify({"success": False, "message": "Insufficient funds"})

    # find receiver by email
    to_id = None
    for uid, user in users.items():
        if user["email"] == to_email:
            to_id = uid
            break
    if not to_id:
        return jsonify({"success": False, "message": "Recipient not found"})

    # perform transfer
    users[from_id]["balance"] -= amount
    users[to_id]["balance"] += amount

    # log transaction for sender
    transactions[from_id].append({
        "type": "Debit",
        "amount": amount,
        "description": f"Sent to {users[to_id]['name']} ({users[to_id]['email']})"
    })
    # log transaction for receiver
    transactions[to_id].append({
        "type": "Credit",
        "amount": amount,
        "description": f"Received from {users[from_id]['name']} ({users[from_id]['email']})"
    })

    return jsonify({"success": True, "balance": users[from_id]["balance"]})

if __name__ == "__main__":
    app.run(debug=True)