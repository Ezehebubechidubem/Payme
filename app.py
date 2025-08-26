from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# In-memory database (demo only)
users = {}  # key = user id, value = user data
next_id = 1

def generate_account_number(phone):
    """Generate 10-digit account number from phone (remove leading 0)."""
    if phone.startswith("0"):
        return phone[1:]
    return phone

@app.route('/register', methods=['POST'])
def register():
    global next_id
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    phone = data.get('phone')

    if not all([username, email, password, phone]):
        return jsonify({"message": "All fields are required!"}), 400

    # Uniqueness checks
    if any(u['email'] == email for u in users.values()):
        return jsonify({"message": "Email already registered!"}), 400
    if any(u['username'] == username for u in users.values()):
        return jsonify({"message": "Username already taken!"}), 400
    if any(u['phone'] == phone for u in users.values()):
        return jsonify({"message": "Phone number already used!"}), 400

    account_number = generate_account_number(phone)

    if any(u['account_number'] == account_number for u in users.values()):
        return jsonify({"message": "Account number already exists!"}), 400

    user = {
        "id": next_id,
        "username": username,
        "email": email,
        "password": password,
        "phone": phone,
        "account_number": account_number,
        "balance": 0
    }
    users[next_id] = user
    next_id += 1
    return jsonify({"message": "Registered successfully!", "user": user})

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    for user in users.values():
        if user['email'] == email and user['password'] == password:
            return jsonify({"message": "Login successful!", "user": user})
    return jsonify({"message": "Invalid email or password"}), 400

@app.route('/update-balance', methods=['POST'])
def update_balance():
    data = request.json
    user_id = data['userId']
    amount = float(data['amount'])
    users[user_id]['balance'] += amount
    return jsonify({"message": "Money added successfully!", "balance": users[user_id]['balance']})

@app.route('/send', methods=['POST'])
def send_money():
    data = request.json
    sender_id = data['userId']
    receiver_account = data.get('receiver')
    amount = float(data['amount'])

    # Find receiver
    receiver = next((u for u in users.values() if u['account_number'] == receiver_account), None)
    if not receiver:
        return jsonify({"message": "Receiver account not found!"}), 400

    if users[sender_id]['balance'] >= amount:
        users[sender_id]['balance'] -= amount
        receiver['balance'] += amount
        return jsonify({
            "message": f"Sent ₦{amount} to {receiver['username']} ({receiver['account_number']})",
            "balance": users[sender_id]['balance']
        })
    else:
        return jsonify({"message": "Insufficient balance!"}), 400

@app.route('/check-account', methods=['POST'])
def check_account():
    """Check if account number exists and return username."""
    data = request.json
    account_number = data.get('account_number')
    user = next((u for u in users.values() if u['account_number'] == account_number), None)
    if user:
        return jsonify({"exists": True, "username": user['username']})
    return jsonify({"exists": False}), 404

@app.route('/transfer', methods=['POST'])
def transfer_money():
    data = request.json
    user_id = data['userId']
    amount = float(data['amount'])
    if users[user_id]['balance'] >= amount:
        users[user_id]['balance'] -= amount
        return jsonify({"message": f"Transferred ₦{amount} to bank!", "balance": users[user_id]['balance']})
    else:
        return jsonify({"message": "Insufficient balance!"}), 400

@app.route('/airtime', methods=['POST'])
def buy_airtime():
    data = request.json
    user_id = data['userId']
    amount = float(data['amount'])
    if users[user_id]['balance'] >= amount:
        users[user_id]['balance'] -= amount
        return jsonify({"message": f"Airtime ₦{amount} purchased!", "balance": users[user_id]['balance']})
    else:
        return jsonify({"message": "Insufficient balance!"}), 400

if __name__ == '__main__':
    app.run(debug=True)
