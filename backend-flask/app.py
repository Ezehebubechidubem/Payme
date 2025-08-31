from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime

app = Flask(__name__)
CORS(app)

# Simple in-memory database (replace with real DB later)
users = {}   # user_id: user_data
transactions = []  # all transactions
next_id = 1

def find_user_by_phone(phone):
    for user in users.values():
        if user['phone'][-10:] == phone[-10:]:
            return user
    return None

def find_user_by_id(user_id):
    return users.get(user_id)

# --- REGISTER ---
@app.route('/register', methods=['POST'])
def register():
    global next_id
    data = request.get_json()
    username = data.get('username')
    phone = data.get('phone')
    password = data.get('password')

    if not username or not phone or not password:
        return jsonify({'message': 'All fields are required!'}), 400

    if find_user_by_phone(phone):
        return jsonify({'message': 'Phone already registered!'}), 400

    user_id = str(next_id)
    account_number = phone[-10:]  # last 10 digits
    users[user_id] = {
        'id': user_id,
        'username': username,
        'phone': phone,
        'password': password,
        'balance': 0.0,
        'account_number': account_number
    }
    next_id += 1
    return jsonify({'message': 'User registered successfully!', 'userId': user_id}), 200

# --- LOGIN ---
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    phone = data.get('phone')
    password = data.get('password')
    user = find_user_by_phone(phone)
    if not user or user['password'] != password:
        return jsonify({'message': 'Invalid credentials!'}), 401
    return jsonify({'message': 'Login successful!', 'user': user}), 200

# --- GET ALL USERS (for sending money) ---
@app.route('/all-users', methods=['GET'])
def all_users():
    return jsonify(list(users.values())), 200

# --- UPDATE BALANCE (Add Money) ---
@app.route('/update-balance', methods=['POST'])
def update_balance():
    data = request.get_json()
    user = find_user_by_id(str(data.get('userId')))
    amount = float(data.get('amount', 0))
    if not user:
        return jsonify({'message': 'User not found'}), 404
    user['balance'] += amount
    # record transaction
    transactions.append({
        'type': 'Deposit',
        'amount': amount,
        'userId': user['id'],
        'date': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })
    return jsonify({'message': f'Added ₦{amount}', 'balance': user['balance']}), 200

# --- SEND MONEY ---
@app.route('/send', methods=['POST'])
def send_money():
    data = request.get_json()
    sender = find_user_by_id(str(data.get('userId')))
    receiver = find_user_by_id(str(data.get('receiverId')))
    amount = float(data.get('amount', 0))
    if not sender or not receiver:
        return jsonify({'message': 'User not found'}), 404
    if sender['balance'] < amount:
        return jsonify({'message': 'Insufficient funds!'}), 400
    sender['balance'] -= amount
    receiver['balance'] += amount
    # record transactions
    transactions.append({
        'type': f'Sent to {receiver["username"]}',
        'amount': amount,
        'userId': sender['id'],
        'date': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })
    transactions.append({
        'type': f'Received from {sender["username"]}',
        'amount': amount,
        'userId': receiver['id'],
        'date': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })
    return jsonify({'message': f'₦{amount} sent to {receiver["username"]}', 'balance': sender['balance']}), 200

# --- GET USER TRANSACTIONS ---
@app.route('/transactions', methods=['POST'])
def get_transactions():
    data = request.get_json()
    user_id = str(data.get('userId'))
    user_tx = [tx for tx in transactions if tx['userId'] == user_id]
    return jsonify(user_tx), 200

# --- GET USER BY ACCOUNT NUMBER ---
@app.route('/user-by-account', methods=['POST'])
def user_by_account():
    data = request.get_json()
    acct = data.get('accountNumber')
    for user in users.values():
        if user['account_number'] == acct:
            return jsonify({'username': user['username'], 'userId': user['id']}), 200
    return jsonify({'message': 'User not found'}), 404

if __name__ == "__main__":
    app.run(debug=True)