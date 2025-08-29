from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
from pymongo import MongoClient
from bson.objectid import ObjectId
import os

app = Flask(__name__)
CORS(app)

# --- MONGODB SETUP ---
MONGO_URI = os.environ.get("MONGO_URI") or "mongodb+srv://Payme:08167542829Pr%24@payme.62k49sg.mongodb.net/?retryWrites=true&w=majority&appName=Payme"
client = MongoClient(MONGO_URI)
db = client.payme_db
users_col = db.users
transactions_col = db.transactions

# --- HELPERS ---
def find_user_by_phone(phone):
    # Store last 10 digits as account identifier
    return users_col.find_one({"phone": phone[-10:]})

def find_user_by_id(user_id):
    try:
        return users_col.find_one({"_id": ObjectId(user_id)})
    except:
        return None

# --- REGISTER ---
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    phone = data.get('phone')
    password = data.get('password')

    if not username or not phone or not password:
        return jsonify({'message': 'All fields are required!'}), 400

    if find_user_by_phone(phone):
        return jsonify({'message': 'Phone already registered!'}), 400

    account_number = phone[-10:]
    result = users_col.insert_one({
        'username': username,
        'phone': phone,
        'password': password,
        'balance': 0.0,
        'account_number': account_number
    })

    user = users_col.find_one({"_id": result.inserted_id}, {"password":0})
    user['_id'] = str(user['_id'])
    return jsonify({'message': 'User registered successfully!', 'user': user}), 200

# --- LOGIN ---
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    phone = data.get('phone')
    password = data.get('password')

    user = find_user_by_phone(phone)
    if not user or user['password'] != password:
        return jsonify({'message': 'Invalid credentials!'}), 401

    user_data = user.copy()
    user_data.pop('password', None)
    user_data['_id'] = str(user_data['_id'])
    return jsonify({'message': 'Login successful!', 'user': user_data}), 200

# --- GET ALL USERS ---
@app.route('/all-users', methods=['GET'])
def all_users():
    users_list = list(users_col.find({}, {"password":0}))
    for u in users_list:
        u['_id'] = str(u['_id'])
    return jsonify(users_list), 200

# --- UPDATE BALANCE (ADD MONEY) ---
@app.route('/update-balance', methods=['POST'])
def update_balance():
    data = request.get_json()
    user = find_user_by_id(data.get('userId'))
    amount = float(data.get('amount', 0))

    if not user:
        return jsonify({'message': 'User not found'}), 404
    if amount <= 0:
        return jsonify({'message': 'Invalid amount'}), 400

    new_balance = user['balance'] + amount
    users_col.update_one({"_id": ObjectId(user['_id'])}, {"$set": {"balance": new_balance}})
    transactions_col.insert_one({
        'type': 'Deposit',
        'amount': amount,
        'userId': str(user['_id']),
        'date': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })
    return jsonify({'message': f'Added ₦{amount}', 'balance': new_balance}), 200

# --- SEND MONEY ---
@app.route('/send', methods=['POST'])
def send_money():
    data = request.get_json()
    sender = find_user_by_id(data.get('userId'))
    receiver = find_user_by_id(data.get('receiverId'))
    amount = float(data.get('amount', 0))

    if not sender or not receiver:
        return jsonify({'message': 'User not found'}), 404
    if sender['_id'] == receiver['_id']:
        return jsonify({'message': 'Cannot send to self'}), 400
    if sender['balance'] < amount or amount <= 0:
        return jsonify({'message': 'Insufficient or invalid funds!'}), 400

    sender_new_balance = sender['balance'] - amount
    receiver_new_balance = receiver['balance'] + amount

    users_col.update_one({"_id": ObjectId(sender['_id'])}, {"$set": {"balance": sender_new_balance}})
    users_col.update_one({"_id": ObjectId(receiver['_id'])}, {"$set": {"balance": receiver_new_balance}})

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    transactions_col.insert_many([
        {'type': f'Sent to {receiver["username"]}', 'amount': amount, 'userId': str(sender['_id']), 'date': now},
        {'type': f'Received from {sender["username"]}', 'amount': amount, 'userId': str(receiver['_id']), 'date': now}
    ])

    return jsonify({'message': f'₦{amount} sent to {receiver["username"]}', 'balance': sender_new_balance}), 200

# --- GET USER TRANSACTIONS ---
@app.route('/transactions', methods=['POST'])
def get_transactions():
    data = request.get_json()
    user_id = str(data.get('userId'))
    tx_list = list(transactions_col.find({"userId": user_id}))
    for tx in tx_list:
        tx['_id'] = str(tx['_id'])
    return jsonify(tx_list), 200

# --- GET USER BY ACCOUNT NUMBER ---
@app.route('/user-by-account', methods=['POST'])
def user_by_account():
    data = request.get_json()
    acct = data.get('accountNumber')
    user = users_col.find_one({"account_number": acct})
    if user:
        return jsonify({'username': user['username'], 'userId': str(user['_id'])}), 200
    return jsonify({'message': 'User not found'}), 404

# --- MAIN ---
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)