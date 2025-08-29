from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
from pymongo import MongoClient
from bson.objectid import ObjectId

app = Flask(__name__)
CORS(app)

# --- MONGODB SETUP ---
MONGO_URI = "mongodb+srv://Payme:08167542829Pr$24@payme.62k49sg.mongodb.net/?retryWrites=true&w=majority&appName=Payme"
client = MongoClient(MONGO_URI)
db = client.payme_db
users_col = db.users
transactions_col = db.transactions

def find_user_by_phone(phone):
    return users_col.find_one({"phone": phone[-10:]})

def find_user_by_id(user_id):
    return users_col.find_one({"_id": ObjectId(user_id)})

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
    user_id = str(result.inserted_id)
    return jsonify({'message': 'User registered successfully!', 'user': users_col.find_one({"_id": ObjectId(user_id)}, {"password":0})}), 200

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

# --- GET ALL USERS (for sending money) ---
@app.route('/all-users', methods=['GET'])
def all_users():
    all_users_list = list(users_col.find({}, {"password":0}))
    for u in all_users_list:
        u['_id'] = str(u['_id'])
    return jsonify(all_users_list), 200

# --- UPDATE BALANCE (Add Money) ---
@app.route('/update-balance', methods=['POST'])
def update_balance():
    data = request.get_json()
    user = find_user_by_id(data.get('userId'))
    amount = float(data.get('amount', 0))
    if not user:
        return jsonify({'message': 'User not found'}), 404
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
    if sender['balance'] < amount:
        return jsonify({'message': 'Insufficient funds!'}), 400

    sender_new_balance = sender['balance'] - amount
    receiver_new_balance = receiver['balance'] + amount

    users_col.update_one({"_id": ObjectId(sender['_id'])}, {"$set": {"balance": sender_new_balance}})
    users_col.update_one({"_id": ObjectId(receiver['_id'])}, {"$set": {"balance": receiver_new_balance}})

    transactions_col.insert_one({
        'type': f'Sent to {receiver["username"]}',
        'amount': amount,
        'userId': str(sender['_id']),
        'date': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })
    transactions_col.insert_one({
        'type': f'Received from {sender["username"]}',
        'amount': amount,
        'userId': str(receiver['_id']),
        'date': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

    return jsonify({'message': f'₦{amount} sent to {receiver["username"]}', 'balance': sender_new_balance}), 200

# --- GET USER TRANSACTIONS ---
@app.route('/transactions', methods=['POST'])
def get_transactions():
    data = request.get_json()
    user_id = str(data.get('userId'))
    user_tx = list(transactions_col.find({"userId": user_id}))
    for tx in user_tx:
        tx['_id'] = str(tx['_id'])
    return jsonify(user_tx), 200

# --- GET USER BY ACCOUNT NUMBER ---
@app.route('/user-by-account', methods=['POST'])
def user_by_account():
    data = request.get_json()
    acct = data.get('accountNumber')
    user = users_col.find_one({"account_number": acct})
    if user:
        return jsonify({'username': user['username'], 'userId': str(user['_id'])}), 200
    return jsonify({'message': 'User not found'}), 404

if __name__ == "__main__":
    app.run(debug=True)