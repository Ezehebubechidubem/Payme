from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Simple in-memory database (for demo)
users = []  # Each user: {id, username, email, phone, accountNumber, password, balance}

# --- Register ---
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    phone = data.get('phone')
    password = data.get('password')

    if not username or not email or not phone or not password:
        return jsonify({'message': 'All fields are required'}), 400

    if len(phone) != 11 or not phone.isdigit():
        return jsonify({'message': 'Phone must be 11 digits'}), 400

    # Check if phone already exists
    for u in users:
        if u['phone'] == phone:
            return jsonify({'message': 'Phone number already registered'}), 400

    # Account number = full phone number (as-is)
    account_number = phone

    user = {
        'id': len(users) + 1,
        'username': username,
        'email': email,
        'phone': phone,
        'accountNumber': account_number,
        'password': password,
        'balance': 0
    }
    users.append(user)
    return jsonify({'user': user, 'message': 'Registered successfully!'}), 200

# --- Login ---
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    phone = data.get('phone')
    password = data.get('password')

    for user in users:
        if user['phone'] == phone and user['password'] == password:
            return jsonify({'user': user, 'message': 'Login successful!'}), 200

    return jsonify({'message': 'Invalid phone number or password'}), 401

# --- Update Balance ---
@app.route('/update-balance', methods=['POST'])
def update_balance():
    data = request.get_json()
    user_id = data.get('userId')
    amount = data.get('amount')

    for user in users:
        if user['id'] == user_id:
            user['balance'] += float(amount)
            return jsonify({'balance': user['balance'], 'message': 'Balance updated!'}), 200

    return jsonify({'message': 'User not found'}), 404

# --- Send Money ---
@app.route('/send', methods=['POST'])
def send_money():
    data = request.get_json()
    sender_id = data.get('userId')
    receiver_phone = data.get('receiverPhone')
    amount = float(data.get('amount'))

    sender = next((u for u in users if u['id'] == sender_id), None)
    receiver = next((u for u in users if u['phone'] == receiver_phone), None)

    if not sender or not receiver:
        return jsonify({'message': 'Sender or receiver not found'}), 404
    if sender['balance'] < amount:
        return jsonify({'message': 'Insufficient balance'}), 400

    sender['balance'] -= amount
    receiver['balance'] += amount

    return jsonify({'balance': sender['balance'], 'message': f'Sent ₦{amount} to {receiver["username"]}'}), 200

if __name__ == '__main__':
    app.run(debug=True)
