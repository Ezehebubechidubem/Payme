from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Simple database (demo only)
users = {}  # key = user id, value = user data
next_id = 1

@app.route('/register', methods=['POST'])
def register():
    global next_id
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    # Check if email already exists
    if any(u['email'] == email for u in users.values()):
        return jsonify({"message": "Email already registered!"}), 400

    user = {"id": next_id, "username": username, "email": email, "password": password, "balance": 0}
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
    user_id = data['userId']
    amount = float(data['amount'])
    if users[user_id]['balance'] >= amount:
        users[user_id]['balance'] -= amount
        return jsonify({"message": f"Sent ₦{amount} successfully!", "balance": users[user_id]['balance']})
    else:
        return jsonify({"message": "Insufficient balance!"}), 400

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
