from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Simple database (demo only)
users = {
    1: {"username": "EBUBE", "balance": 0}
}

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
