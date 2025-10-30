# services.py
import threading

# Simple in-memory store for demo. Replace with DB in production.
_data_lock = threading.Lock()
_users = {
    # phone: { account_number: '...', balance: 10000, username: 'joe' }
}

def get_user_by_phone(phone):
    return _users.get(phone)

def get_balance(phone):
    user = get_user_by_phone(phone)
    return float(user.get("balance", 0)) if user else 0.0

def update_balance(phone, delta):
    """Change balance by delta (can be negative)."""
    with _data_lock:
        user = _users.setdefault(phone, {"balance": 0.0})
        user["balance"] = float(user.get("balance", 0)) + float(delta)
        return user["balance"]

def register_user(phone, account_number, username, initial_balance=0):
    with _data_lock:
        _users[phone] = {
            "phone": phone,
            "account_number": account_number,
            "username": username,
            "balance": float(initial_balance)
        }