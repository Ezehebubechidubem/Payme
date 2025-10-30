# services.py
import threading
import time
import uuid

# Simple thread-safe in-memory store for demo. Replace with DB in production.
_data_lock = threading.Lock()

# users: phone -> user dict
_users = {
    # example:
    # "08010000000": {"phone":"08010000000", "account_number":"0123456789", "username":"joe", "balance":10000.0}
}

# transactions: list of dicts
_transactions = []

def get_user_by_phone(phone):
    if not phone:
        return None
    with _data_lock:
        return _users.get(str(phone))

def get_user_by_account(account_number):
    if not account_number:
        return None
    with _data_lock:
        for user in _users.values():
            if str(user.get("account_number")) == str(account_number):
                return user
    return None

def get_balance(phone):
    user = get_user_by_phone(phone)
    if not user:
        return 0.0
    try:
        return float(user.get("balance", 0.0))
    except Exception:
        return 0.0

def update_balance(phone, delta):
    """Change balance by delta (can be negative). Returns new balance."""
    with _data_lock:
        phone = str(phone)
        user = _users.setdefault(phone, {"phone": phone, "account_number": None, "username": None, "balance": 0.0})
        user["balance"] = float(user.get("balance", 0.0)) + float(delta)
        # avoid negative balances here if desired: uncomment to prevent negative
        # if user["balance"] < 0:
        #     user["balance"] -= float(delta)  # revert
        #     raise ValueError("Insufficient funds")
        return user["balance"]

def register_user(phone, account_number, username, initial_balance=0.0):
    with _data_lock:
        _users[str(phone)] = {
            "phone": str(phone),
            "account_number": str(account_number),
            "username": username,
            "balance": float(initial_balance)
        }
        return _users[str(phone)]

def create_transaction(payload):
    """
    payload: dict with keys like type, sender_phone, receiver_acc, receiver_bank, amount, metadata
    returns transaction_id
    """
    tx = {}
    tx["id"] = str(uuid.uuid4())
    tx["created_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    tx.update(payload or {})
    with _data_lock:
        _transactions.append(tx)
    return tx["id"]

def list_transactions(limit=50):
    with _data_lock:
        return list(_transactions[-limit:])