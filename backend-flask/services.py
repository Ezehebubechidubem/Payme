# services.py
import threading
import time
import uuid

_data_lock = threading.Lock()

# users: phone -> user dict
_users = {
    # "08010000000": {"phone":"08010000000", "account_number":"8167542829", "username":"dubem", "balance":10000.0}
}

# transactions list (chronological)
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
    payload: dict containing type, sender_phone, receiver_acc, receiver_bank, amount, status, metadata
    returns transaction_id
    """
    tx = {}
    tx["id"] = str(uuid.uuid4())
    tx["created_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    tx.update(payload or {})
    with _data_lock:
        _transactions.append(tx)
    return tx["id"]

def log_transaction(sender, receiver, amount, status, bank_code, message=""):
    """
    Human readable history log (also stored in transactions list)
    """
    payload = {
        "type": "history",
        "sender_phone": sender,
        "receiver_acc": receiver,
        "amount": amount,
        "bank_code": bank_code,
        "status": status,
        "message": message
    }
    return create_transaction(payload)

def list_transactions(limit=100):
    with _data_lock:
        return list(_transactions[-limit:])

def get_transactions_for_phone(phone):
    with _data_lock:
        return [tx for tx in _transactions if tx.get("sender_phone") == str(phone) or tx.get("receiver_phone") == str(phone)]