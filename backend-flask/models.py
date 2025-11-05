# utils.py
"""
Utility helpers for PIN handling. Independent and safe to import in pin_routes.py.
"""
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

PIN_LENGTH = 4
MAX_FAILED_ATTEMPTS = 4
LOCK_DURATION = timedelta(hours=4)

def hash_pin(pin: str) -> str:
    if not pin or not pin.isdigit():
        raise ValueError("PIN must be digits")
    return generate_password_hash(pin)

def verify_pin(hashed_pin: str, pin: str) -> bool:
    if not hashed_pin:
        return False
    return check_password_hash(hashed_pin, pin)

def is_locked(user) -> (bool, datetime):
    """Return (locked:bool, until:datetime or None). Expects user.locked_until attribute or None."""
    if not user:
        return False, None
    try:
        if getattr(user, 'locked_until', None) and getattr(user, 'locked_until') > datetime.utcnow():
            return True, user.locked_until
    except Exception:
        pass
    return False, None

def lock_user(user, DB=None):
    """Lock a user and optionally commit via DB.session."""
    user.locked_until = datetime.utcnow() + LOCK_DURATION
    user.failed_attempts = 0
    if DB:
        DB.session.add(user)
        DB.session.commit()
    return user.locked_until

def reset_attempts(user, DB=None):
    user.failed_attempts = 0
    user.locked_until = None
    if DB:
        DB.session.add(user)
        DB.session.commit()
    return True