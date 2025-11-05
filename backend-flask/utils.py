# utils.py
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

# Business constants (tweak as needed)
PIN_LENGTH = 4
LOCK_THRESHOLD = 4
LOCK_DURATION = timedelta(hours=4)
CODE_TTL_SECONDS = 10 * 60  # 10 minutes for 6-digit verification codes

# PIN helpers
def hash_pin(pin: str) -> str:
    if not pin or not pin.isdigit() or len(pin) != PIN_LENGTH:
        raise ValueError("PIN must be exactly %d digits" % PIN_LENGTH)
    return generate_password_hash(pin)

def verify_pin_hash(hashed: str, pin: str) -> bool:
    if not hashed or not pin:
        return False
    return check_password_hash(hashed, pin)

def is_locked(user) -> (bool, 'datetime|None'):
    """Return (locked_bool, locked_until_datetime_or_None)."""
    if not user:
        return False, None
    if user.locked_until and user.locked_until > datetime.utcnow():
        return True, user.locked_until
    return False, None

def register_failed_attempt(user, DB):
    """
    Increment failed_attempts and lock if threshold reached.
    DB: SQLAlchemy instance (models.DB)
    """
    try:
        user.failed_attempts = (user.failed_attempts or 0) + 1
        if user.failed_attempts >= LOCK_THRESHOLD:
            user.locked_until = datetime.utcnow() + LOCK_DURATION
            user.failed_attempts = 0  # reset after locking (optional)
        DB.session.add(user)
        DB.session.commit()
    except Exception:
        DB.session.rollback()
        raise

def reset_attempts_and_unlock(user, DB):
    user.failed_attempts = 0
    user.locked_until = None
    DB.session.add(user)
    DB.session.commit()