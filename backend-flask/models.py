# models.py
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

# NOTE: Do NOT call DB.init_app(app) here — app.py must initialize DB.
DB = SQLAlchemy()

class User(DB.Model):
    __tablename__ = "users"
    id = DB.Column(DB.Integer, primary_key=True)
    username = DB.Column(DB.String(255), unique=True, nullable=True)
    phone = DB.Column(DB.String(255), unique=True, nullable=True)
    password = DB.Column(DB.String(255), nullable=True)
    account_number = DB.Column(DB.String(255), unique=True, nullable=True)
    balance = DB.Column(DB.Numeric, default=0)

    # PIN-related fields
    payment_pin = DB.Column(DB.String(255), nullable=True)   # hashed PIN
    failed_attempts = DB.Column(DB.Integer, default=0)
    locked_until = DB.Column(DB.DateTime, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "phone": self.phone,
            "account_number": self.account_number,
            "balance": float(self.balance) if self.balance is not None else None,
        }

class PinAudit(DB.Model):
    __tablename__ = "pin_audit"
    id = DB.Column(DB.Integer, primary_key=True)
    user_id = DB.Column(DB.Integer, DB.ForeignKey("users.id"), nullable=False)
    event_type = DB.Column(DB.String(50), nullable=False)  # e.g., PIN_SETUP, PIN_VERIFY_FAIL, PIN_LOCK
    meta = DB.Column(DB.JSON, nullable=True)
    created_at = DB.Column(DB.DateTime, default=datetime.utcnow)

class Transaction(DB.Model):
    __tablename__ = "transactions"
    id = DB.Column(DB.Integer, primary_key=True)
    from_user = DB.Column(DB.Integer, DB.ForeignKey("users.id"), nullable=False)
    to_account = DB.Column(DB.String(255), nullable=False)
    amount = DB.Column(DB.Numeric, nullable=False)
    status = DB.Column(DB.String(50), default="PENDING")
    created_at = DB.Column(DB.DateTime, default=datetime.utcnow)