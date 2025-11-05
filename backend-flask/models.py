# models.py
"""
Optional models module. Provides a DB instance (flask_sqlalchemy.SQLAlchemy) that can be
initialized by app.py if you want to centralize DB initialization here:

In app.py:
    from models import DB
    DB.init_app(app)
    with app.app_context():
        DB.create_all()

We define PinAudit here (useful for logging pin events). We keep the User model out,
because your app.py already defines / owns the canonical User model.
"""
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

DB = SQLAlchemy()

class PinAudit(DB.Model):
    __tablename__ = 'pin_audit'
    id = DB.Column(DB.Integer, primary_key=True)
    user_id = DB.Column(DB.Integer, nullable=False)
    action = DB.Column(DB.String(50), nullable=False)
    meta = DB.Column(DB.JSON, nullable=True)
    created_at = DB.Column(DB.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<PinAudit user={self.user_id} action={self.action}>"