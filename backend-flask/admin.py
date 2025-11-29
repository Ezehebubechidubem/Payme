# admin.py
import uuid
import re
import random
import string
from datetime import datetime
from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash

admin_bp = Blueprint("admin_bp", __name__)

# DB connector function will be injected from app.py
_get_conn = None

def init_admin(get_conn_func):
    """
    Inject DB connector function from app.py and ensure table exists.
    Usage in app.py (after get_conn is defined):
        from admin import admin_bp, init_admin
        init_admin(get_conn)
        app.register_blueprint(admin_bp, url_prefix="/api")
    """
    global _get_conn
    _get_conn = get_conn_func
    init_staff_table()

def init_staff_table():
    if _get_conn is None:
        raise RuntimeError("Call init_admin(get_conn) before init_staff_table()")

    with _get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS staff (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            role TEXT NOT NULL,
            password TEXT NOT NULL,
            created_at TEXT
        )
        """)
        # commit for safety (works for both sqlite and postgres contexts)
        try:
            conn.commit()
        except Exception:
            pass


def _generate_password(length=10):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    return ''.join(random.choice(chars) for _ in range(length))


def _validate_email(email: str) -> bool:
    return bool(re.match(r"[^@]+@[^@]+\.[^@]+", email))


# ------------------------
# Routes
# ------------------------

@admin_bp.route("/staff/create", methods=["POST"])
def create_staff():
    if _get_conn is None:
        return jsonify({"status":"error","message":"DB not initialized"}), 500
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    role = (data.get("role") or "").strip()
    if not (name and email and role):
        return jsonify({"status":"error","message":"All fields are required"}), 400

    # generate & hash
    import random, string
    plain_pw = ''.join(random.choice(string.ascii_letters + string.digits + "!@#$%^&*()") for _ in range(10))
    hashed = generate_password_hash(plain_pw)
    sid = str(uuid.uuid4()); created = datetime.now().isoformat()

    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            # check duplicate
            cur.execute("SELECT id FROM staff WHERE email = ?", (email,))
            if cur.fetchone():
                return jsonify({"status":"error","message":"Email already exists"}), 400
            cur.execute("INSERT INTO staff (id,name,email,role,password,created_at) VALUES (?, ?, ?, ?, ?, ?)",
                        (sid, name, email, role, hashed, created))
            try: conn.commit()
            except: pass
    except Exception as e:
        print("create_staff error:", e)
        return jsonify({"status":"error","message":"Failed to create staff"}), 500

    return jsonify({"status":"success","generated_password": plain_pw, "staff": {"id":sid,"name":name,"email":email,"role":role}}), 201

@admin_bp.route("/staff/<staff_id>", methods=["DELETE"])
def delete_staff(staff_id):
    if _get_conn is None:
        return jsonify({"status": "error", "message": "Database connector not initialized"}), 500

    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM staff WHERE id = ?", (staff_id,))
            try:
                conn.commit()
            except Exception:
                pass
    except Exception as e:
        print("delete_staff error:", e)
        return jsonify({"status": "error", "message": "Failed to delete staff"}), 500

    return jsonify({"status": "success"}), 200