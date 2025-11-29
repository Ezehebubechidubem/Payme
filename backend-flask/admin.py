# admin.py
import uuid
from datetime import datetime
from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash
import random
import string

admin_bp = Blueprint("admin", __name__)

# This will be initialized from app.py
get_conn = None

def init_admin(conn_func):
    """Pass the DB connector function from app.py"""
    global get_conn
    get_conn = conn_func
    # Ensure staff table exists
    init_staff_table()

def init_staff_table():
    """Create staff table if not exists"""
    if get_conn is None:
        raise RuntimeError("DB connector not initialized. Call init_admin(get_conn)")
    
    with get_conn() as conn:
        cur = conn.cursor()
        try:
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
            if hasattr(conn, "commit"):
                conn.commit()
        except Exception as e:
            print("Error creating staff table:", e)

def generate_password(length=10):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    return ''.join(random.choice(chars) for _ in range(length))

# ----------------------------
# Routes
# ----------------------------

@admin_bp.route("/staff/create", methods=["POST"])
def create_staff():
    if not request.is_json:
        return jsonify({"status": "error", "message": "Content-Type must be application/json"}), 400
    
    data = request.get_json()
    name = data.get("name", "").strip()
    email = data.get("email", "").strip()
    role = data.get("role", "").strip()

    if not all([name, email, role]):
        return jsonify({"status": "error", "message": "All fields are required"}), 400

    password_plain = generate_password()
    password_hash = generate_password_hash(password_plain)

    staff_id = str(uuid.uuid4())
    created_at = datetime.now().isoformat()

    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO staff (id, name, email, role, password, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (staff_id, name, email, role, password_hash, created_at)
            )
            if hasattr(conn, "commit"):
                conn.commit()
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

    return jsonify({
        "status": "success",
        "staff": {"id": staff_id, "name": name, "email": email, "role": role},
        "password": password_plain  # send plain password to frontend to display once
    })

@admin_bp.route("/staff/list", methods=["GET"])
def list_staff():
    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, name, email, role FROM staff")
            staff_list = [dict(row) for row in cur.fetchall()]
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    return jsonify({"status": "success", "staff": staff_list})

@admin_bp.route("/staff/<staff_id>", methods=["DELETE"])
def delete_staff(staff_id):
    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM staff WHERE id=?", (staff_id,))
            if hasattr(conn, "commit"):
                conn.commit()
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    return jsonify({"status": "success"})