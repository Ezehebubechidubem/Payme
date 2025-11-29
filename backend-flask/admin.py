# admin.py
import uuid
from datetime import datetime
from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash
import re

admin_bp = Blueprint("admin", __name__)

# This will be set by init_staff_table or init_admin
_get_conn = None

def init_admin(get_conn_func):
    """Initialize the admin module with a database connector function"""
    global _get_conn
    _get_conn = get_conn_func
    init_staff_table()

def init_staff_table():
    """Create staff table if it doesn't exist"""
    if _get_conn is None:
        raise RuntimeError("Database connector not initialized. Call init_admin(get_conn)")
    
    with _get_conn() as conn:
        cur = conn.cursor()
        # Detect which DB type (Postgres vs SQLite)
        id_type = "UUID" if hasattr(conn, "cursor") and "PG" in str(type(conn)).upper() else "TEXT"
        timestamp_type = "TIMESTAMP" if id_type == "UUID" else "TEXT"

        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS staff (
                id {id_type} PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                role TEXT NOT NULL,
                password TEXT NOT NULL,
                created_at {timestamp_type}
            )
        """)
        conn.commit()

# --- UTILITIES ---
def generate_password(length=10):
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()"
    import random
    return "".join(random.choice(chars) for _ in range(length))

def validate_email(email):
    return bool(re.match(r"[^@]+@[^@]+\.[^@]+", email))

# --- ROUTES ---
@admin_bp.route("/staff/create", methods=["POST"])
def create_staff():
    if _get_conn is None:
        return jsonify({"status":"error","message":"DB not initialized"}), 500
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip()
    role = (data.get("role") or "").strip()
    if not (name and email and role):
        return jsonify({"status":"error","message":"All fields are required"}), 400

    # validate email simple
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({"status":"error","message":"Invalid email"}), 400

    password_plain = generate_password()
    password_hashed = generate_password_hash(password_plain)
    staff_id = str(uuid.uuid4())
    created_at = datetime.now().isoformat()

    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO staff (id, name, email, role, password, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (staff_id, name, email, role, password_hashed, created_at)
            )
            conn.commit()
    except Exception as e:
        msg = str(e)
        # friendly duplicate email handling
        if "UNIQUE" in msg.upper() and "EMAIL" in msg.upper():
            return jsonify({"status":"error","message":"Email already exists"}), 400
        print("create_staff error:", e)   # server logs
        return jsonify({"status":"error","message":msg}), 500

    return jsonify({
        "status":"success",
        "staff":{"id":staff_id,"name":name,"email":email,"role":role},
        "generated_password": password_plain
    }), 201
@admin_bp.route("/staff/list", methods=["GET"])
def list_staff():
    if _get_conn is None:
        return jsonify({"status": "error", "message": "DB not initialized"}), 500
    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, name, email, role FROM staff ORDER BY created_at DESC")
            rows = cur.fetchall()
            # Convert to dict list
            staff_list = []
            for r in rows:
                # if SQLite Row object
                if hasattr(r, "keys"):
                    staff_list.append({k: r[k] for k in r.keys()})
                else:
                    # Postgres dict
                    staff_list.append(r)
        return jsonify({"status": "success", "staff": staff_list})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@admin_bp.route("/staff/<staff_id>", methods=["DELETE"])
def delete_staff(staff_id):
    if _get_conn is None:
        return jsonify({"status": "error", "message": "DB not initialized"}), 500
    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM staff WHERE id = ?", (staff_id,))
            conn.commit()
        return jsonify({"status": "success"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
@admin_bp.route("/staff/debug_create", methods=["POST"])
def debug_create_staff():
    data = request.get_json() or {}
    print("DEBUG create payload:", data)
    # then call same logic as create_staff and print results before return