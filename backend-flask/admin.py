# admin.py
import uuid
from datetime import datetime
from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash
import random
import string

admin_bp = Blueprint("admin", __name__)

# We'll set this later via init_admin(get_conn)
_get_conn = None

def init_admin(get_conn_func):
    """
    Initialize the admin module with a database connector.
    """
    global _get_conn
    _get_conn = get_conn_func

def init_staff_table():
    """
    Creates staff table if it doesn't exist (SQLite or Postgres)
    """
    if not _get_conn:
        raise RuntimeError("Call init_admin(get_conn) first before initializing table.")

    with _get_conn() as conn:
        cur = conn.cursor()
        # Postgres UUID / TIMESTAMP support vs SQLite
        if hasattr(conn, "cursor") and hasattr(conn.cursor(), "execute"):
            # Use the same table creation logic as in your app.py
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
            conn.commit()

def generate_password(length=10):
    """
    Generate a random password with letters, digits, symbols
    """
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    return "".join(random.choice(chars) for _ in range(length))

# --------------------------
# STAFF ROUTES
# --------------------------

@admin_bp.route("/staff/create", methods=["POST"])
def create_staff():
    if not _get_conn:
        return jsonify({"status": "error", "message": "Database not initialized"}), 500

    data = request.get_json(silent=True) or {}
    name = data.get("name", "").strip()
    email = data.get("email", "").strip()
    role = data.get("role", "").strip()

    if not name or not email or not role:
        return jsonify({"status": "error", "message": "All fields are required"}), 400

    password_plain = generate_password()
    password_hashed = generate_password_hash(password_plain)

    staff_id = str(uuid.uuid4())
    created_at = datetime.now().isoformat()

    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO staff (id, name, email, role, password, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (staff_id, name, email, role, password_hashed, created_at))
            conn.commit()
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

    return jsonify({
        "status": "success",
        "staff": {"id": staff_id, "name": name, "email": email, "role": role},
        "generated_password": password_plain
    })

@admin_bp.route("/staff/list", methods=["GET"])
def list_staff():
    if not _get_conn:
        return jsonify({"status": "error", "message": "Database not initialized"}), 500

    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, name, email, role FROM staff ORDER BY created_at DESC")
            rows = cur.fetchall()
            # convert sqlite3.Row or dict-like rows to list of dicts
            staff_list = [dict(row) for row in rows]
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

    return jsonify({"status": "success", "staff": staff_list})

@admin_bp.route("/staff/<staff_id>", methods=["DELETE"])
def remove_staff(staff_id):
    if not _get_conn:
        return jsonify({"status": "error", "message": "Database not initialized"}), 500
    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM staff WHERE id = ?", (staff_id,))
            conn.commit()
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    return jsonify({"status": "success"})