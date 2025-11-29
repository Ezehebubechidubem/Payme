# admin.py
import uuid
from datetime import datetime
from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash

admin_bp = Blueprint("admin_bp", __name__)

# Placeholder for DB connector function
get_conn = None

def init_admin(get_conn_func):
    """
    Initialize admin module by passing DB connector function from app.py
    """
    global get_conn
    get_conn = get_conn_func
    init_staff_table()


def init_staff_table():
    """
    Create staff table if it doesn't exist
    """
    if get_conn is None:
        raise RuntimeError("DB connector not initialized. Call init_admin(get_conn) first.")
    
    with get_conn() as conn:
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
        conn.commit()


# ----------------------------
# Staff API Routes
# ----------------------------

@admin_bp.route("/staff/create", methods=["POST"])
def create_staff():
    if get_conn is None:
        return jsonify({"status": "error", "message": "DB not initialized"}), 500

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "message": "JSON required"}), 400

    name = data.get("name", "").strip()
    email = data.get("email", "").strip()
    role = data.get("role", "").strip()
    password = data.get("password", "").strip()

    if not all([name, email, role, password]):
        return jsonify({"status": "error", "message": "All fields are required"}), 400

    # hash the password for security
    password_hash = generate_password_hash(password)

    staff_id = str(uuid.uuid4())
    created_at = datetime.now().isoformat()

    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO staff (id, name, email, role, password, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (staff_id, name, email, role, password_hash, created_at))
            conn.commit()
        return jsonify({"status": "success", "id": staff_id})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@admin_bp.route("/staff/list", methods=["GET"])
def list_staff():
    if get_conn is None:
        return jsonify({"status": "error", "message": "DB not initialized"}), 500

    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, name, email, role FROM staff")
            staff_rows = cur.fetchall()
            staff_list = [dict(row) if hasattr(row, "keys") else {
                "id": row[0],
                "name": row[1],
                "email": row[2],
                "role": row[3]
            } for row in staff_rows]
        return jsonify({"staff": staff_list})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@admin_bp.route("/staff/<staff_id>", methods=["DELETE"])
def delete_staff(staff_id):
    if get_conn is None:
        return jsonify({"status": "error", "message": "DB not initialized"}), 500

    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM staff WHERE id=?", (staff_id,))
            conn.commit()
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500