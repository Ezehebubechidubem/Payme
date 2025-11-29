# admin.py
from flask import Blueprint, request, jsonify
import sqlite3, uuid, secrets
from werkzeug.security import generate_password_hash

admin_bp = Blueprint('admin', __name__)

DB = "database.db"


def init_staff_table():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS staff (
            id TEXT PRIMARY KEY,
            name TEXT,
            email TEXT UNIQUE,
            role TEXT,
            password TEXT
        )
    """)
    conn.commit()
    conn.close()


# ------------------------------
# Helper functions
# ------------------------------
def generate_password():
    return ''.join(secrets.choice("0123456789") for _ in range(10))


def db_execute(query, values=(), fetch=False, many=False):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    if many:
        c.executemany(query, values)
    else:
        c.execute(query, values)

    data = c.fetchall() if fetch else None
    conn.commit()
    conn.close()
    return data


# ------------------------------
# API ROUTES
# ------------------------------

@admin_bp.route("/staff/create", methods=["POST"])
def create_staff():
    data = request.get_json() or {}
    name = data.get("name")
    email = data.get("email")
    role = data.get("role")

    if not name or not email:
        return jsonify({"status": "error", "message": "Name & Email required"}), 400

    generated_password = generate_password()  # auto-generate 10-digit password
    staff_id = str(uuid.uuid4())

    created_at = datetime.now().isoformat()

    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO staff (id, name, email, role, password, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (staff_id, name, email, role, generated_password, created_at))
        conn.commit()

        return jsonify({
            "status": "success",
            "message": "Staff created successfully",
            "password": generated_password  # ⬅️ return password for UI
        }), 201

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

    finally:
        try: conn.close()
        except: pass



@admin_bp.route("/staff/list", methods=["GET"])
def list_staff():
    data = db_execute("SELECT id,name,email,role FROM staff", fetch=True)

    staff = []
    for row in data:
        staff.append({
            "id": row[0],
            "name": row[1],
            "email": row[2],
            "role": row[3]
        })

    return jsonify({"status": "success", "staff": staff})


@admin_bp.route("/staff/<id>", methods=["DELETE"])
def delete_staff(id):
    db_execute("DELETE FROM staff WHERE id=?", (id,))
    return jsonify({"status": "success"})