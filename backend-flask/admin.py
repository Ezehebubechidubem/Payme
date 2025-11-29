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
    data = request.json
    name = data.get("name")
    email = data.get("email")
    role = data.get("role")

    if not name or not email:
        return jsonify({"status": "error", "message": "Name and Email required"}), 400

    raw_password = generate_password()   # auto 10-digit
    hashed_password = generate_password_hash(raw_password)

    staff_id = str(uuid.uuid4())

    try:
        db_execute("""
            INSERT INTO staff(id,name,email,role,password)
            VALUES(?,?,?,?,?)
        """, (staff_id, name, email, role, hashed_password))

        return jsonify({
            "status": "success",
            "generated_password": raw_password,
            "id": staff_id
        }), 201

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500



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