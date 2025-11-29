# admin.py
from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash
import uuid
from datetime import datetime
from app import get_conn  # import your get_conn() from app.py

admin_bp = Blueprint("admin_bp", __name__)

# ----- List Staff -----
@admin_bp.route("/api/staff/list", methods=["GET"])
def list_staff():
    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, name, email, role FROM staff ORDER BY created_at DESC")
            rows = cur.fetchall()
            staff_list = []
            for r in rows:
                staff_list.append({
                    "id": r["id"],
                    "name": r["name"],
                    "email": r["email"],
                    "role": r["role"]
                })
        return jsonify({"staff": staff_list})
    except Exception as e:
        return jsonify({"staff": [], "error": str(e)}), 500

# ----- Create Staff -----
@admin_bp.route("/api/staff/create", methods=["POST"])
def create_staff():
    data = request.get_json()
    name = data.get("name")
    email = data.get("email")
    role = data.get("role")
    password = data.get("password")

    if not name or not email or not role or not password:
        return jsonify({"status": "error", "message": "All fields are required"}), 400

    staff_id = str(uuid.uuid4())
    hashed_password = generate_password_hash(password)

    try:
        with get_conn() as conn:
            cur = conn.cursor()
            # check for duplicate email
            cur.execute("SELECT id FROM staff WHERE email=%s", (email,))
            if cur.fetchone():
                return jsonify({"status": "error", "message": "Email already exists"}), 400

            cur.execute(
                "INSERT INTO staff (id, name, email, role, password, created_at) VALUES (%s,%s,%s,%s,%s,%s)",
                (staff_id, name, email, role, hashed_password, datetime.now())
            )
            conn.commit()

        return jsonify({"status": "success", "staff": {"id": staff_id, "name": name, "email": email, "role": role}})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# ----- Delete Staff -----
@admin_bp.route("/api/staff/<staff_id>", methods=["DELETE"])
def delete_staff(staff_id):
    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM staff WHERE id=%s", (staff_id,))
            if cur.rowcount == 0:
                return jsonify({"status": "error", "message": "Staff not found"}), 404
            conn.commit()
        return jsonify({"status": "success", "message": "Staff removed"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500