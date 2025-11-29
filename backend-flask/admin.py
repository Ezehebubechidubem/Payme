# admin.py
import uuid
import re
import random
import string
from datetime import datetime
from flask import Blueprint, request, jsonify, current_app
from werkzeug.security import generate_password_hash

admin_bp = Blueprint("admin_bp", __name__)
_get_conn = None

# Initialize admin module by injecting get_conn function from app.py
def init_admin(get_conn_func):
    global _get_conn
    _get_conn = get_conn_func
    # ensure table exists (app.py may also already create it)
    try:
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
            try:
                conn.commit()
            except Exception:
                pass
    except Exception as e:
        current_app.logger.exception("init_admin/create table failed: %s", e)
        raise

# ---- utilities ----
def _generate_password(length=10):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    return ''.join(random.choice(chars) for _ in range(length))

def _validate_email(email):
    return bool(re.match(r"[^@]+@[^@]+\.[^@]+", email))

# ---- routes ----

@admin_bp.route("/staff/create", methods=["POST", "OPTIONS"])
def create_staff():
    # allow OPTIONS for CORS preflight
    if request.method == "OPTIONS":
        return "", 204

    if _get_conn is None:
        return jsonify({"status":"error","message":"DB not initialized"}), 500

    if not request.is_json:
        return jsonify({"status":"error","message":"Content-Type must be application/json"}), 400

    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    role = (data.get("role") or "").strip()

    if not name or not email or not role:
        return jsonify({"status":"error","message":"All fields are required"}), 400

    if not _validate_email(email):
        return jsonify({"status":"error","message":"Invalid email address"}), 400

    # generate password and hash it
    plain_pw = _generate_password(10)
    hashed = generate_password_hash(plain_pw)
    staff_id = str(uuid.uuid4())
    created_at = datetime.now().isoformat()

    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            # check for duplicate email
            cur.execute("SELECT id FROM staff WHERE email = ?", (email,))
            if cur.fetchone():
                return jsonify({"status":"error","message":"Email already exists"}), 400

            cur.execute(
                "INSERT INTO staff (id, name, email, role, password, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (staff_id, name, email, role, hashed, created_at)
            )
            try:
                conn.commit()
            except Exception:
                pass

    except Exception as e:
        current_app.logger.exception("create_staff failed: %s", e)
        return jsonify({"status":"error","message":"Failed to create staff (see server logs)"}), 500

    # return the plaintext password only once for admin to show to staff
    return jsonify({
        "status": "success",
        "staff": {"id": staff_id, "name": name, "email": email, "role": role},
        "generated_password": plain_pw
    }), 201

@admin_bp.route("/staff/list", methods=["GET"])
def list_staff():
    if _get_conn is None:
        return jsonify({"status":"error","message":"DB not initialized"}), 500
    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, name, email, role, created_at FROM staff ORDER BY created_at DESC")
            rows = cur.fetchall()
            staff_list = []
            for r in rows:
                # sqlite3.Row -> supports keys(); psycopg2 -> dict-like
                if hasattr(r, "keys"):
                    staff_list.append({k: r[k] for k in r.keys()})
                elif isinstance(r, dict):
                    staff_list.append(r)
                else:
                    staff_list.append({
                        "id": r[0], "name": r[1], "email": r[2], "role": r[3],
                        "created_at": r[4] if len(r) > 4 else None
                    })
    except Exception as e:
        current_app.logger.exception("list_staff failed: %s", e)
        return jsonify({"status":"error","message":"Unable to list staff"}), 500
    return jsonify({"status":"success","staff": staff_list}), 200

@admin_bp.route("/staff/<staff_id>", methods=["DELETE"])
def delete_staff(staff_id):
    if _get_conn is None:
        return jsonify({"status":"error","message":"DB not initialized"}), 500
    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM staff WHERE id = ?", (staff_id,))
            try:
                conn.commit()
            except Exception:
                pass
    except Exception as e:
        current_app.logger.exception("delete_staff failed: %s", e)
        return jsonify({"status":"error","message":"Failed to delete staff"}), 500
    return jsonify({"status":"success"}), 200

# ---- small debug helper inside admin blueprint (optional) ----
@admin_bp.route("/staff/debug_echo", methods=["POST","OPTIONS"])
def staff_debug_echo():
    if request.method == "OPTIONS":
        return "", 204
    return jsonify({
        "received": request.get_json(silent=True),
        "headers": dict(request.headers),
        "method": request.method
    })
@app.route("/admin/recent_tx", methods=["GET"])
def admin_recent_tx():
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT id, user_id, type, amount, other_party, date 
            FROM transactions ORDER BY id DESC LIMIT 10
        """)
        rows = cur.fetchall()

    result = [
        {
            "id": r["id"],
            "type": r["type"],
            "amount": r["amount"],
            "other_party": r["other_party"],
            "date": r["date"]
        }
        for r in rows
    ]

    return jsonify(result), 200