# admin.py
import uuid
import re
import string
import random
from datetime import datetime
from flask import Flask, Blueprint, jsonify, request, current_app
from werkzeug.security import generate_password_hash

# --- Admin Blueprint ---
admin_bp = Blueprint("admin_bp", __name__, url_prefix="/admin")

# --- Global connection holder ---
_get_conn = None

# --- Initialize admin module ---
def init_admin(get_conn_func):
    """
    Inject the get_conn function from app.py
    """
    global _get_conn
    _get_conn = get_conn_func

    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute("""
            CREATE TABLE IF NOT EXISTS staff (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                role TEXT NOT NULL,
                staffRole TEXT,             -- added staffRole column
                password TEXT NOT NULL,
                created_at TEXT
            )
            """)
            conn.commit()
    except Exception as e:
        current_app.logger.exception("init_admin failed: %s", e)
        raise

# --- Utilities ---
def _generate_password(length=10):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    return ''.join(random.choice(chars) for _ in range(length))

def _validate_email(email):
    return bool(re.match(r"[^@]+@[^@]+\.[^@]+", email))

# --- Staff Routes ---
@admin_bp.route("/staff/create", methods=["POST","OPTIONS"])
def create_staff():
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
    staff_role = (data.get("staffRole") or "").strip()  # added staffRole support

    if not name or not email or not role:
        return jsonify({"status":"error","message":"All fields are required"}), 400

    if not _validate_email(email):
        return jsonify({"status":"error","message":"Invalid email address"}), 400

    plain_pw = _generate_password(10)
    hashed = generate_password_hash(plain_pw)
    staff_id = str(uuid.uuid4())
    created_at = datetime.now().isoformat()

    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id FROM staff WHERE email = ?", (email,))
            if cur.fetchone():
                return jsonify({"status":"error","message":"Email already exists"}), 400

            cur.execute(
                "INSERT INTO staff (id, name, email, role, staffRole, password, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (staff_id, name, email, role, staff_role, hashed, created_at)
            )
            conn.commit()
    except Exception as e:
        current_app.logger.exception("create_staff failed: %s", e)
        return jsonify({"status":"error","message":"Failed to create staff"}), 500

    return jsonify({
        "status": "success",
        "staff": {"id": staff_id, "name": name, "email": email, "role": role, "staffRole": staff_role},
        "generated_password": plain_pw
    }), 201

@admin_bp.route("/staff/list", methods=["GET"])
def list_staff():
    if _get_conn is None:
        return jsonify({"status":"error","message":"DB not initialized"}), 500

    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            # Keep original logic exactly, only select staffRole too
            cur.execute("SELECT id, name, email, role, staffRole, created_at FROM staff ORDER BY created_at DESC")
            rows = cur.fetchall()
            staff_list = []
            for r in rows:
                if hasattr(r, "keys"):
                    staff_list.append({k: r[k] for k in r.keys()})
                elif isinstance(r, dict):
                    staff_list.append(r)
                else:
                    staff_list.append({
                        "id": r[0], "name": r[1], "email": r[2], "role": r[3],
                        "staffRole": r[4],
                        "created_at": r[5] if len(r) > 5 else None
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
            conn.commit()
    except Exception as e:
        current_app.logger.exception("delete_staff failed: %s", e)
        return jsonify({"status":"error","message":"Failed to delete staff"}), 500

    return jsonify({"status":"success"}), 200

@admin_bp.route("/staff/debug_echo", methods=["POST","OPTIONS"])
def staff_debug_echo():
    if request.method == "OPTIONS":
        return "", 204
    return jsonify({
        "received": request.get_json(silent=True),
        "headers": dict(request.headers),
        "method": request.method
    })

# --- Admin Metrics ---
@admin_bp.route("/metrics", methods=["GET","OPTIONS"])
def admin_metrics():
    if _get_conn is None:
        return jsonify({"status":"error","message":"DB not initialized"}), 500

    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT COALESCE(SUM(amount),0) as deposits FROM transactions WHERE type='Deposit'")
            deposits = cur.fetchone()["deposits"]
            cur.execute("SELECT COALESCE(SUM(amount),0) as withdrawals FROM transactions WHERE type='Transfer Out'")
            withdrawals = cur.fetchone()["withdrawals"]
            total_volume = deposits + withdrawals
            cur.execute("SELECT COUNT(DISTINCT user_id) as active_users FROM transactions")
            active_users = cur.fetchone()["active_users"]
    except Exception as e:
        current_app.logger.exception("admin_metrics failed: %s", e)
        return jsonify({"status":"error","message":"Failed to fetch metrics"}), 500

    return jsonify({
        "status": "success",
        "deposits": deposits,
        "withdrawals": withdrawals,
        "total_volume": total_volume,
        "active_users": active_users
    }), 200

# --- Admin Recent Transactions ---
@admin_bp.route("/recent_tx", methods=["GET","OPTIONS"])
def admin_recent_tx():
    if _get_conn is None:
        return jsonify({"status":"error","message":"DB not initialized"}), 500

    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT id, user_id, type, amount, other_party, date 
                FROM transactions ORDER BY id DESC LIMIT 10
            """)
            rows = cur.fetchall()
            result = []
            for r in rows:
                row_dict = r if isinstance(r, dict) else {k: r[k] for k in r.keys()} if hasattr(r,"keys") else {}
                result.append({
                    "id": row_dict.get("id","-"),
                    "type": row_dict.get("type","-"),
                    "amount": float(row_dict.get("amount",0)),
                    "other_party": row_dict.get("other_party","-"),
                    "date": row_dict.get("date","-")
                })
    except Exception as e:
        current_app.logger.exception("admin_recent_tx failed: %s", e)
        return jsonify({"status":"error","message":"Failed to fetch recent transactions"}), 500

    return jsonify(result), 200

# --- To use blueprint in main app.py ---
# from admin import admin_bp, init_admin
# app.register_blueprint(admin_bp)
# init_admin(get_conn)