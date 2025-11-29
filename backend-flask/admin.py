# admin.py
import uuid
import re
import sqlite3
import random
import string
from datetime import datetime
from flask import Blueprint, request, jsonify, current_app
from werkzeug.security import generate_password_hash
import traceback  # <-- for detailed error logs

admin_bp = Blueprint("admin_bp", __name__)
_get_conn = None  # Will be set via init_admin

# ---- initialization ----
def init_admin(get_conn_func):
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

# ---- helpers ----
def _generate_password(length=10):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    return ''.join(random.choice(chars) for _ in range(length))

def _validate_email(email):
    return bool(re.match(r"[^@]+@[^@]+\.[^@]+", email))

def row_to_dict(cur, row):
    """Convert sqlite3 row tuple to dictionary"""
    return {cur.description[i][0]: row[i] for i in range(len(row))}

# ---- staff routes ----
@admin_bp.route("/staff/create", methods=["POST","OPTIONS"])
def create_staff():
    if request.method == "OPTIONS":
        return "", 204
    try:
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

        plain_pw = _generate_password(10)
        hashed = generate_password_hash(plain_pw)
        staff_id = str(uuid.uuid4())
        created_at = datetime.now().isoformat()

        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id FROM staff WHERE email = ?", (email,))
            if cur.fetchone():
                return jsonify({"status":"error","message":"Email already exists"}), 400
            cur.execute(
                "INSERT INTO staff (id, name, email, role, password, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (staff_id, name, email, role, hashed, created_at)
            )
            try: conn.commit()
            except Exception: pass

        return jsonify({
            "status": "success",
            "staff": {"id": staff_id, "name": name, "email": email, "role": role},
            "generated_password": plain_pw
        }), 201
    except Exception as e:
        current_app.logger.error("create_staff failed: %s", traceback.format_exc())
        return jsonify({"status":"error","message":"Failed to create staff, check server logs"}), 500

@admin_bp.route("/staff/list", methods=["GET"])
def list_staff():
    try:
        if _get_conn is None:
            return jsonify({"status":"error","message":"DB not initialized"}), 500
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, name, email, role, created_at FROM staff ORDER BY created_at DESC")
            rows = cur.fetchall()
            staff_list = [row_to_dict(cur,r) for r in rows]
        return jsonify({"status":"success","staff":staff_list}), 200
    except Exception:
        current_app.logger.error("list_staff failed: %s", traceback.format_exc())
        return jsonify({"status":"error","message":"Unable to list staff, check server logs"}), 500

@admin_bp.route("/staff/<staff_id>", methods=["DELETE"])
def delete_staff(staff_id):
    try:
        if _get_conn is None:
            return jsonify({"status":"error","message":"DB not initialized"}), 500
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM staff WHERE id = ?", (staff_id,))
            try: conn.commit()
            except Exception: pass
        return jsonify({"status":"success"}), 200
    except Exception:
        current_app.logger.error("delete_staff failed: %s", traceback.format_exc())
        return jsonify({"status":"error","message":"Failed to delete staff, check server logs"}), 500

# ---- metrics ----
@admin_bp.route("/admin/metrics", methods=["GET"])
def admin_metrics():
    try:
        if _get_conn is None:
            return jsonify({"status":"error","message":"DB not initialized"}), 500
        with _get_conn() as conn:
            cur = conn.cursor()

            # deposits
            cur.execute("SELECT COALESCE(SUM(amount),0) as deposits FROM transactions WHERE type='Deposit'")
            deposits = cur.fetchone()[0]

            # withdrawals
            cur.execute("SELECT COALESCE(SUM(amount),0) as withdrawals FROM transactions WHERE type='Transfer Out'")
            withdrawals = cur.fetchone()[0]

            total_volume = deposits + withdrawals

            # active users
            cur.execute("SELECT COUNT(DISTINCT user_id) as active_users FROM transactions")
            active_users = cur.fetchone()[0]

        return jsonify({
            "status": "success",
            "deposits": deposits,
            "withdrawals": withdrawals,
            "total_volume": total_volume,
            "active_users": active_users
        }), 200
    except Exception:
        current_app.logger.error("admin_metrics failed: %s", traceback.format_exc())
        return jsonify({"status":"error","message":"Failed to fetch metrics, see server logs"}), 500

# ---- recent transactions ----
@admin_bp.route("/admin/recent_tx", methods=["GET"])
def admin_recent_tx():
    try:
        if _get_conn is None:
            return jsonify({"status":"error","message":"DB not initialized"}), 500
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT id, user_id, type, amount, other_party, date 
                FROM transactions ORDER BY id DESC LIMIT 10
            """)
            rows = cur.fetchall()
            result = [row_to_dict(cur,r) for r in rows]

        return jsonify(result), 200
    except Exception:
        current_app.logger.error("admin_recent_tx failed: %s", traceback.format_exc())
        return jsonify({"status":"error","message":"Failed to fetch recent transactions, see server logs"}), 500