# admin.py
import uuid
import random
import string
import re
from datetime import datetime
from flask import Blueprint, request, jsonify, current_app
from werkzeug.security import generate_password_hash

admin_bp = Blueprint("admin_bp", __name__)

# Will be set by init_admin(get_conn) from app.py
_get_conn = None

def init_admin(get_conn_func):
    """
    Inject the DB connector function from app.py.
    Call this from app.py AFTER get_conn() is defined:
        from admin import admin_bp, init_admin
        init_admin(get_conn)
        app.register_blueprint(admin_bp, url_prefix="/api")
    """
    global _get_conn
    _get_conn = get_conn_func
    # ensure staff table exists
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
        current_app.logger.info("admin.init_admin: staff table ensured")
    except Exception as e:
        # If current_app isn't available during import, fallback to print
        try:
            current_app.logger.exception("admin.init_admin failed: %s", e)
        except Exception:
            print("admin.init_admin failed:", e)
        raise

# -------------------------
# Helpers
# -------------------------
_email_re = re.compile(r"[^@]+@[^@]+\.[^@]+")

def _is_email(s):
    return bool(s and _email_re.match(s))

def _rand_password(length=10):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    return ''.join(random.choice(chars) for _ in range(length))

def _row_to_dict(r):
    if r is None:
        return None
    if hasattr(r, "keys"):
        return {k: r[k] for k in r.keys()}
    if isinstance(r, dict):
        return r
    if isinstance(r, (list, tuple)):
        return {
            "id": r[0] if len(r) > 0 else None,
            "name": r[1] if len(r) > 1 else None,
            "email": r[2] if len(r) > 2 else None,
            "role": r[3] if len(r) > 3 else None
        }
    return dict(r)

# -------------------------
# Routes (admin/staff)
# -------------------------

@admin_bp.route("/staff/create", methods=["POST", "OPTIONS"])
def staff_create():
    if request.method == "OPTIONS":
        return "", 204

    if _get_conn is None:
        return jsonify({"status":"error","message":"DB connector not initialized"}), 500

    if not request.is_json:
        return jsonify({"status":"error","message":"JSON required"}), 400

    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    role = (data.get("role") or "").strip()

    if not name or not email or not role:
        return jsonify({"status":"error","message":"All fields are required"}), 400

    if not _is_email(email):
        return jsonify({"status":"error","message":"Invalid email"}), 400

    plain_pw = _rand_password(10)
    hashed_pw = generate_password_hash(plain_pw)
    staff_id = str(uuid.uuid4())
    created_at = datetime.utcnow().isoformat()

    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            # friendly duplicate check
            cur.execute("SELECT id FROM staff WHERE email = ?", (email,))
            if cur.fetchone():
                return jsonify({"status":"error","message":"Email already exists"}), 400

            cur.execute(
                "INSERT INTO staff (id, name, email, role, password, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (staff_id, name, email, role, hashed_pw, created_at)
            )
            try:
                conn.commit()
            except Exception:
                pass
    except Exception as e:
        current_app.logger.exception("staff_create failed: %s", e)
        return jsonify({"status":"error","message":"Failed to create staff"}), 500

    # IMPORTANT: return plain password only once
    return jsonify({
        "status": "success",
        "staff": {"id": staff_id, "name": name, "email": email, "role": role},
        "generated_password": plain_pw
    }), 201

@admin_bp.route("/staff/list", methods=["GET"])
def staff_list():
    if _get_conn is None:
        return jsonify({"status":"error","message":"DB connector not initialized"}), 500
    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, name, email, role, created_at FROM staff ORDER BY created_at DESC")
            rows = cur.fetchall()
            out = []
            for r in rows:
                out.append(_row_to_dict(r))
    except Exception as e:
        current_app.logger.exception("staff_list failed: %s", e)
        return jsonify({"status":"error","message":"Unable to list staff"}), 500
    return jsonify({"status":"success","staff": out}), 200

@admin_bp.route("/staff/<staff_id>", methods=["DELETE"])
def staff_delete(staff_id):
    if _get_conn is None:
        return jsonify({"status":"error","message":"DB connector not initialized"}), 500
    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM staff WHERE id = ?", (staff_id,))
            try:
                conn.commit()
            except Exception:
                pass
    except Exception as e:
        current_app.logger.exception("staff_delete failed: %s", e)
        return jsonify({"status":"error","message":"Failed to delete staff"}), 500
    return jsonify({"status":"success"}), 200

# optional debug endpoint inside this blueprint (only for dev)
@admin_bp.route("/staff/debug_echo", methods=["POST","OPTIONS"])
def staff_debug_echo():
    if request.method == "OPTIONS":
        return "", 204
    return jsonify({
        "received": request.get_json(silent=True),
        "headers": dict(request.headers),
        "method": request.method
    })