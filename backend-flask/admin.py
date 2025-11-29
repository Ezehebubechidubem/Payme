# backend_blueprints.py
import uuid
import random
import string
import re
from datetime import datetime
from flask import Blueprint, request, jsonify, current_app
from werkzeug.security import generate_password_hash, check_password_hash

# --- Blueprints ---
admin_bp = Blueprint("admin_bp", __name__)   # mounted at /api (recommended)
auth_bp = Blueprint("auth_bp", __name__)     # mounted at root (for /login)

# DB connector will be injected from app.py by calling init_backend(get_conn)
_get_conn = None

def init_backend(get_conn_func):
    """
    Call this from app.py AFTER get_conn() is defined:
        from backend_blueprints import admin_bp, auth_bp, init_backend
        init_backend(get_conn)
        app.register_blueprint(admin_bp, url_prefix="/api")
        app.register_blueprint(auth_bp)  # exposes /login
    """
    global _get_conn
    _get_conn = get_conn_func
    _ensure_staff_table()

# -------------------------
# Utilities
# -------------------------
def _rand_password(length=10):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    return ''.join(random.choice(chars) for _ in range(length))

_email_re = re.compile(r"[^@]+@[^@]+\.[^@]+")

def _is_email(s):
    return bool(s and _email_re.match(s))

def _row_to_dict(r):
    """
    Convert sqlite3.Row / psycopg2 row / dict / tuple to a simple dict.
    """
    if r is None:
        return None
    # sqlite3.Row supports keys()
    if hasattr(r, "keys"):
        return {k: r[k] for k in r.keys()}
    if isinstance(r, dict):
        return r
    if isinstance(r, (list, tuple)):
        # fallback - best guess (id,name,email,role,...)
        return {
            "id": r[0] if len(r) > 0 else None,
            "name": r[1] if len(r) > 1 else None,
            "email": r[2] if len(r) > 2 else None,
            "role": r[3] if len(r) > 3 else None
        }
    return dict(r)

def _ensure_staff_table():
    if _get_conn is None:
        raise RuntimeError("Database connector not initialized. Call init_backend(get_conn) first.")
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

# -------------------------
# Admin / Staff endpoints (under /api/staff/*)
# -------------------------

@admin_bp.route("/staff/create", methods=["POST", "OPTIONS"])
def staff_create():
    if request.method == "OPTIONS":
        return "", 204
    if _get_conn is None:
        return jsonify({"status":"error","message":"DB not initialized"}), 500

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

    # generate password and hash it
    plain_pw = _rand_password(10)
    hashed_pw = generate_password_hash(plain_pw)
    staff_id = str(uuid.uuid4())
    created_at = datetime.utcnow().isoformat()

    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            # check duplicate
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

    # return the plain password once (frontend shows it once)
    return jsonify({
        "status": "success",
        "staff": {"id": staff_id, "name": name, "email": email, "role": role},
        "generated_password": plain_pw
    }), 201


@admin_bp.route("/staff/list", methods=["GET"])
def staff_list():
    if _get_conn is None:
        return jsonify({"status":"error","message":"DB not initialized"}), 500
    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, name, email, role, created_at FROM staff ORDER BY created_at DESC")
            rows = cur.fetchall()
            staff = []
            for r in rows:
                staff.append(_row_to_dict(r))
    except Exception as e:
        current_app.logger.exception("staff_list failed: %s", e)
        return jsonify({"status":"error","message":"Unable to list staff"}), 500
    return jsonify({"status":"success","staff": staff}), 200


@admin_bp.route("/staff/<staff_id>", methods=["DELETE"])
def staff_delete(staff_id):
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
        current_app.logger.exception("staff_delete failed: %s", e)
        return jsonify({"status":"error","message":"Failed to delete staff"}), 500
    return jsonify({"status":"success"}), 200

# -------------------------
# Authentication (login) endpoint exposed at /login
# - Accepts JSON: { login, password } where login can be email/username/phone
# - Returns 200 + {status: "success", role: "staff", user: {...} } on success
# - 401 on invalid credentials
# -------------------------
@auth_bp.route("/login", methods=["POST", "OPTIONS"])
def login():
    if request.method == "OPTIONS":
        return "", 204
    if _get_conn is None:
        return jsonify({"status":"error","message":"DB not initialized"}), 500
    if not request.is_json:
        return jsonify({"status":"error","message":"JSON required"}), 400

    data = request.get_json() or {}
    login = (data.get("login") or data.get("email") or data.get("username") or "").strip()
    password = data.get("password") or ""

    if not login or not password:
        return jsonify({"status":"error","message":"Login and password required"}), 400

    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            # Try email match first
            if _is_email(login):
                cur.execute("SELECT * FROM staff WHERE email = ?", (login.lower(),))
                row = cur.fetchone()
            else:
                # try username/phone -> in your app's users table you might have different fields.
                # We'll attempt to match staff.email OR staff.name OR staff.id (fallback)
                cur.execute("SELECT * FROM staff WHERE email = ? OR name = ?", (login, login))
                row = cur.fetchone()

            user_row = _row_to_dict(row)
            if not user_row:
                # not in staff table; fallback: optionally check users table if you also have regular users
                # Try users table (if present) - this keeps backward compatibility if login can be user
                try:
                    cur.execute("SELECT * FROM users WHERE email = ? OR username = ? OR phone = ?", (login, login, login))
                    urow = cur.fetchone()
                    u = _row_to_dict(urow)
                    if u and "password" in u and check_password_hash(u.get("password"), password):
                        # normal user
                        return jsonify({"status":"success","role":"user","user": {
                            "id": u.get("id"), "username": u.get("username"), "phone": u.get("phone"),
                            "account_number": u.get("account_number"), "balance": u.get("balance")
                        }}), 200
                except Exception:
                    # ignore users table errors and continue to return 401 below
                    pass

                # no matching user
                return jsonify({"status":"error","message":"Invalid credentials"}), 401

            # We found a staff row; check password
            stored_hash = user_row.get("password")
            if not stored_hash or not check_password_hash(stored_hash, password):
                return jsonify({"status":"error","message":"Invalid credentials"}), 401

            # success - return staff role and minimal user info
            return jsonify({
                "status": "success",
                "role": "staff",
                "user": {
                    "id": user_row.get("id"),
                    "name": user_row.get("name"),
                    "email": user_row.get("email"),
                    "role": user_row.get("role")
                }
            }), 200

    except Exception as e:
        current_app.logger.exception("login failed: %s", e)
        return jsonify({"status":"error","message":"Login failed (server error)"}), 500