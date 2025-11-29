# admin.py
import uuid
import re
import random
import string
from datetime import datetime
from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash

admin_bp = Blueprint("admin_bp", __name__)

# DB connector function will be injected from app.py
_get_conn = None

def init_admin(get_conn_func):
    """
    Inject DB connector function from app.py and ensure table exists.
    Usage in app.py (after get_conn is defined):
        from admin import admin_bp, init_admin
        init_admin(get_conn)
        app.register_blueprint(admin_bp, url_prefix="/api")
    """
    global _get_conn
    _get_conn = get_conn_func
    init_staff_table()

def init_staff_table():
    if _get_conn is None:
        raise RuntimeError("Call init_admin(get_conn) before init_staff_table()")

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
        # commit for safety (works for both sqlite and postgres contexts)
        try:
            conn.commit()
        except Exception:
            pass


def _generate_password(length=10):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    return ''.join(random.choice(chars) for _ in range(length))


def _validate_email(email: str) -> bool:
    return bool(re.match(r"[^@]+@[^@]+\.[^@]+", email))


# ------------------------
# Routes
# ------------------------

@admin_bp.route("/staff/create", methods=["POST"])
def create_staff():
    if _get_conn is None:
        return jsonify({"status": "error", "message": "Database connector not initialized"}), 500

    if not request.is_json:
        return jsonify({"status": "error", "message": "Content-Type must be application/json"}), 400

    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    role = (data.get("role") or "").strip()

    if not name or not email or not role:
        return jsonify({"status": "error", "message": "All fields are required"}), 400

    if not _validate_email(email):
        return jsonify({"status": "error", "message": "Invalid email address"}), 400

    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            # check duplicate email first (friendly message)
            cur.execute("SELECT id FROM staff WHERE email = ?", (email,))
            if cur.fetchone():
                return jsonify({"status": "error", "message": "Email already exists"}), 400

            # generate password, hash, store
            plain_pw = _generate_password(10)
            hashed_pw = generate_password_hash(plain_pw)
            staff_id = str(uuid.uuid4())
            created_at = datetime.now().isoformat()

            cur.execute(
                "INSERT INTO staff (id, name, email, role, password, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (staff_id, name, email, role, hashed_pw, created_at)
            )
            try:
                conn.commit()
            except Exception:
                pass

    except Exception as e:
        # log server-side (optional) and return friendly error
        print("create_staff error:", e)
        return jsonify({"status": "error", "message": "Failed to create staff"}), 500

    # Return plain password once so frontend can display it
    return jsonify({
        "status": "success",
        "staff": {"id": staff_id, "name": name, "email": email, "role": role},
        "generated_password": plain_pw
    }), 201


@admin_bp.route("/staff/list", methods=["GET"])
def list_staff():
    if _get_conn is None:
        return jsonify({"status": "error", "message": "Database connector not initialized"}), 500

    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, name, email, role, created_at FROM staff ORDER BY created_at DESC")
            rows = cur.fetchall()
            staff_list = []
            for r in rows:
                # support sqlite3.Row and dict-like rows from psycopg2
                if hasattr(r, "keys"):
                    staff_list.append({k: r[k] for k in r.keys()})
                elif isinstance(r, dict):
                    staff_list.append(r)
                else:
                    # tuple fallback
                    staff_list.append({
                        "id": r[0],
                        "name": r[1],
                        "email": r[2],
                        "role": r[3],
                        "created_at": r[4] if len(r) > 4 else None
                    })
    except Exception as e:
        print("list_staff error:", e)
        return jsonify({"status": "error", "message": "Unable to list staff"}), 500

    return jsonify({"status": "success", "staff": staff_list}), 200


@admin_bp.route("/staff/<staff_id>", methods=["DELETE"])
def delete_staff(staff_id):
    if _get_conn is None:
        return jsonify({"status": "error", "message": "Database connector not initialized"}), 500

    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM staff WHERE id = ?", (staff_id,))
            try:
                conn.commit()
            except Exception:
                pass
    except Exception as e:
        print("delete_staff error:", e)
        return jsonify({"status": "error", "message": "Failed to delete staff"}), 500

    return jsonify({"status": "success"}), 200