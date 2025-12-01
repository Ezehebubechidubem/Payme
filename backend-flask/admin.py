# admin.py
import uuid
import re
import string
import random
import os
import logging
from datetime import datetime
from flask import Blueprint, jsonify, request, current_app, send_from_directory, session
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename

# --- Admin Blueprint ---
admin_bp = Blueprint("admin_bp", __name__, url_prefix="/admin")

# --- Logging setup note ---
logger = logging.getLogger("admin_bp")

# --- CORS: after_request hook (minimal, echoes Origin for credentials support) ---
@admin_bp.after_request
def add_cors_headers(response):
    # Echo the Origin header so credentials can be used by the browser.
    origin = request.headers.get("Origin", "*")
    response.headers["Access-Control-Allow-Origin"] = origin
    response.headers["Access-Control-Allow-Credentials"] = "true"
    # Include common headers your frontend might send
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With, Accept, X-Debug"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    try:
        if request.method == "OPTIONS":
            current_app.logger.debug(f"[CORS] OPTIONS handled for {request.path} Origin={origin} AC-Req-Method={request.headers.get('Access-Control-Request-Method')}")
    except Exception:
        pass
    return response

# --- Small request logger to help debug 405/OPTIONS issues ---
@admin_bp.before_app_request
def log_incoming_request():
    try:
        origin = request.headers.get("Origin")
        content_type = request.headers.get("Content-Type")
        acr_method = request.headers.get("Access-Control-Request-Method")
        acr_headers = request.headers.get("Access-Control-Request-Headers")
        current_app.logger.debug(f"[ADMIN_REQ] {request.remote_addr} -> {request.method} {request.path} Origin={origin} Content-Type={content_type} AC-Req-Method={acr_method} AC-Req-Headers={acr_headers}")
    except Exception:
        pass

# --- Global connection holder (injected by main app) ---
_get_conn = None

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
                password TEXT NOT NULL,
                created_at TEXT
            )
            """)
            conn.commit()

            cur.execute("""
            CREATE TABLE IF NOT EXISTS announcements (
                id TEXT PRIMARY KEY,
                title TEXT,
                body TEXT,
                target TEXT,
                image_path TEXT,
                created_at TEXT,
                expires_at TEXT,
                status TEXT,
                created_by TEXT
            )
            """)
            conn.commit()

            current_app.logger.debug("init_admin: DB tables ensured")
    except Exception as e:
        current_app.logger.exception("init_admin failed: %s", e)
        raise

# --- Utilities ---
def _generate_password(length=10):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    return ''.join(random.choice(chars) for _ in range(length))

def _validate_email(email):
    return bool(re.match(r"[^@]+@[^@]+\.[^@]+", email))

def _debug_in_response(data):
    """
    If the requester included debug=1 in query or X-Debug header, include debug info in JSON responses.
    """
    if request.args.get("debug") == "1" or request.headers.get("X-Debug") == "1":
        return {"debug_request": {
            "method": request.method,
            "path": request.path,
            "headers_sample": {
                "Origin": request.headers.get("Origin"),
                "Content-Type": request.headers.get("Content-Type"),
                "Accept": request.headers.get("Accept"),
                "Access-Control-Request-Method": request.headers.get("Access-Control-Request-Method")
            }
        }, **data}
    return data

# --- Staff Routes (unchanged pattern; example working endpoints) ---
@admin_bp.route("/staff/create", methods=["POST","OPTIONS"])
def create_staff():
    if request.method == "OPTIONS":
        return "", 204

    current_app.logger.debug("create_staff called")
    if _get_conn is None:
        current_app.logger.error("create_staff: DB not initialized")
        return jsonify(_debug_in_response({"status":"error","message":"DB not initialized"})), 500

    if not request.is_json:
        current_app.logger.debug("create_staff: bad content-type (not JSON)")
        return jsonify(_debug_in_response({"status":"error","message":"Content-Type must be application/json"})), 400

    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    role = (data.get("role") or "").strip()

    if not name or not email or not role:
        current_app.logger.debug("create_staff: missing fields")
        return jsonify(_debug_in_response({"status":"error","message":"All fields are required"})), 400

    if not _validate_email(email):
        current_app.logger.debug("create_staff: invalid email %s", email)
        return jsonify(_debug_in_response({"status":"error","message":"Invalid email address"})), 400

    plain_pw = _generate_password(10)
    hashed = generate_password_hash(plain_pw)
    staff_id = str(uuid.uuid4())
    created_at = datetime.now().isoformat()

    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id FROM staff WHERE email = ?", (email,))
            if cur.fetchone():
                current_app.logger.debug("create_staff: email already exists %s", email)
                return jsonify(_debug_in_response({"status":"error","message":"Email already exists"})), 400

            cur.execute(
                "INSERT INTO staff (id, name, email, role, password, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (staff_id, name, email, role, hashed, created_at)
            )
            conn.commit()
            current_app.logger.info("create_staff: created staff %s", email)
    except Exception as e:
        current_app.logger.exception("create_staff failed: %s", e)
        return jsonify(_debug_in_response({"status":"error","message":"Failed to create staff"})), 500

    return jsonify({"status": "success",
                    "staff": {"id": staff_id, "name": name, "email": email, "role": role},
                    "generated_password": plain_pw}), 201

@admin_bp.route("/staff/list", methods=["GET","OPTIONS"])
def list_staff():
    if request.method == "OPTIONS":
        return "", 204

    current_app.logger.debug("list_staff called")
    if _get_conn is None:
        current_app.logger.error("list_staff: DB not initialized")
        return jsonify(_debug_in_response({"status":"error","message":"DB not initialized"})), 500

    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, name, email, role, created_at FROM staff ORDER BY created_at DESC")
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
                        "created_at": r[4] if len(r) > 4 else None
                    })
            current_app.logger.debug("list_staff: returned %d rows", len(staff_list))
    except Exception as e:
        current_app.logger.exception("list_staff failed: %s", e)
        return jsonify(_debug_in_response({"status":"error","message":"Unable to list staff"})), 500
    return jsonify({"status":"success","staff": staff_list}), 200

@admin_bp.route("/staff/<staff_id>", methods=["DELETE","OPTIONS"])
def delete_staff(staff_id):
    if request.method == "OPTIONS":
        return "", 204

    current_app.logger.debug("delete_staff called id=%s", staff_id)
    if _get_conn is None:
        current_app.logger.error("delete_staff: DB not initialized")
        return jsonify(_debug_in_response({"status":"error","message":"DB not initialized"})), 500

    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM staff WHERE id = ?", (staff_id,))
            conn.commit()
            current_app.logger.info("delete_staff: deleted id=%s rowcount=%s", staff_id, getattr(cur, "rowcount", None))
    except Exception as e:
        current_app.logger.exception("delete_staff failed: %s", e)
        return jsonify(_debug_in_response({"status":"error","message":"Failed to delete staff"})), 500

    return jsonify({"status":"success"}), 200

@admin_bp.route("/staff/debug_echo", methods=["POST","OPTIONS"])
def staff_debug_echo():
    if request.method == "OPTIONS":
        return "", 204
    current_app.logger.debug("staff_debug_echo called")
    return jsonify({
        "received": request.get_json(silent=True),
        "headers": {k: request.headers.get(k) for k in ("Origin","Content-Type","Accept","X-Requested-With","X-Debug")},
        "method": request.method,
        "path": request.path
    })

# --- Admin Metrics & utility routes ---
@admin_bp.route("/metrics", methods=["GET","OPTIONS"])
def admin_metrics():
    if request.method == "OPTIONS":
        return "", 204

    current_app.logger.debug("admin_metrics called")
    if _get_conn is None:
        current_app.logger.error("admin_metrics: DB not initialized")
        return jsonify(_debug_in_response({"status":"error","message":"DB not initialized"})), 500

    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT COALESCE(SUM(amount),0) as deposits FROM transactions WHERE type='Deposit'")
            row = cur.fetchone()
            deposits = row["deposits"] if hasattr(row, "keys") else (row[0] if row and len(row) > 0 else 0)

            cur.execute("SELECT COALESCE(SUM(amount),0) as withdrawals FROM transactions WHERE type='Transfer Out'")
            row = cur.fetchone()
            withdrawals = row["withdrawals"] if hasattr(row, "keys") else (row[0] if row and len(row) > 0 else 0)

            total_volume = (deposits or 0) + (withdrawals or 0)

            cur.execute("SELECT COUNT(DISTINCT user_id) as active_users FROM transactions")
            row = cur.fetchone()
            active_users = row["active_users"] if hasattr(row, "keys") else (row[0] if row and len(row) > 0 else 0)

            current_app.logger.debug("admin_metrics: deposits=%s withdrawals=%s active_users=%s", deposits, withdrawals, active_users)
    except Exception as e:
        current_app.logger.exception("admin_metrics failed: %s", e)
        return jsonify(_debug_in_response({"status":"error","message":"Failed to fetch metrics"})), 500

    return jsonify({
        "status": "success",
        "deposits": deposits,
        "withdrawals": withdrawals,
        "total_volume": total_volume,
        "active_users": active_users
    }), 200

@admin_bp.route("/recent_tx", methods=["GET","OPTIONS"])
def admin_recent_tx():
    if request.method == "OPTIONS":
        return "", 204

    current_app.logger.debug("admin_recent_tx called")
    if _get_conn is None:
        current_app.logger.error("admin_recent_tx: DB not initialized")
        return jsonify(_debug_in_response({"status":"error","message":"DB not initialized"})), 500

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
            current_app.logger.debug("admin_recent_tx: returning %d rows", len(result))
    except Exception as e:
        current_app.logger.exception("admin_recent_tx failed: %s", e)
        return jsonify(_debug_in_response({"status":"error","message":"Failed to fetch recent transactions"})), 500

    return jsonify(result), 200

@admin_bp.route("/daily_summary", methods=["GET","OPTIONS"])
def daily_summary():
    if request.method == "OPTIONS":
        return "", 204

    current_app.logger.debug("daily_summary called")
    with _get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT DATE(date) as day,
                   COALESCE(SUM(CASE WHEN type='Deposit' THEN amount END),0) as deposits,
                   COALESCE(SUM(CASE WHEN type='Transfer Out' THEN amount END),0) as withdrawals,
                   COALESCE(SUM(amount),0) as total
            FROM transactions
            WHERE date >= DATE('now','-6 days')
            GROUP BY DATE(date)
            ORDER BY day DESC
        """)
        rows = cur.fetchall()
        summary = [{"day": r["day"], "deposits": r["deposits"], "withdrawals": r["withdrawals"], "total": r["total"]} for r in rows]
        current_app.logger.debug("daily_summary: rows=%d", len(summary))
    return jsonify({"status":"success","summary":summary})

# -----------------------------------------
# Announcements backend (arranged like staff routes)
# -----------------------------------------

# Upload configuration
UPLOAD_BASE = os.environ.get("UPLOAD_BASE", "uploads")
ANN_UPLOAD_DIR = os.path.join(UPLOAD_BASE, "announcements")
os.makedirs(ANN_UPLOAD_DIR, exist_ok=True)

ALLOWED_EXTS = {"png", "jpg", "jpeg", "gif", "webp"}

def allowed_file(filename):
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    return ext in ALLOWED_EXTS

def _require_staff_or_admin():
    # Simple check using session flags (adjust depending on your auth)
    if session.get("is_admin") or session.get("is_staff"):
        return True
    return False

@admin_bp.route("/announcements", methods=["POST","OPTIONS"])
def create_announcement():
    if request.method == "OPTIONS":
        return "", 204

    current_app.logger.debug("create_announcement called; headers sample: Origin=%s Content-Type=%s", request.headers.get("Origin"), request.headers.get("Content-Type"))

    if _get_conn is None:
        current_app.logger.error("create_announcement: DB not initialized")
        return jsonify(_debug_in_response({"status":"error","message":"DB not initialized"})), 500

    if not _require_staff_or_admin():
        current_app.logger.warning("create_announcement: unauthorized access attempt")
        return jsonify(_debug_in_response({"status":"error","message":"unauthorized"})), 401

    title = (request.form.get("title") or "").strip()
    body = (request.form.get("body") or "").strip()
    target = (request.form.get("target") or "all").strip()
    created_at = request.form.get("createdAt") or datetime.now().isoformat()
    expires_at = request.form.get("expiresAt") or None

    image_path = None
    if "image" in request.files:
        f = request.files["image"]
        if f and f.filename:
            if not allowed_file(f.filename):
                current_app.logger.debug("create_announcement: invalid file type for filename=%s", f.filename)
                return jsonify(_debug_in_response({"status":"error","message":"invalid file type"})), 400
            filename = secure_filename(f.filename)
            uid_name = uuid.uuid4().hex
            ext = filename.rsplit(".", 1)[-1].lower()
            saved_name = f"{uid_name}.{ext}"
            saved_path = os.path.join(ANN_UPLOAD_DIR, saved_name)
            try:
                f.save(saved_path)
                image_path = saved_name
                current_app.logger.debug("create_announcement: saved image to %s", saved_path)
            except Exception as e:
                current_app.logger.exception("Failed to save announcement image: %s", e)
                return jsonify(_debug_in_response({"status":"error","message":"failed to save image"})), 500

    ann_id = uuid.uuid4().hex
    created_by = session.get("staff_id") or session.get("user_id") or None

    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO announcements (id, title, body, target, image_path, created_at, expires_at, status, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (ann_id, title, body, target, image_path, created_at, expires_at, "active", created_by))
            conn.commit()
            current_app.logger.info("create_announcement: created ann_id=%s by=%s", ann_id, created_by)
    except Exception as e:
        current_app.logger.exception("create_announcement failed: %s", e)
        return jsonify(_debug_in_response({"status":"error","message":"Failed to create announcement"})), 500

    image_url = None
    if image_path:
        base = request.host_url.rstrip("/")
        image_url = f"{base}/admin/uploads/announcements/{image_path}"

    return jsonify({"status":"success", "id": ann_id, "image_url": image_url}), 200

@admin_bp.route("/announcements/active", methods=["GET","OPTIONS"])
def get_active_announcements():
    if request.method == "OPTIONS":
        return "", 204

    current_app.logger.debug("get_active_announcements called; headers sample: Origin=%s", request.headers.get("Origin"))
    if _get_conn is None:
        current_app.logger.error("get_active_announcements: DB not initialized")
        return jsonify([]), 200

    now_iso = datetime.now().isoformat()
    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT id, title, body, target, image_path, created_at, expires_at
                FROM announcements
                WHERE status = 'active' AND (expires_at IS NULL OR expires_at > ?)
                ORDER BY created_at DESC
                LIMIT 10
            """, (now_iso,))
            rows = cur.fetchall()
            current_app.logger.debug("get_active_announcements: fetched %d rows", len(rows) if rows is not None else 0)
    except Exception as e:
        current_app.logger.exception("get_active_announcements failed: %s", e)
        return jsonify([]), 200

    out = []
    for r in rows:
        if hasattr(r, "keys"):
            rp = {k: r[k] for k in r.keys()}
        else:
            rp = {
                "id": r[0], "title": r[1], "body": r[2], "target": r[3],
                "image_path": r[4], "created_at": r[5], "expires_at": r[6]
            }
        image_url = None
        if rp.get("image_path"):
            base = request.host_url.rstrip("/")
            image_url = f"{base}/admin/uploads/announcements/{rp['image_path']}"
        out.append({
            "id": rp.get("id"),
            "title": rp.get("title"),
            "body": rp.get("body"),
            "target": rp.get("target"),
            "image_url": image_url,
            "createdAt": rp.get("created_at"),
            "expiresAt": rp.get("expires_at")
        })

    return jsonify(out), 200

@admin_bp.route("/announcements", methods=["POST","OPTIONS"])
def create_announcement():
    if request.method == "OPTIONS":
        return "", 204

    current_app.logger.debug("create_announcement called; headers sample: Origin=%s Content-Type=%s", request.headers.get("Origin"), request.headers.get("Content-Type"))

    if _get_conn is None:
        current_app.logger.error("create_announcement: DB not initialized")
        return jsonify(_debug_in_response({"status":"error","message":"DB not initialized"})), 500

    if not _require_staff_or_admin():
        current_app.logger.warning("create_announcement: unauthorized access attempt")
        return jsonify(_debug_in_response({"status":"error","message":"unauthorized"})), 401

    title = (request.form.get("title") or "").strip()
    body = (request.form.get("body") or "").strip()
    target = (request.form.get("target") or "all").strip()
    created_at = request.form.get("createdAt") or datetime.now().isoformat()
    expires_at = request.form.get("expiresAt") or None

    image_path = None
    if "image" in request.files:
        f = request.files["image"]
        if f and f.filename:
            if not allowed_file(f.filename):
                current_app.logger.debug("create_announcement: invalid file type for filename=%s", f.filename)
                return jsonify(_debug_in_response({"status":"error","message":"invalid file type"})), 400
            filename = secure_filename(f.filename)
            uid_name = uuid.uuid4().hex
            ext = filename.rsplit(".", 1)[-1].lower()
            saved_name = f"{uid_name}.{ext}"
            saved_path = os.path.join(ANN_UPLOAD_DIR, saved_name)
            try:
                f.save(saved_path)
                image_path = saved_name
                current_app.logger.debug("create_announcement: saved image to %s", saved_path)
            except Exception as e:
                current_app.logger.exception("Failed to save announcement image: %s", e)
                return jsonify(_debug_in_response({"status":"error","message":"failed to save image"})), 500

    ann_id = uuid.uuid4().hex
    created_by = session.get("staff_id") or session.get("user_id") or None

    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO announcements (id, title, body, target, image_path, created_at, expires_at, status, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (ann_id, title, body, target, image_path, created_at, expires_at, "active", created_by))
            conn.commit()
            current_app.logger.info("create_announcement: created ann_id=%s by=%s", ann_id, created_by)
    except Exception as e:
        current_app.logger.exception("create_announcement failed: %s", e)
        return jsonify(_debug_in_response({"status":"error","message":"Failed to create announcement"})), 500

    image_url = None
    if image_path:
        base = request.host_url.rstrip("/")
        image_url = f"{base}/admin/uploads/announcements/{image_path}"

    return jsonify({"status":"success", "id": ann_id, "image_url": image_url}), 200

@admin_bp.route("/announcements/active", methods=["GET","OPTIONS"])
def get_active_announcements():
    if request.method == "OPTIONS":
        return "", 204

    current_app.logger.debug("get_active_announcements called; headers sample: Origin=%s", request.headers.get("Origin"))
    if _get_conn is None:
        current_app.logger.error("get_active_announcements: DB not initialized")
        return jsonify([]), 200

    now_iso = datetime.now().isoformat()
    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT id, title, body, target, image_path, created_at, expires_at
                FROM announcements
                WHERE status = 'active' AND (expires_at IS NULL OR expires_at > ?)
                ORDER BY created_at DESC
                LIMIT 10
            """, (now_iso,))
            rows = cur.fetchall()
            current_app.logger.debug("get_active_announcements: fetched %d rows", len(rows) if rows is not None else 0)
    except Exception as e:
        current_app.logger.exception("get_active_announcements failed: %s", e)
        return jsonify([]), 200

    out = []
    for r in rows:
        if hasattr(r, "keys"):
            rp = {k: r[k] for k in r.keys()}
        else:
            rp = {
                "id": r[0], "title": r[1], "body": r[2], "target": r[3],
                "image_path": r[4], "created_at": r[5], "expires_at": r[6]
            }
        image_url = None
        if rp.get("image_path"):
            base = request.host_url.rstrip("/")
            image_url = f"{base}/admin/uploads/announcements/{rp['image_path']}"
        out.append({
            "id": rp.get("id"),
            "title": rp.get("title"),
            "body": rp.get("body"),
            "target": rp.get("target"),
            "image_url": image_url,
            "createdAt": rp.get("created_at"),
            "expiresAt": rp.get("expires_at")
        })

    return jsonify(out), 200

@admin_bp.route("/announcements", methods=["GET","OPTIONS"])
def list_announcements():
    if request.method == "OPTIONS":
        return "", 204

    current_app.logger.debug("list_announcements called")
    if _get_conn is None:
        current_app.logger.error("list_announcements: DB not initialized")
        return jsonify(_debug_in_response({"status":"error","message":"DB not initialized"})), 500

    if not _require_staff_or_admin():
        current_app.logger.warning("list_announcements: unauthorized access attempt")
        return jsonify(_debug_in_response({"status":"error","message":"unauthorized"})), 401

    active_only = request.args.get("active") == "1"
    now_iso = datetime.now().isoformat()
    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            if active_only:
                cur.execute("""
                  SELECT id, title, body, target, image_path, created_at, expires_at, status
                  FROM announcements
                  WHERE status = 'active' AND (expires_at IS NULL OR expires_at > ?)
                  ORDER BY created_at DESC
                """, (now_iso,))
            else:
                cur.execute("""
                  SELECT id, title, body, target, image_path, created_at, expires_at, status
                  FROM announcements
                  ORDER BY created_at DESC
                """)
            rows = cur.fetchall()
            current_app.logger.debug("list_announcements: fetched %d rows (active_only=%s)", len(rows) if rows is not None else 0, active_only)
    except Exception as e:
        current_app.logger.exception("list_announcements failed: %s", e)
        return jsonify(_debug_in_response({"status":"error","message":"Failed to fetch announcements"})), 500

    out = []
    for r in rows:
        if hasattr(r, "keys"):
            rp = {k: r[k] for k in r.keys()}
        else:
            rp = {
                "id": r[0], "title": r[1], "body": r[2], "target": r[3],
                "image_path": r[4], "created_at": r[5], "expires_at": r[6], "status": r[7]
            }
        image_url = None
        if rp.get("image_path"):
            base = request.host_url.rstrip("/")
            image_url = f"{base}/admin/uploads/announcements/{rp['image_path']}"
        out.append({
            "id": rp.get("id"),
            "title": rp.get("title"),
            "body": rp.get("body"),
            "target": rp.get("target"),
            "image_url": image_url,
            "createdAt": rp.get("created_at"),
            "expiresAt": rp.get("expires_at"),
            "status": rp.get("status")
        })

    return jsonify({"status":"success","announcements": out}), 200

@admin_bp.route("/announcements/<ann_id>", methods=["DELETE","OPTIONS"])
def delete_announcement(ann_id):
    if request.method == "OPTIONS":
        return "", 204

    current_app.logger.debug("delete_announcement called id=%s", ann_id)
    if _get_conn is None:
        current_app.logger.error("delete_announcement: DB not initialized")
        return jsonify(_debug_in_response({"status":"error","message":"DB not initialized"})), 500

    if not _require_staff_or_admin():
        current_app.logger.warning("delete_announcement: unauthorized attempt id=%s", ann_id)
        return jsonify(_debug_in_response({"status":"error","message":"unauthorized"})), 401

    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute("UPDATE announcements SET status = 'deleted' WHERE id = ?", (ann_id,))
            conn.commit()
            if cur.rowcount == 0:
                current_app.logger.debug("delete_announcement: not found id=%s", ann_id)
                return jsonify(_debug_in_response({"status":"error","message":"not found"})), 404
            current_app.logger.info("delete_announcement: marked deleted id=%s", ann_id)
    except Exception as e:
        current_app.logger.exception("delete_announcement failed: %s", e)
        return jsonify(_debug_in_response({"status":"error","message":"Failed to delete announcement"})), 500

    return jsonify({"status":"success","id":ann_id}), 200

@admin_bp.route("/announcements/<ann_id>/republish", methods=["POST","OPTIONS"])
def republish_announcement(ann_id):
    if request.method == "OPTIONS":
        return "", 204

    current_app.logger.debug("republish_announcement called id=%s", ann_id)
    if _get_conn is None:
        current_app.logger.error("republish_announcement: DB not initialized")
        return jsonify(_debug_in_response({"status":"error","message":"DB not initialized"})), 500

    if not _require_staff_or_admin():
        current_app.logger.warning("republish_announcement: unauthorized attempt id=%s", ann_id)
        return jsonify(_debug_in_response({"status":"error","message":"unauthorized"})), 401

    payload = request.get_json(silent=True) or {}
    new_expires = payload.get("expiresAt")
    new_created = payload.get("createdAt") or datetime.now().isoformat()

    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute("""
              UPDATE announcements
              SET status = 'active', expires_at = ?, created_at = ?
              WHERE id = ?
            """, (new_expires, new_created, ann_id))
            conn.commit()
            if cur.rowcount == 0:
                current_app.logger.debug("republish_announcement: not found id=%s", ann_id)
                return jsonify(_debug_in_response({"status":"error","message":"not found"})), 404
            current_app.logger.info("republish_announcement: republished id=%s", ann_id)
    except Exception as e:
        current_app.logger.exception("republish_announcement failed: %s", e)
        return jsonify(_debug_in_response({"status":"error","message":"Failed to republish"})), 500

    return jsonify({"status":"success","id":ann_id}), 200

# Serve uploaded images
@admin_bp.route("/uploads/announcements/<filename>", methods=["GET","OPTIONS"])
def serve_ann_image(filename):
    if request.method == "OPTIONS":
        return "", 204
    try:
        current_app.logger.debug("serve_ann_image: serving %s", filename)
        return send_from_directory(ANN_UPLOAD_DIR, filename, conditional=True)
    except Exception as e:
        current_app.logger.exception("serve_ann_image failed: %s", e)
        return jsonify(_debug_in_response({"status":"error","message":"File not found"})), 404

# --- Small debug endpoint to inspect registered admin routes & request sample ---
@admin_bp.route("/debug", methods=["GET","OPTIONS"])
def admin_debug():
    if request.method == "OPTIONS":
        return "", 204
    try:
        url_rules = []
        for r in sorted(current_app.url_map.iter_rules(), key=lambda x: str(x.rule)):
            rule = str(r.rule)
            if "/admin" in rule:
                url_rules.append({
                    "rule": rule,
                    "methods": sorted([m for m in r.methods if m not in ("HEAD","OPTIONS")])
                })
        return jsonify({
            "status": "success",
            "request_sample": {
                "method": request.method,
                "path": request.path,
                "origin": request.headers.get("Origin"),
                "content_type": request.headers.get("Content-Type"),
                "x_debug": request.headers.get("X-Debug"),
                "query_debug": request.args.get("debug")
            },
            "admin_routes": url_rules
        }), 200
    except Exception as e:
        current_app.logger.exception("admin_debug failed: %s", e)
        return jsonify({"status":"error","message":"debug failed"}), 500
