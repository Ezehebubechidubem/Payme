# admin.py
import uuid
import re
import string
import random
import os
import logging
from datetime import datetime
from flask import Blueprint, jsonify, request, send_from_directory, session, current_app
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename

# Try to import cloudinary (optional). If not installed or not configured, code will fallback to saving locally.
try:
    import cloudinary
    import cloudinary.uploader
    _CLOUDINARY_IMPORTED = True
except Exception:
    cloudinary = None
    _CLOUDINARY_IMPORTED = False

# --- Admin Blueprint ---
admin_bp = Blueprint("admin_bp", __name__, url_prefix="/admin")

# --- Logger ---
logger = logging.getLogger("admin_bp")

# --- CORS: minimal after_request to echo Origin for credentials support ---
@admin_bp.after_request
def add_cors_headers(response):
    origin = request.headers.get("Origin", "*")
    response.headers["Access-Control-Allow-Origin"] = origin
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With, Accept, X-Debug"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    return response

# --- Global connection holder (set by your app) ---
_get_conn = None

def init_admin(get_conn_func):
    """
    Inject the get_conn function from app.py
    """
    global _get_conn
    _get_conn = get_conn_func

    # Configure cloudinary if available and env vars exist
    try:
        if _CLOUDINARY_IMPORTED:
            cloud_name = os.environ.get("CLOUDINARY_CLOUD_NAME")
            api_key = os.environ.get("CLOUDINARY_API_KEY")
            api_secret = os.environ.get("CLOUDINARY_API_SECRET")
            if cloud_name and api_key and api_secret:
                cloudinary.config(
                    cloud_name=cloud_name,
                    api_key=api_key,
                    api_secret=api_secret,
                    secure=True
                )
                logger.info("init_admin: cloudinary configured")
            else:
                logger.debug("init_admin: cloudinary env not fully configured")
    except Exception as e:
        logger.exception("init_admin: cloudinary config failed: %s", e)

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

            # Add image_url column to announcements table schema so we can store remote URLs (Cloudinary)
            cur.execute("""
            CREATE TABLE IF NOT EXISTS announcements (
                id TEXT PRIMARY KEY,
                title TEXT,
                body TEXT,
                target TEXT,
                image_path TEXT,
                image_url TEXT,
                created_at TEXT,
                expires_at TEXT,
                status TEXT,
                created_by TEXT
            )
            """)
            conn.commit()

            logger.debug("init_admin: DB tables ensured")
    except Exception as e:
        logger.exception("init_admin failed: %s", e)
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
        logger.error("create_staff: DB not initialized")
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

    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id FROM staff WHERE email = ?", (email,))
            if cur.fetchone():
                return jsonify({"status":"error","message":"Email already exists"}), 400

            cur.execute(
                "INSERT INTO staff (id, name, email, role, password, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (staff_id, name, email, role, hashed, created_at)
            )
            conn.commit()
            logger.info("create_staff: created staff %s", email)
    except Exception as e:
        logger.exception("create_staff failed: %s", e)
        return jsonify({"status":"error","message":"Failed to create staff"}), 500

    return jsonify({
        "status": "success",
        "staff": {"id": staff_id, "name": name, "email": email, "role": role},
        "generated_password": plain_pw
    }), 201

@admin_bp.route("/staff/list", methods=["GET","OPTIONS"])
def list_staff():
    if request.method == "OPTIONS":
        return "", 204

    if _get_conn is None:
        logger.error("list_staff: DB not initialized")
        return jsonify({"status":"error","message":"DB not initialized"}), 500

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
    except Exception as e:
        logger.exception("list_staff failed: %s", e)
        return jsonify({"status":"error","message":"Unable to list staff"}), 500
    return jsonify({"status":"success","staff": staff_list}), 200

@admin_bp.route("/staff/<staff_id>", methods=["DELETE","OPTIONS"])
def delete_staff(staff_id):
    if request.method == "OPTIONS":
        return "", 204

    if _get_conn is None:
        logger.error("delete_staff: DB not initialized")
        return jsonify({"status":"error","message":"DB not initialized"}), 500

    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM staff WHERE id = ?", (staff_id,))
            conn.commit()
            logger.info("delete_staff: deleted id=%s rowcount=%s", staff_id, getattr(cur, "rowcount", None))
    except Exception as e:
        logger.exception("delete_staff failed: %s", e)
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

# --- Admin Metrics & Recent TX & Daily summary (kept as before) ---
@admin_bp.route("/metrics", methods=["GET","OPTIONS"])
def admin_metrics():
    if request.method == "OPTIONS":
        return "", 204

    if _get_conn is None:
        logger.error("admin_metrics: DB not initialized")
        return jsonify({"status":"error","message":"DB not initialized"}), 500

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

            logger.debug("admin_metrics: deposits=%s withdrawals=%s active_users=%s", deposits, withdrawals, active_users)
    except Exception as e:
        logger.exception("admin_metrics failed: %s", e)
        return jsonify({"status":"error","message":"Failed to fetch metrics"}), 500

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

    if _get_conn is None:
        logger.error("admin_recent_tx: DB not initialized")
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
            logger.debug("admin_recent_tx: returning %d rows", len(result))
    except Exception as e:
        logger.exception("admin_recent_tx failed: %s", e)
        return jsonify({"status":"error","message":"Failed to fetch recent transactions"}), 500

    return jsonify(result), 200

@admin_bp.route("/daily_summary", methods=["GET","OPTIONS"])
def daily_summary():
    if request.method == "OPTIONS":
        return "", 204

    if _get_conn is None:
        logger.error("daily_summary: DB not initialized")
        return jsonify({"status":"error","message":"DB not initialized"}), 500

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
        logger.debug("daily_summary: rows=%d", len(summary))
    return jsonify({"status":"success","summary":summary})

# -----------------------------------------
# Announcements backend
# -----------------------------------------

# Upload configuration: ensure absolute path so send_from_directory works reliably
UPLOAD_BASE = os.environ.get("UPLOAD_BASE", "uploads")
ANN_UPLOAD_DIR = os.path.abspath(os.path.join(UPLOAD_BASE, "announcements"))
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

    if _get_conn is None:
        logger.error("create_announcement: DB not initialized")
        return jsonify({"status":"error","message":"DB not initialized"}), 500

    if not _require_staff_or_admin():
        logger.warning("create_announcement: unauthorized access attempt")
        return jsonify({"status":"error","message":"unauthorized"}), 401

    title = (request.form.get("title") or "").strip()
    body = (request.form.get("body") or "").strip()
    target = (request.form.get("target") or "all").strip()
    created_at = request.form.get("createdAt") or datetime.now().isoformat()
    expires_at = request.form.get("expiresAt") or None

    image_path = None
    image_url = None
    uploaded_to_cloudinary = False

    if "image" in request.files:
        f = request.files["image"]
        if f and f.filename:
            if not allowed_file(f.filename):
                logger.debug("create_announcement: invalid file type for filename=%s", f.filename)
                return jsonify({"status":"error","message":"invalid file type"}), 400

            # Try Cloudinary upload first if configured
            try:
                cloud_name = os.environ.get("CLOUDINARY_CLOUD_NAME")
                api_key = os.environ.get("CLOUDINARY_API_KEY")
                api_secret = os.environ.get("CLOUDINARY_API_SECRET")
                if _CLOUDINARY_IMPORTED and cloud_name and api_key and api_secret:
                    try:
                        # pass the FileStorage directly; cloudinary handles file-like objects
                        upload_result = cloudinary.uploader.upload(
                            f,
                            folder="payme/announcements",
                            use_filename=True,
                            unique_filename=True,
                            overwrite=False
                        )
                        image_url = upload_result.get("secure_url")
                        uploaded_to_cloudinary = True
                        logger.info("create_announcement: uploaded image to cloudinary url=%s", image_url)
                    except Exception as e:
                        logger.exception("create_announcement: cloudinary upload failed: %s", e)
                        # fall back to local save below
                else:
                    logger.debug("create_announcement: cloudinary not configured or not available, falling back to local save")
            except Exception as e:
                logger.exception("create_announcement: cloudinary check failed: %s", e)

            # If Cloudinary not used or failed, save to local disk
            if not uploaded_to_cloudinary:
                try:
                    filename = secure_filename(f.filename)
                    uid_name = uuid.uuid4().hex
                    ext = filename.rsplit(".", 1)[-1].lower()
                    saved_name = f"{uid_name}.{ext}"
                    saved_path = os.path.join(ANN_UPLOAD_DIR, saved_name)
                    # Ensure the file pointer is at start (in case cloudinary consumed some)
                    try:
                        f.stream.seek(0)
                    except Exception:
                        try:
                            f.seek(0)
                        except Exception:
                            pass
                    f.save(saved_path)
                    image_path = saved_name
                    logger.debug("create_announcement: saved image to %s", saved_path)
                    # build image_url from host for local files (will be persisted in DB)
                    try:
                        base = request.host_url.rstrip("/") if request.host_url else ""
                    except Exception:
                        base = ""
                    image_url = f"{base}/admin/uploads/announcements/{image_path}" if base else f"/admin/uploads/announcements/{image_path}"
                except Exception as e:
                    logger.exception("Failed to save announcement image: %s", e)
                    return jsonify({"status":"error","message":"failed to save image"}), 500

    ann_id = uuid.uuid4().hex
    created_by = session.get("staff_id") or session.get("user_id") or None

    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO announcements (id, title, body, target, image_path, image_url, created_at, expires_at, status, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (ann_id, title, body, target, image_path, image_url, created_at, expires_at, "active", created_by))
            conn.commit()
            logger.info("create_announcement: created ann_id=%s by=%s image_url=%s image_path=%s", ann_id, created_by, image_url, image_path)
    except Exception as e:
        logger.exception("create_announcement failed: %s", e)
        return jsonify({"status":"error","message":"Failed to create announcement"}), 500

    return jsonify({"status":"success", "id": ann_id, "image_url": image_url}), 200


@admin_bp.route("/announcements/active", methods=["GET","OPTIONS"])
def get_active_announcements():
    if request.method == "OPTIONS":
        return "", 204

    if _get_conn is None:
        logger.error("get_active_announcements: DB not initialized")
        return jsonify([]), 200

    now_iso = datetime.now().isoformat()
    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT id, title, body, target, image_path, image_url, created_at, expires_at
                FROM announcements
                WHERE status = 'active' AND (expires_at IS NULL OR expires_at > ?)
                ORDER BY created_at DESC
                LIMIT 10
            """, (now_iso,))
            rows = cur.fetchall()
    except Exception as e:
        logger.exception("get_active_announcements failed: %s", e)
        return jsonify([]), 200

    out = []
    for r in rows:
        if hasattr(r, "keys"):
            rp = {k: r[k] for k in r.keys()}
        else:
            rp = {
                "id": r[0], "title": r[1], "body": r[2], "target": r[3],
                "image_path": r[4], "image_url": r[5], "created_at": r[6], "expires_at": r[7]
            }
        # Prefer image_url column (Cloudinary or built URL); fallback to constructed URL from image_path
        image_url = rp.get("image_url")
        if not image_url and rp.get("image_path"):
            try:
                base = request.host_url.rstrip("/") if request.host_url else ""
            except Exception:
                base = ""
            image_url = f"{base}/admin/uploads/announcements/{rp['image_path']}" if base else f"/admin/uploads/announcements/{rp['image_path']}"
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

    if _get_conn is None:
        logger.error("list_announcements: DB not initialized")
        return jsonify({"status":"error","message":"DB not initialized"}), 500

    if not _require_staff_or_admin():
        logger.warning("list_announcements: unauthorized access attempt")
        return jsonify({"status":"error","message":"unauthorized"}), 401

    active_only = request.args.get("active") == "1"
    now_iso = datetime.now().isoformat()
    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            if active_only:
                cur.execute("""
                  SELECT id, title, body, target, image_path, image_url, created_at, expires_at, status
                  FROM announcements
                  WHERE status = 'active' AND (expires_at IS NULL OR expires_at > ?)
                  ORDER BY created_at DESC
                """, (now_iso,))
            else:
                cur.execute("""
                  SELECT id, title, body, target, image_path, image_url, created_at, expires_at, status
                  FROM announcements
                  ORDER BY created_at DESC
                """)
            rows = cur.fetchall()
    except Exception as e:
        logger.exception("list_announcements failed: %s", e)
        return jsonify({"status":"error","message":"Failed to fetch announcements"}), 500

    out = []
    for r in rows:
        if hasattr(r, "keys"):
            rp = {k: r[k] for k in r.keys()}
        else:
            rp = {
                "id": r[0], "title": r[1], "body": r[2], "target": r[3],
                "image_path": r[4], "image_url": r[5], "created_at": r[6], "expires_at": r[7], "status": r[8]
            }
        image_url = rp.get("image_url")
        if not image_url and rp.get("image_path"):
            try:
                base = request.host_url.rstrip("/") if request.host_url else ""
            except Exception:
                base = ""
            image_url = f"{base}/admin/uploads/announcements/{rp['image_path']}" if base else f"/admin/uploads/announcements/{rp['image_path']}"
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

    if _get_conn is None:
        logger.error("delete_announcement: DB not initialized")
        return jsonify({"status":"error","message":"DB not initialized"}), 500

    if not _require_staff_or_admin():
        logger.warning("delete_announcement: unauthorized attempt id=%s", ann_id)
        return jsonify({"status":"error","message":"unauthorized"}), 401

    try:
        # Perform permanent deletion: remove DB row, and unlink image file if present
        with _get_conn() as conn:
            cur = conn.cursor()
            # First fetch image_path and image_url (if any) so we can delete the file if saved locally
            cur.execute("SELECT image_path, image_url FROM announcements WHERE id = ?", (ann_id,))
            row = cur.fetchone()
            image_path = None
            image_url = None
            if row:
                if hasattr(row, "keys"):
                    image_path = row.get("image_path")
                    image_url = row.get("image_url")
                else:
                    # row is likely a tuple
                    image_path = row[0] if len(row) > 0 else None
                    image_url = row[1] if len(row) > 1 else None

            # Delete the DB row
            cur.execute("DELETE FROM announcements WHERE id = ?", (ann_id,))
            conn.commit()
            if getattr(cur, "rowcount", 0) == 0:
                logger.debug("delete_announcement: not found id=%s", ann_id)
                return jsonify({"status":"error","message":"not found"}), 404

            # If there was a locally saved image, attempt to remove the file
            if image_path:
                try:
                    file_path = os.path.join(ANN_UPLOAD_DIR, image_path)
                    if os.path.exists(file_path):
                        os.remove(file_path)
                        logger.debug("delete_announcement: removed image file %s", file_path)
                except Exception as e:
                    logger.exception("delete_announcement: failed to remove image file %s: %s", image_path, e)

            # NOTE: If image_url points to Cloudinary, we do not automatically delete remote resource here
            # unless you want to implement cloudinary.uploader.destroy with stored public_id.
            logger.info("delete_announcement: permanently deleted id=%s", ann_id)
    except Exception as e:
        logger.exception("delete_announcement failed: %s", e)
        return jsonify({"status":"error","message":"Failed to delete announcement"}), 500

    return jsonify({"status":"success","id":ann_id}), 200

@admin_bp.route("/announcements/<ann_id>/republish", methods=["POST","OPTIONS"])
def republish_announcement(ann_id):
    if request.method == "OPTIONS":
        return "", 204

    if _get_conn is None:
        logger.error("republish_announcement: DB not initialized")
        return jsonify({"status":"error","message":"DB not initialized"}), 500

    if not _require_staff_or_admin():
        logger.warning("republish_announcement: unauthorized attempt id=%s", ann_id)
        return jsonify({"status":"error","message":"unauthorized"}), 401

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
            if getattr(cur, "rowcount", 0) == 0:
                logger.debug("republish_announcement: not found id=%s", ann_id)
                return jsonify({"status":"error","message":"not found"}), 404
            logger.info("republish_announcement: republished id=%s", ann_id)
    except Exception as e:
        logger.exception("republish_announcement failed: %s", e)
        return jsonify({"status":"error","message":"Failed to republish"}), 500

    return jsonify({"status":"success","id":ann_id}), 200

# Serve uploaded images
@admin_bp.route("/uploads/announcements/<filename>", methods=["GET","OPTIONS"])
def serve_ann_image(filename):
    if request.method == "OPTIONS":
        return "", 204
    try:
        logger.debug("serve_ann_image: serving %s from %s", filename, ANN_UPLOAD_DIR)
        return send_from_directory(ANN_UPLOAD_DIR, filename, conditional=True)
    except Exception as e:
        logger.exception("serve_ann_image failed: %s", e)
        return jsonify({"status":"error","message":"File not found"}), 404

# --- Small admin debug route for inspecting admin routes (kept) ---
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
        logger.exception("admin_debug failed: %s", e)
        return jsonify({"status":"error","message":"debug failed"}), 500

@admin_bp.route("/fix-announcement-columns", methods=["GET"])
def fix_announcement_columns():
    try:
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute("ALTER TABLE announcements ADD COLUMN IF NOT EXISTS image_path TEXT;")
            cur.execute("ALTER TABLE announcements ADD COLUMN IF NOT EXISTS image_url TEXT;")
            cur.execute("ALTER TABLE announcements ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'active';")
            cur.execute("ALTER TABLE announcements ADD COLUMN IF NOT EXISTS created_by TEXT;")
            conn.commit()
        return jsonify({"status": "success", "message": "Columns updated"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500