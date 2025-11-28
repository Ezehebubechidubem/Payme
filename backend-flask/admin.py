# admin.py
import os
import traceback
import importlib
from datetime import datetime
from functools import wraps

from flask import Blueprint, request, jsonify, session, current_app

admin_bp = Blueprint("admin_bp", __name__)

# Config secrets (read from env)
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "change-this-admin-pw")
# Optional per-request header token (useful for scripts): X-Admin-Token
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", None)

# internal flag to ensure admin tables initialized only once per process
_ADMIN_TABLES_INITIALIZED = False

def _now_iso():
    return datetime.utcnow().isoformat()

def _get_app_get_conn():
    """
    Lazy import of get_conn from main app to avoid circular import problems.
    app.py must define get_conn() in its module scope.
    """
    try:
        app_module = importlib.import_module("app")
        return getattr(app_module, "get_conn")
    except Exception as e:
        current_app.logger.error("admin: failed to import get_conn from app: %s", e)
        raise

def ensure_admin_tables():
    """
    Create admin helper tables and add minimal columns to users table if missing.
    This runs lazily on first admin route call.
    """
    global _ADMIN_TABLES_INITIALIZED
    if _ADMIN_TABLES_INITIALIZED:
        return
    get_conn = _get_app_get_conn()
    try:
        with get_conn() as conn:
            cur = conn.cursor()
            # Add helpful columns to users table if they don't exist.
            # For sqlite and postgres, ALTER TABLE ADD COLUMN is acceptable.
            try:
                cur.execute("ALTER TABLE users ADD COLUMN is_blocked INTEGER DEFAULT 0")
            except Exception:
                # ignore if already exists or alter not allowed
                pass
            try:
                cur.execute("ALTER TABLE users ADD COLUMN kyc_status TEXT DEFAULT 'pending'")
            except Exception:
                pass
            # admin actions audit
            cur.execute("""
              CREATE TABLE IF NOT EXISTS admin_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin TEXT,
                action TEXT,
                target_type TEXT,
                target_id TEXT,
                details TEXT,
                created_at TEXT
              )
            """)
            # staff table
            cur.execute("""
              CREATE TABLE IF NOT EXISTS staff (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                email TEXT UNIQUE,
                role TEXT,
                created_at TEXT
              )
            """)
            # service flags
            cur.execute("""
              CREATE TABLE IF NOT EXISTS service_flags (
                key TEXT PRIMARY KEY,
                value TEXT
              )
            """)
            # notifications history
            cur.execute("""
              CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT,
                body TEXT,
                target TEXT,
                scheduled_at TEXT,
                sent_at TEXT,
                created_at TEXT
              )
            """)
            # simple logs table (for admin-only records, not replacing transactions)
            cur.execute("""
              CREATE TABLE IF NOT EXISTS admin_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event TEXT,
                user_phone TEXT,
                ip TEXT,
                meta TEXT,
                created_at TEXT
              )
            """)
            try:
                conn.commit()
            except Exception:
                try:
                    conn.close()
                except:
                    pass
    except Exception:
        traceback.print_exc()
    _ADMIN_TABLES_INITIALIZED = True

# -------------------------
# Security helpers
# -------------------------
def _check_admin_auth():
    """
    Accept either:
      - session['is_admin'] True
      - X-Admin-Token header matching ADMIN_TOKEN
      - posted password to login endpoint (handled separately)
    """
    # session based
    if session.get("is_admin"):
        return True
    # header token
    header_token = request.headers.get("X-Admin-Token")
    if ADMIN_TOKEN and header_token and header_token == ADMIN_TOKEN:
        return True
    return False

def admin_only(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        ensure_admin_tables()
        if not _check_admin_auth():
            return jsonify({"status":"error","message":"Admin authentication required"}), 401
        return f(*args, **kwargs)
    return wrapper

def _record_admin_action(conn, admin, action, target_type=None, target_id=None, details=None):
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO admin_actions (admin, action, target_type, target_id, details, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (admin or "unknown", action, target_type, str(target_id) if target_id is not None else None, details or "", _now_iso())
        )
    except Exception:
        try:
            conn.rollback()
        except:
            pass

# -------------------------
# Admin login/logout
# -------------------------
@admin_bp.route("/login", methods=["POST"])
def admin_login():
    """
    POST /admin/login
    { "password": "..." }
    On success sets session['is_admin']=True
    """
    ensure_admin_tables()
    data = request.get_json(silent=True) or {}
    pw = data.get("password", "")
    if not pw:
        return jsonify({"status":"error","message":"password required"}), 400
    if pw != ADMIN_PASSWORD:
        return jsonify({"status":"error","message":"invalid password"}), 403
    session["is_admin"] = True
    # optional admin name:
    session["admin_name"] = data.get("admin_name", "admin")
    return jsonify({"status":"success","message":"admin logged in"}), 200

@admin_bp.route("/logout", methods=["GET","POST"])
@admin_only
def admin_logout():
    session.pop("is_admin", None)
    session.pop("admin_name", None)
    return jsonify({"status":"success","message":"logged out"}), 200

# -------------------------
# Users: list, get, block/unblock, manual adjust
# -------------------------
@admin_bp.route("/users", methods=["GET"])
@admin_only
def list_users():
    """
    GET /admin/users?limit=100&offset=0
    returns users with is_blocked and kyc_status
    """
    ensure_admin_tables()
    get_conn = _get_app_get_conn()
    limit = int(request.args.get("limit", 200))
    offset = int(request.args.get("offset", 0))
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, username, phone, account_number, balance, is_blocked, kyc_status FROM users ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset))
        rows = cur.fetchall()
    out = []
    for r in rows:
        out.append({
            "id": r["id"],
            "username": r.get("username") or r[1] if hasattr(r, "__getitem__") else None,
            "phone": r.get("phone"),
            "account_number": r.get("account_number"),
            "balance": float(r.get("balance") or 0),
            "is_blocked": bool(r.get("is_blocked")),
            "kyc_status": r.get("kyc_status") or "pending"
        })
    return jsonify({"status":"success","users": out}), 200

@admin_bp.route("/users/<int:user_id>", methods=["GET"])
@admin_only
def get_user_admin(user_id):
    ensure_admin_tables()
    get_conn = _get_app_get_conn()
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, username, phone, account_number, balance, is_blocked, kyc_status FROM users WHERE id = ?", (user_id,))
        r = cur.fetchone()
    if not r:
        return jsonify({"status":"error","message":"not found"}), 404
    return jsonify({"status":"success","user": {
        "id": r["id"], "username": r.get("username"), "phone": r.get("phone"),
        "account_number": r.get("account_number"), "balance": float(r.get("balance") or 0),
        "is_blocked": bool(r.get("is_blocked")), "kyc_status": r.get("kyc_status") or "pending"
    }}), 200

@admin_bp.route("/users/block", methods=["POST"])
@admin_only
def block_user():
    """
    POST /admin/users/block
    { "user_id": <id> }  OR  { "phone": "0803..." }
    Optional: {"reason": "suspected takeover", "block": true/false}
    """
    ensure_admin_tables()
    data = request.get_json(silent=True) or {}
    uid = data.get("user_id")
    phone = data.get("phone")
    reason = data.get("reason", "")
    block = data.get("block", True)
    if not (uid or phone):
        return jsonify({"status":"error","message":"user_id or phone required"}), 400
    get_conn = _get_app_get_conn()
    with get_conn() as conn:
        cur = conn.cursor()
        if uid:
            cur.execute("UPDATE users SET is_blocked = ? WHERE id = ?", (1 if block else 0, uid))
        else:
            cur.execute("UPDATE users SET is_blocked = ? WHERE phone = ?", (1 if block else 0, phone))
        _record_admin_action(conn, session.get("admin_name"), "block" if block else "unblock", "user", uid or phone, reason)
    return jsonify({"status":"success","message":f"user {'blocked' if block else 'unblocked'}"}), 200

@admin_bp.route("/users/manual_adjust", methods=["POST"])
@admin_only
def manual_adjust():
    """
    POST /admin/users/manual_adjust
    { "user_id": <id> } OR { "phone": "..." }, "amount": 1000, "type": "credit"|"debit", "note": "..." }
    """
    ensure_admin_tables()
    data = request.get_json(silent=True) or {}
    uid = data.get("user_id")
    phone = data.get("phone")
    try:
        amount = float(data.get("amount", 0))
    except Exception:
        return jsonify({"status":"error","message":"invalid amount"}), 400
    tx_type = data.get("type", "credit")
    note = data.get("note", "")

    if not (uid or phone):
        return jsonify({"status":"error","message":"user_id or phone required"}), 400
    if amount <= 0:
        return jsonify({"status":"error","message":"amount must be > 0"}), 400
    if tx_type not in ("credit","debit"):
        return jsonify({"status":"error","message":"type must be credit or debit"}), 400

    get_conn = _get_app_get_conn()
    with get_conn() as conn:
        cur = conn.cursor()
        # find user id
        if uid:
            cur.execute("SELECT id, balance FROM users WHERE id = ?", (uid,))
        else:
            cur.execute("SELECT id, balance FROM users WHERE phone = ?", (phone,))
        r = cur.fetchone()
        if not r:
            return jsonify({"status":"error","message":"user not found"}), 404
        user_id = r["id"]
        if tx_type == "credit":
            cur.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, user_id))
            cur.execute("INSERT INTO transactions (user_id, type, amount, other_party, date) VALUES (?, ?, ?, ?, ?)",
                        (user_id, "Admin Credit", amount, note or "admin", _now_iso()))
        else:
            # check balance
            bal = float(r["balance"] or 0)
            if bal < amount:
                return jsonify({"status":"error","message":"insufficient balance for debit"}), 400
            cur.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, user_id))
            cur.execute("INSERT INTO transactions (user_id, type, amount, other_party, date) VALUES (?, ?, ?, ?, ?)",
                        (user_id, "Admin Debit", -amount, note or "admin", _now_iso()))
        _record_admin_action(conn, session.get("admin_name"), f"manual_{tx_type}", "user", user_id, note)
        # return updated balance
        cur.execute("SELECT balance FROM users WHERE id = ?", (user_id,))
        newb = cur.fetchone()
        new_balance = float(newb["balance"]) if newb else None
    return jsonify({"status":"success","message":"adjustment applied","new_balance": new_balance}), 200

# -------------------------
# Transactions: list & query
# -------------------------
@admin_bp.route("/transactions", methods=["GET"])
@admin_only
def admin_transactions():
    """
    GET /admin/transactions?limit=100&offset=0&phone=<phone>
    """
    ensure_admin_tables()
    limit = int(request.args.get("limit", 200))
    offset = int(request.args.get("offset", 0))
    phone = request.args.get("phone")
    get_conn = _get_app_get_conn()
    with get_conn() as conn:
        cur = conn.cursor()
        if phone:
            cur.execute("""
              SELECT t.id, t.user_id, t.type, t.amount, t.other_party, t.date, u.phone
              FROM transactions t LEFT JOIN users u ON u.id = t.user_id
              WHERE u.phone = ? ORDER BY t.id DESC LIMIT ? OFFSET ?
            """, (phone, limit, offset))
        else:
            cur.execute("""
              SELECT t.id, t.user_id, t.type, t.amount, t.other_party, t.date, u.phone
              FROM transactions t LEFT JOIN users u ON u.id = t.user_id
              ORDER BY t.id DESC LIMIT ? OFFSET ?
            """, (limit, offset))
        rows = cur.fetchall()
    out = []
    for r in rows:
        out.append({
            "id": r["id"],
            "user_id": r["user_id"],
            "phone": r.get("phone"),
            "type": r["type"],
            "amount": float(r["amount"]),
            "other_party": r["other_party"],
            "date": r["date"]
        })
    return jsonify({"status":"success","transactions": out}), 200

@admin_bp.route("/transactions/<int:user_id>", methods=["GET"])
@admin_only
def admin_transactions_for_user(user_id):
    ensure_admin_tables()
    get_conn = _get_app_get_conn()
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, type, amount, other_party, date FROM transactions WHERE user_id = ? ORDER BY id DESC", (user_id,))
        rows = cur.fetchall()
    out = [{"id": r["id"], "type": r["type"], "amount": float(r["amount"]), "other_party": r["other_party"], "date": r["date"]} for r in rows]
    return jsonify({"status":"success","transactions": out}), 200

# -------------------------
# KYC management
# -------------------------
@admin_bp.route("/kyc/update", methods=["POST"])
@admin_only
def admin_kyc_update():
    """
    POST /admin/kyc/update
    { "user_id": <id> or "phone": "...", "status": "approved"|"rejected"|"pending", "note": "..." }
    """
    ensure_admin_tables()
    data = request.get_json(silent=True) or {}
    uid = data.get("user_id")
    phone = data.get("phone")
    status = str(data.get("status", "pending")).lower()
    note = data.get("note", "")
    if status not in ("approved", "rejected", "pending"):
        return jsonify({"status":"error","message":"invalid status"}), 400
    get_conn = _get_app_get_conn()
    with get_conn() as conn:
        cur = conn.cursor()
        if uid:
            cur.execute("UPDATE users SET kyc_status = ? WHERE id = ?", (status, uid))
            target = uid
        else:
            cur.execute("UPDATE users SET kyc_status = ? WHERE phone = ?", (status, phone))
            target = phone
        _record_admin_action(conn, session.get("admin_name"), f"kyc_{status}", "user", target, note)
    return jsonify({"status":"success","message":"kyc updated"}), 200

# -------------------------
# Service control & notifications
# -------------------------
@admin_bp.route("/service/toggle", methods=["POST"])
@admin_only
def service_toggle():
    """
    POST /admin/service/toggle { "key": "airtime_api", "value": "on"/"off" }
    """
    ensure_admin_tables()
    data = request.get_json(silent=True) or {}
    key = data.get("key")
    value = data.get("value")
    if not key:
        return jsonify({"status":"error","message":"key required"}), 400
    get_conn = _get_app_get_conn()
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("INSERT OR REPLACE INTO service_flags (key, value) VALUES (?, ?)", (key, str(value)))
        _record_admin_action(conn, session.get("admin_name"), "service_toggle", "service", key, str(value))
    return jsonify({"status":"success","message":"service flag updated"}), 200

@admin_bp.route("/service/flags", methods=["GET"])
@admin_only
def service_flags():
    ensure_admin_tables()
    get_conn = _get_app_get_conn()
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT key, value FROM service_flags")
        rows = cur.fetchall()
    out = {r["key"]: r["value"] for r in rows}
    return jsonify({"status":"success","flags": out}), 200

@admin_bp.route("/notifications/send", methods=["POST"])
@admin_only
def send_notification():
    """
    POST /admin/notifications/send
    { "title":"...", "body":"...", "target":"all|active|suspended|custom", "scheduled_at": null }
    """
    ensure_admin_tables()
    data = request.get_json(silent=True) or {}
    title = data.get("title", "")
    body = data.get("body", "")
    target = data.get("target", "all")
    scheduled_at = data.get("scheduled_at")
    get_conn = _get_app_get_conn()
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("INSERT INTO notifications (title, body, target, scheduled_at, created_at) VALUES (?, ?, ?, ?, ?)",
                    (title, body, target, scheduled_at, _now_iso()))
        _record_admin_action(conn, session.get("admin_name"), "notification_send", "notification", None, f"{title} -> {target}")
    # NOTE: This only records the announcement; integrate with push / sms service to actually deliver
    return jsonify({"status":"success","message":"notification queued"}), 200

@admin_bp.route("/notifications/history", methods=["GET"])
@admin_only
def notifications_history():
    ensure_admin_tables()
    get_conn = _get_app_get_conn()
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, title, body, target, scheduled_at, sent_at, created_at FROM notifications ORDER BY id DESC LIMIT 200")
        rows = cur.fetchall()
    out = [{"id": r["id"], "title": r["title"], "body": r["body"], "target": r["target"], "scheduled_at": r["scheduled_at"], "sent_at": r["sent_at"], "created_at": r["created_at"]} for r in rows]
    return jsonify({"status":"success","history": out}), 200

# -------------------------
# Staff management
# -------------------------
@admin_bp.route("/staff", methods=["GET"])
@admin_only
def list_staff():
    ensure_admin_tables()
    get_conn = _get_app_get_conn()
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, name, email, role, created_at FROM staff ORDER BY id DESC")
        rows = cur.fetchall()
    out = [{"id": r["id"], "name": r["name"], "email": r["email"], "role": r["role"], "created_at": r["created_at"]} for r in rows]
    return jsonify({"status":"success","staff": out}), 200

@admin_bp.route("/staff/create", methods=["POST"])
@admin_only
def create_staff():
    ensure_admin_tables()
    data = request.get_json(silent=True) or {}
    name = data.get("name")
    email = data.get("email")
    role = data.get("role", "support")
    if not (name and email):
        return jsonify({"status":"error","message":"name and email required"}), 400
    get_conn = _get_app_get_conn()
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("INSERT INTO staff (name, email, role, created_at) VALUES (?, ?, ?, ?)", (name, email, role, _now_iso()))
        _record_admin_action(conn, session.get("admin_name"), "staff_create", "staff", email, role)
    return jsonify({"status":"success","message":"staff created"}), 200

admin_bp.route("/staff/create", methods=["POST"])
@admin_only
def create_staff():
    ensure_admin_tables()
    data = request.get_json(silent=True) or {}
    name = data.get("name")
    email = data.get("email")
    role = data.get("role", "support")
    if not (name and email):
        return jsonify({"status":"error","message":"name and email required"}), 400
    get_conn = _get_app_get_conn()
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("INSERT INTO staff (name, email, role, created_at) VALUES (?, ?, ?, ?)", (name, email, role, _now_iso()))
        _record_admin_action(conn, session.get("admin_name"), "staff_create", "staff", email, role)
    return jsonify({"status":"success","message":"staff created"}), 200

@admin_bp.route("/staff/delete", methods=["POST"])
@admin_only
def delete_staff():
    ensure_admin_tables()
    data = request.get_json(silent=True) or {}
    staff_id = data.get("id")
    if not staff_id:
        return jsonify({"status":"error","message":"id required"}), 400
    get_conn = _get_app_get_conn()
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM staff WHERE id = ?", (staff_id,))
        _record_admin_action(conn, session.get("admin_name"), "staff_delete", "staff", staff_id, "")
    return jsonify({"status":"success","message":"staff removed"}), 200

# -------------------------
# Audit logs & metrics
# -------------------------
@admin_bp.route("/audit/actions", methods=["GET"])
@admin_only
def audit_actions():
    ensure_admin_tables()
    limit = int(request.args.get("limit", 200))
    get_conn = _get_app_get_conn()
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, admin, action, target_type, target_id, details, created_at FROM admin_actions ORDER BY id DESC LIMIT ?", (limit,))
        rows = cur.fetchall()
    out = [{"id": r["id"], "admin": r["admin"], "action": r["action"], "target_type": r["target_type"], "target_id": r["target_id"], "details": r["details"], "created_at": r["created_at"]} for r in rows]
    return jsonify({"status":"success","actions": out}), 200

@admin_bp.route("/metrics", methods=["GET"])
@admin_only
def metrics():
    """
    Returns simple admin metrics: total users, active users (non-blocked), total volume (sum transactions)
    """
    ensure_admin_tables()
    get_conn = _get_app_get_conn()
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) as c FROM users")
        total_users = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) as c FROM users WHERE is_blocked = 0 OR is_blocked IS NULL")
        active_users = cur.fetchone()["c"]
        # sum of transaction amounts, best effort
        try:
            cur.execute("SELECT SUM(amount) as s FROM transactions")
            srow = cur.fetchone()
            total_volume = float(srow["s"] or 0)
        except Exception:
            total_volume = 0.0
    return jsonify({"status":"success","metrics": {"total_users": total_users, "active_users": active_users, "total_volume": total_volume}}), 200

# -------------------------
# Admin helper: search logs (very simple)
# -------------------------
@admin_bp.route("/logs/search", methods=["GET"])
@admin_only
def logs_search():
    """
    GET /admin/logs/search?q=...  (searches admin_logs and transactions and admin_actions)
    """
    ensure_admin_tables()
    q = (request.args.get("q") or "").strip()
    limit = int(request.args.get("limit", 200))
    if not q:
        return jsonify({"status":"error","message":"q required"}), 400
    get_conn = _get_app_get_conn()
    results = {"transactions": [], "admin_actions": [], "admin_logs": []}
    with get_conn() as conn:
        cur = conn.cursor()
        try:
            cur.execute("SELECT id, user_id, type, amount, other_party, date FROM transactions WHERE (other_party LIKE ? OR type LIKE ?) ORDER BY id DESC LIMIT ?", (f"%{q}%", f"%{q}%", limit))
            rows = cur.fetchall()
            results["transactions"] = [{"id": r["id"], "user_id": r["user_id"], "type": r["type"], "amount": float(r["amount"]), "other_party": r["other_party"], "date": r["date"]} for r in rows]
        except Exception:
            pass
        try:
            cur.execute("SELECT id, admin, action, details, created_at FROM admin_actions WHERE action LIKE ? OR details LIKE ? ORDER BY id DESC LIMIT ?", (f"%{q}%", f"%{q}%", limit))
            rows = cur.fetchall()
            results["admin_actions"] = [{"id": r["id"], "admin": r["admin"], "action": r["action"], "details": r["details"], "created_at": r["created_at"]} for r in rows]
        except Exception:
            pass
        try:
            cur.execute("SELECT id, event, user_phone, meta, created_at FROM admin_logs WHERE event LIKE ? OR meta LIKE ? ORDER BY id DESC LIMIT ?", (f"%{q}%", f"%{q}%", limit))
            rows = cur.fetchall()
            results["admin_logs"] = [{"id": r["id"], "event": r["event"], "user_phone": r["user_phone"], "meta": r["meta"], "created_at": r["created_at"]} for r in rows]
        except Exception:
            pass
    return jsonify({"status":"success","results": results}), 200

# -------------------------
# Small utility route for health
# -------------------------
@admin_bp.route("/ping", methods=["GET"])
@admin_only
def admin_ping():
    return jsonify({"status":"success","message":"admin ok"}), 200

# End of admin.py

