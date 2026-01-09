# otp.py
# Email-only OTP blueprint (works with Postgres or SQLite via utils.get_conn)
# Drop into your project and register with:
#   from otp import otp_bp
#   app.register_blueprint(otp_bp, url_prefix="/api")
# or (as you already do): app.register_blueprint(otp_bp, url_prefix="/api")

import os
import random
import traceback
from datetime import datetime, timedelta
import hashlib
import binascii
import hmac
import json

from flask import Blueprint, request, jsonify, make_response

# optional libs / providers
resend = None
try:
    import resend as _resend_pkg
    resend = _resend_pkg
except Exception:
    resend = None

ryan = None
try:
    import ryan  # optional provider wrapper your project may have
except Exception:
    ryan = None

# try to import DB helpers (get_conn / now_iso)
try:
    from utils import get_conn, now_iso
except Exception:
    get_conn = None

# blueprint (keeps same name so your app.register_blueprint(from otp import otp_bp) keeps working)
otp_bp = Blueprint("otp_bp", __name__, url_prefix="/otp")

# config
RESEND_API_KEY = os.environ.get("RESEND_API_KEY")  # e.g. re_...
OTP_TTL_SECONDS = int(os.environ.get("OTP_TTL_SECONDS", 10 * 60))  # default 10 minutes
DEV_RETURN_OTP = os.environ.get("DEV_RETURN_OTP", "true").lower() not in ("0", "false", "no")
OTP_HASH_ITER = int(os.environ.get("OTP_HASH_ITER", 200_000))
OTP_SALT_BYTES = int(os.environ.get("OTP_SALT_BYTES", 16))
SENDER_EMAIL = os.environ.get("OTP_SENDER_EMAIL", "PayMe <onboarding@resend.dev>")

# configure resend if available and key present
if resend and RESEND_API_KEY:
    try:
        resend.api_key = RESEND_API_KEY
    except Exception:
        # some versions may set differently; ignore and let send attempt surface errors
        pass

# --- helpers ---------------------------------------------------------------

def _err_resp(message: str, exc: Exception = None, status: int = 500):
    """
    Structured error response. Includes exception message for debugging (useful on staging/dev).
    In production you might hide exc details.
    """
    payload = {"success": False, "message": message}
    if exc is not None:
        try:
            payload["error"] = str(exc)
        except Exception:
            payload["error"] = "error-string-unavailable"
    return jsonify(payload), status

def _gen_code():
    return f"{random.randint(0, 999999):06d}"

def hash_otp(code: str):
    """
    PBKDF2-like but simple salted SHA256 for storage (fast and interoperable).
    Returns (salt_hex, hash_hex).
    """
    if not isinstance(code, str):
        code = str(code)
    salt = os.urandom(OTP_SALT_BYTES)
    dk = hashlib.pbkdf2_hmac("sha256", code.encode("utf-8"), salt, OTP_HASH_ITER)
    return binascii.hexlify(salt).decode(), binascii.hexlify(dk).decode()

def verify_otp(code: str, salt_hex: str, hash_hex: str) -> bool:
    if not isinstance(code, str):
        code = str(code)
    try:
        salt = binascii.unhexlify(salt_hex.encode())
        expected = binascii.unhexlify(hash_hex.encode())
    except Exception:
        return False
    dk = hashlib.pbkdf2_hmac("sha256", code.encode("utf-8"), salt, OTP_HASH_ITER)
    return hmac.compare_digest(dk, expected)

def _row_get(row, idx_or_key):
    """
    Safe reader for sqlite row / tuple or dict-like row (psycopg2 RealDictCursor).
    """
    if row is None:
        return None
    try:
        if isinstance(row, dict):
            return row.get(idx_or_key)
        try:
            return row[idx_or_key]
        except Exception:
            if isinstance(idx_or_key, str) and hasattr(row, "keys"):
                try:
                    return row[idx_or_key]
                except Exception:
                    pass
        if not isinstance(idx_or_key, int):
            return None
        return row[idx_or_key]
    except Exception:
        return None

def execute_with_params(cur, conn, sql, params=()):
    """
    Try cur.execute(sql, params). If fails due to param style, retry with '?'=> '%s'.
    Works with sqlite (?), psycopg2 (%s), and wrapper that already handles it.
    """
    try:
        cur.execute(sql, params)
        return
    except Exception as e:
        # try alternative placeholder style
        try:
            alt = sql.replace("?", "%s")
            cur.execute(alt, params)
            return
        except Exception:
            # last resort try without params
            try:
                cur.execute(sql)
                return
            except Exception:
                # re-raise original for diagnostics
                raise e

# --- provider: send email -----------------------------------------------

def _send_email_via_resend(to_email: str, subject: str, html_body: str) -> bool:
    """
    Attempts to send using Resend SDK. Returns True on success, raises on failure.
    """
    if not resend:
        raise NotImplementedError("resend SDK not installed")
    if not RESEND_API_KEY:
        raise RuntimeError("RESEND_API_KEY not configured")
    # Resend API: resend.Emails.send({...}) - adapt to installed package version
    try:
        # newer resend package uses resend.Emails.send
        resp = resend.Emails.send({
            "from": SENDER_EMAIL,
            "to": to_email,
            "subject": subject,
            "html": html_body
        })
        # some SDKs return dict or object; treat non-exception as success
        return True
    except AttributeError:
        # try alternative style: resend.send_email or similar
        try:
            if hasattr(resend, "send_email"):
                resend.send_email(to=to_email, subject=subject, html=html_body, sender=SENDER_EMAIL)
                return True
        except Exception:
            pass
        raise

def _send_email_via_ryan(to_email: str, subject: str, html_body: str) -> bool:
    if not ryan or not hasattr(ryan, "send_email"):
        raise NotImplementedError("ryan.send_email not available")
    try:
        return bool(ryan.send_email(to=to_email, subject=subject, body=html_body))
    except Exception:
        raise

def send_email_provider(to_email: str, subject: str, html_body: str) -> bool:
    """
    Use provider in priority:
      1. Resend (if configured)
      2. ryan.send_email (if available)
      3. else raise NotImplementedError so calling code can return dev code.
    """
    # prefer Resend if API key and package available
    if resend and RESEND_API_KEY:
        return _send_email_via_resend(to_email, subject, html_body)
    # fallback to ryan integration (if project provides it)
    if ryan and hasattr(ryan, "send_email"):
        return _send_email_via_ryan(to_email, subject, html_body)
    raise NotImplementedError("No email provider configured (resend or ryan)")

# --- DB table creation (best-effort) -------------------------------------

def _ensure_table():
    if not get_conn:
        return
    try:
        with get_conn() as conn:
            cur = conn.cursor()
            # Try Postgres serial first
            try:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS otp_codes (
                        id SERIAL PRIMARY KEY,
                        contact TEXT NOT NULL,
                        channel TEXT NOT NULL,
                        code_hash TEXT NOT NULL,
                        code_salt TEXT NOT NULL,
                        reason TEXT,
                        created_at TEXT,
                        expires_at TEXT
                    )
                """)
                try:
                    conn.commit()
                except Exception:
                    pass
                return
            except Exception:
                # fallback to sqlite style
                try:
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS otp_codes (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            contact TEXT NOT NULL,
                            channel TEXT NOT NULL,
                            code_hash TEXT NOT NULL,
                            code_salt TEXT NOT NULL,
                            reason TEXT,
                            created_at TEXT,
                            expires_at TEXT
                        )
                    """)
                    try:
                        conn.commit()
                    except Exception:
                        pass
                except Exception:
                    traceback.print_exc()
    except Exception:
        traceback.print_exc()

# create table (silent)
_ensure_table()

# --- Routes ---------------------------------------------------------------

@otp_bp.route("/send-email", methods=["POST", "OPTIONS"])
def otp_send_email():
    # preflight
    if request.method == "OPTIONS":
        return make_response(jsonify({"ok": True}), 200)

    # read body safely
    try:
        data = request.get_json() or {}
    except Exception:
        data = {}

    email = (data.get("email") or data.get("contact") or "").strip()
    reason = (data.get("reason") or "registration").strip()

    if not email:
        return jsonify({"success": False, "message": "Missing email"}), 400

    # generate and hash code
    code = _gen_code()
    salt_hex, hash_hex = hash_otp(code)
    created_at = datetime.utcnow().isoformat()
    expires_at = (datetime.utcnow() + timedelta(seconds=OTP_TTL_SECONDS)).isoformat()

    # store hashed OTP in DB
    if not get_conn:
        return _err_resp("Database not configured", None, 500)

    try:
        with get_conn() as conn:
            cur = conn.cursor()
            execute_with_params(cur, conn,
                "DELETE FROM otp_codes WHERE contact = ? AND channel = ? AND reason = ?",
                (email, "email", reason)
            )
            execute_with_params(cur, conn,
                "INSERT INTO otp_codes (contact, channel, code_hash, code_salt, reason, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (email, "email", hash_hex, salt_hex, reason, created_at, expires_at)
            )
            try:
                conn.commit()
            except Exception:
                pass
    except Exception as e:
        return _err_resp("Failed to store OTP", e, 500)

    # prepare email content
    subject = "Your verification code"
    html_body = f"""
        <div>
          <p>Your PayMe verification code is:</p>
          <h2 style="font-family:system-ui, Arial; letter-spacing:4px">{code}</h2>
          <p>This code expires in {OTP_TTL_SECONDS // 60} minutes.</p>
        </div>
    """

    # attempt to send via provider(s)
    try:
        send_email_provider(email, subject, html_body)
    except NotImplementedError:
        # no provider configured; if DEV_RETURN_OTP is true, return the code (dev mode)
        if DEV_RETURN_OTP:
            resp = {"success": True, "message": "OTP stored (no provider configured)", "code": code, "expires_at": expires_at}
            return jsonify(resp), 200
        return _err_resp("Email provider not configured", None, 500)
    except Exception as exc:
        # provider-level error; return detailed message so frontend log can show it
        return _err_resp("Failed to send email via provider", exc, 500)

    # success
    resp = {"success": True, "message": "Email OTP sent"}
    if DEV_RETURN_OTP:
        resp["code"] = code
        resp["expires_at"] = expires_at
    return jsonify(resp), 200


@otp_bp.route("/verify", methods=["POST", "OPTIONS"])
def otp_verify():
    # preflight
    if request.method == "OPTIONS":
        return make_response(jsonify({"ok": True}), 200)

    try:
        data = request.get_json() or {}
    except Exception:
        data = {}

    contact = (data.get("contact") or data.get("email") or "").strip()
    channel = (data.get("channel") or "email").strip()
    code = (data.get("code") or "").strip()
    reason = (data.get("reason") or "registration").strip()

    if not contact or not code:
        return jsonify({"success": False, "message": "Missing contact or code"}), 400
    if channel != "email":
        return jsonify({"success": False, "message": "Only 'email' channel supported in this endpoint"}), 400

    if not get_conn:
        return _err_resp("Database not configured", None, 500)

    try:
        with get_conn() as conn:
            cur = conn.cursor()
            execute_with_params(cur, conn,
                "SELECT id, code_hash, code_salt, expires_at FROM otp_codes WHERE contact = ? AND channel = ? AND reason = ? ORDER BY id DESC LIMIT 1",
                (contact, channel, reason)
            )
            row = cur.fetchone()
            if not row:
                return jsonify({"success": False, "message": "OTP not found"}), 404

            otp_id = _row_get(row, 0)
            stored_hash = _row_get(row, 1)
            stored_salt = _row_get(row, 2)
            expires_at = _row_get(row, 3)

            # normalize expiry (string or datetime)
            try:
                if isinstance(expires_at, str):
                    exp_dt = datetime.fromisoformat(expires_at)
                else:
                    exp_dt = expires_at
            except Exception:
                exp_dt = datetime.utcnow() - timedelta(seconds=1)

            if not exp_dt or exp_dt < datetime.utcnow():
                # delete expired OTP (best-effort)
                try:
                    execute_with_params(cur, conn, "DELETE FROM otp_codes WHERE id = ?", (otp_id,))
                    try:
                        conn.commit()
                    except Exception:
                        pass
                except Exception:
                    pass
                return jsonify({"success": False, "message": "OTP expired"}), 400

            if not verify_otp(code, stored_salt, stored_hash):
                return jsonify({"success": False, "message": "Invalid OTP"}), 401

            # success -> delete used otp
            try:
                execute_with_params(cur, conn, "DELETE FROM otp_codes WHERE id = ?", (otp_id,))
                try:
                    conn.commit()
                except Exception:
                    pass
            except Exception:
                pass

            return jsonify({"success": True, "message": "OTP verified"}), 200

    except Exception as e:
        return _err_resp("Server error while verifying OTP", e, 500)