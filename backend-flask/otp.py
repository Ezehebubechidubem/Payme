# otp.py
# Register in app.py:
#   from otp import otp_bp
#   app.register_blueprint(otp_bp, url_prefix="/api")
#
# This module supports PostgreSQL (psycopg2) or SQLite via your utils.get_conn().
# It focuses on email OTPs but provides a safe /send-sms endpoint that will either
# simulate (DEV mode) or return a helpful Not Implemented error (so frontend doesn't get 405).
#
# Features:
# - PBKDF2-HMAC-SHA256 hashed OTP storage (salted)
# - Works with both sqlite ('?') and psycopg2 ('%s') parameter styles
# - Optional Resend integration (RESEND_API_KEY), optional SMTP fallback
# - Detailed JSON error responses for frontend debugging (include stack on dev)
# - CORS headers returned on all endpoints (echoes Origin when present)

import os
import random
import traceback
from datetime import datetime, timedelta
import hashlib
import binascii
import hmac
import smtplib
from email.message import EmailMessage

from flask import Blueprint, request, jsonify, make_response

# Optional CORS helper; best-effort
try:
    from flask_cors import CORS
except Exception:
    CORS = None

# Try to import project helpers (get_conn / now_iso)
try:
    from utils import get_conn, now_iso
except Exception:
    get_conn = None

    def now_iso():
        return datetime.utcnow().isoformat()

# Try to import Resend client if available and key provided
resend_client = None
try:
    from resend import Resend  # pip install resend
    RESEND_API_KEY = os.environ.get("RESEND_API_KEY")
    if RESEND_API_KEY:
        resend_client = Resend(api_key=RESEND_API_KEY)
except Exception:
    resend_client = None

# SMTP fallback config (optional)
SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT") or 0) if os.environ.get("SMTP_PORT") else None
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASS = os.environ.get("SMTP_PASS")
SMTP_FROM = os.environ.get("SMTP_FROM") or os.environ.get("RESEND_FROM_EMAIL") or "no-reply@example.com"
SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "true").lower() not in ("0", "false", "no")

# Blueprint (registered under /api in app.py -> results in /api/otp/...)
otp_bp = Blueprint("otp_bp", __name__, url_prefix="/otp")
try:
    if CORS:
        CORS(otp_bp, supports_credentials=True)
except Exception:
    pass

# Configuration
OTP_TTL_SECONDS = int(os.environ.get("OTP_TTL_SECONDS", 10 * 60))  # 10 minutes default
DEV_RETURN_OTP = os.environ.get("DEV_RETURN_OTP", "true").lower() not in ("0", "false", "no")
OTP_HASH_ITER = int(os.environ.get("OTP_HASH_ITER", 200_000))
OTP_SALT_BYTES = int(os.environ.get("OTP_SALT_BYTES", 16))

# ------------------ Helpers ------------------


def _gen_code():
    return f"{random.randint(0, 999999):06d}"


def hash_otp(code: str):
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
    """Read from tuple-like or dict-like DB rows safely."""
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
    Execute a query, trying both '?' (sqlite) and '%s' (psycopg2) placeholder styles.
    If both fail, re-raise the last exception.
    """
    last_exc = None
    try:
        cur.execute(sql, params)
        return
    except Exception as e1:
        last_exc = e1
    try:
        alt = sql.replace("?", "%s")
        cur.execute(alt, params)
        return
    except Exception as e2:
        last_exc = e2
    # final attempt: without params (best-effort)
    try:
        cur.execute(sql)
        return
    except Exception as e3:
        last_exc = e3
    raise last_exc


def _add_cors_headers(resp):
    """
    Append CORS headers (echo Origin for credentials).
    """
    origin = request.headers.get("Origin") or request.headers.get("origin") or "*"
    if origin == "null":
        origin = "*"
    resp.headers["Access-Control-Allow-Origin"] = origin
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    resp.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return resp


def _err_resp(msg, exc: Exception = None, status=500):
    """
    Standard JSON error response. Includes exc string and stack when available (useful in dev).
    """
    detail = None
    tb = None
    if exc is not None:
        try:
            detail = str(exc)
        except Exception:
            detail = "exception (no message)"
        try:
            tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        except Exception:
            tb = None
    body = {"success": False, "message": msg, "status": "error", "error_detail": detail}
    if tb and DEV_RETURN_OTP:
        # include stack only in dev/testing mode to avoid leaking in prod
        body["stack"] = tb
    resp = make_response(jsonify(body), status)
    return _add_cors_headers(resp)


# ------------------ Providers ------------------


def _send_via_resend(to_email: str, subject: str, body_text: str):
    """Send using Resend (if available)."""
    try:
        resp = resend_client.emails.send(
            from_email=os.environ.get("RESEND_FROM_EMAIL", SMTP_FROM),
            to=[to_email],
            subject=subject,
            text=body_text,
        )
        # resend_client may return info; we print for server logs
        print("[OTP] Resend send response:", resp)
        return True
    except Exception as e:
        print("[OTP] Resend error:", e)
        raise


def _send_via_smtp(to_email: str, subject: str, body_text: str):
    """Send using SMTP (if configured)."""
    if not SMTP_HOST or not SMTP_PORT:
        raise RuntimeError("SMTP not configured (host/port missing)")

    msg = EmailMessage()
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body_text)

    try:
        if SMTP_USE_TLS:
            # connect with TLS (STARTTLS)
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10)
            server.ehlo()
            server.starttls()
            server.ehlo()
        else:
            # SSL or plain
            try:
                server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=10)
            except Exception:
                server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10)

        if SMTP_USER and SMTP_PASS:
            server.login(SMTP_USER, SMTP_PASS)

        server.send_message(msg)
        try:
            server.quit()
        except Exception:
            try:
                server.close()
            except Exception:
                pass
        print("[OTP] SMTP send succeeded to", to_email)
        return True
    except Exception as e:
        print("[OTP] SMTP send error:", e)
        raise


def send_email_provider(to_email: str, subject: str, body_text: str) -> bool:
    """
    Top-level email send function:
     - Prefer Resend (if client available and API key present)
     - Else use SMTP if configured
     - Else: if DEV_RETURN_OTP True, simulate success (do not actually send)
     - Else raise NotImplementedError
    """
    if resend_client:
        return _send_via_resend(to_email, subject, body_text)

    if SMTP_HOST and SMTP_PORT:
        return _send_via_smtp(to_email, subject, body_text)

    if DEV_RETURN_OTP:
        print("[OTP] DEV mode - simulated send (no provider configured).")
        return True

    raise NotImplementedError("No email provider configured. Set RESEND_API_KEY or SMTP_* env vars.")


def send_sms_provider(phone: str, msg_text: str) -> bool:
    """
    SMS provider placeholder. If you later wire an SMS provider (e.g. Twilio),
    replace/extend this function. For now:
     - simulate in DEV_RETURN_OTP mode (return True)
     - otherwise raise NotImplementedError so frontend gets clear error.
    """
    if DEV_RETURN_OTP:
        print(f"[OTP] DEV mode - simulated SMS to {phone}: {msg_text}")
        return True
    raise NotImplementedError("SMS provider not configured (send_sms_provider).")


# ------------------ DB table ensure ------------------


def _ensure_table():
    if not get_conn:
        print("[OTP] get_conn not available; skipping table creation.")
        return
    try:
        with get_conn() as conn:
            cur = conn.cursor()
            # Try Postgres-style then fallback to sqlite-style
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
                # fallback sqlite
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


# create table on import (best-effort)
_ensure_table()

# ------------------ Routes ------------------


@otp_bp.route("/send-email", methods=["POST", "OPTIONS"])
def otp_send_email():
    # handle preflight
    if request.method == "OPTIONS":
        resp = make_response(jsonify({"ok": True}), 200)
        return _add_cors_headers(resp)

    try:
        # debug-friendly parsing
        try:
            body_debug = request.get_json(silent=True)
        except Exception:
            body_debug = None
        print("[OTP] /send-email called, body=", body_debug)

        data = request.get_json() or {}
        email = (data.get("email") or data.get("contact") or "").strip()
        reason = (data.get("reason") or "registration").strip()

        if not email:
            return _err_resp("Missing email", None, 400)

        # generate & hash OTP
        code = _gen_code()
        salt_hex, hash_hex = hash_otp(code)
        created_at = datetime.utcnow().isoformat()
        expires_at = (datetime.utcnow() + timedelta(seconds=OTP_TTL_SECONDS)).isoformat()

        if not get_conn:
            return _err_resp("Database not configured (get_conn not found)", None, 500)

        # store the OTP (delete previous for same contact+channel+reason)
        try:
            with get_conn() as conn:
                cur = conn.cursor()
                execute_with_params(cur, conn,
                                    "DELETE FROM otp_codes WHERE contact = ? AND channel = ? AND reason = ?",
                                    (email, "email", reason))
                execute_with_params(cur, conn,
                                    "INSERT INTO otp_codes (contact, channel, code_hash, code_salt, reason, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                                    (email, "email", hash_hex, salt_hex, reason, created_at, expires_at))
                try:
                    conn.commit()
                except Exception:
                    pass
        except Exception as e:
            return _err_resp("Failed to store OTP in DB", e, 500)

        # send (may raise)
        subject = "Your verification code"
        text_body = f"Your verification code is {code}. It expires in {OTP_TTL_SECONDS//60} minutes."

        try:
            ok = send_email_provider(email, subject, text_body)
            if not ok:
                raise Exception("provider returned falsy")
        except NotImplementedError as e:
            # provider missing: in DEV mode we can return the code; otherwise present clear error
            if DEV_RETURN_OTP:
                body = {"success": True, "message": "OTP stored (email provider not wired)", "code": code, "expires_at": expires_at}
                resp = make_response(jsonify(body), 200)
                return _add_cors_headers(resp)
            return _err_resp("Email provider not configured", e, 500)
        except Exception as e:
            # surface provider error to frontend for debugging (stack included in DEV_RETURN_OTP)
            return _err_resp("Failed to send email OTP (provider error)", e, 500)

        # success response (include otp only if DEV mode)
        resp_body = {"success": True, "message": "Email OTP sent"}
        if DEV_RETURN_OTP:
            resp_body["code"] = code
            resp_body["expires_at"] = expires_at
        resp = make_response(jsonify(resp_body), 200)
        return _add_cors_headers(resp)

    except Exception as e:
        return _err_resp("Server error while processing send-email", e, 500)


@otp_bp.route("/send-sms", methods=["POST", "OPTIONS"])
def otp_send_sms():
    """
    Present so frontend calls won't get 405. Behavior:
      - If DEV_RETURN_OTP is true, create a stored OTP (like email) and return code (simulated)
      - Otherwise return Not Implemented / helpful message
    """
    if request.method == "OPTIONS":
        resp = make_response(jsonify({"ok": True}), 200)
        return _add_cors_headers(resp)

    try:
        data = request.get_json() or {}
        phone = (data.get("phone") or data.get("contact") or "").strip()
        reason = (data.get("reason") or "registration").strip()

        if not phone:
            return _err_resp("Missing phone", None, 400)

        # generate & hash OTP
        code = _gen_code()
        salt_hex, hash_hex = hash_otp(code)
        created_at = datetime.utcnow().isoformat()
        expires_at = (datetime.utcnow() + timedelta(seconds=OTP_TTL_SECONDS)).isoformat()

        if not get_conn:
            return _err_resp("Database not configured (get_conn not found)", None, 500)

        try:
            with get_conn() as conn:
                cur = conn.cursor()
                execute_with_params(cur, conn,
                                    "DELETE FROM otp_codes WHERE contact = ? AND channel = ? AND reason = ?",
                                    (phone, "sms", reason))
                execute_with_params(cur, conn,
                                    "INSERT INTO otp_codes (contact, channel, code_hash, code_salt, reason, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                                    (phone, "sms", hash_hex, salt_hex, reason, created_at, expires_at))
                try:
                    conn.commit()
                except Exception:
                    pass
        except Exception as e:
            return _err_resp("Failed to store OTP in DB", e, 500)

        # If provider is not configured we either simulate (DEV) or return helpful error
        try:
            ok = send_sms_provider(phone, f"Your verification code is {code}. It expires in {OTP_TTL_SECONDS//60} minutes.")
            if not ok:
                raise Exception("sms provider returned falsy")
        except NotImplementedError as e:
            if DEV_RETURN_OTP:
                body = {"success": True, "message": "OTP stored (sms provider not wired)", "code": code, "expires_at": expires_at}
                resp = make_response(jsonify(body), 200)
                return _add_cors_headers(resp)
            return _err_resp("SMS provider not configured", e, 501)
        except Exception as e:
            return _err_resp("Failed to send SMS OTP (provider error)", e, 500)

        resp_body = {"success": True, "message": "SMS OTP sent"}
        if DEV_RETURN_OTP:
            resp_body["code"] = code
            resp_body["expires_at"] = expires_at
        resp = make_response(jsonify(resp_body), 200)
        return _add_cors_headers(resp)

    except Exception as e:
        return _err_resp("Server error while processing send-sms", e, 500)


@otp_bp.route("/verify", methods=["POST", "OPTIONS"])
def otp_verify():
    if request.method == "OPTIONS":
        resp = make_response(jsonify({"ok": True}), 200)
        return _add_cors_headers(resp)

    try:
        data = request.get_json() or {}
        contact = (data.get("contact") or data.get("email") or data.get("phone") or "").strip()
        # default channel: email if contact contains '@', else sms -- but caller should specify channel
        channel = (data.get("channel") or ("email" if "@" in (contact or "") else "sms")).strip()
        code = (data.get("code") or "").strip()
        reason = (data.get("reason") or "registration").strip()

        if not contact or not code:
            return _err_resp("Missing contact or code", None, 400)
        if channel not in ("email", "sms"):
            return _err_resp("Invalid channel", None, 400)
        if not get_conn:
            return _err_resp("Database not configured (get_conn not found)", None, 500)

        with get_conn() as conn:
            cur = conn.cursor()
            execute_with_params(cur, conn,
                                "SELECT id, code_hash, code_salt, expires_at FROM otp_codes WHERE contact = ? AND channel = ? AND reason = ? ORDER BY id DESC LIMIT 1",
                                (contact, channel, reason))
            row = cur.fetchone()
            if not row:
                return _err_resp("OTP not found", None, 404)

            otp_id = _row_get(row, 0)
            stored_hash = _row_get(row, 1)
            stored_salt = _row_get(row, 2)
            expires_at = _row_get(row, 3)

            # parse expiry (ISO string or native datetime from PG)
            try:
                if isinstance(expires_at, str):
                    exp_dt = datetime.fromisoformat(expires_at)
                else:
                    exp_dt = expires_at
            except Exception:
                exp_dt = datetime.utcnow() - timedelta(seconds=1)

            if not exp_dt or exp_dt < datetime.utcnow():
                try:
                    execute_with_params(cur, conn, "DELETE FROM otp_codes WHERE id = ?", (otp_id,))
                    try:
                        conn.commit()
                    except Exception:
                        pass
                except Exception:
                    pass
                return _err_resp("OTP expired", None, 400)

               if not verify_otp(code, stored_salt, stored_hash):
                return _err_resp("Invalid OTP", None, 401)

            # delete used OTP
            try:
                execute_with_params(cur, conn, "DELETE FROM otp_codes WHERE id = ?", (otp_id,))
                try:
                    conn.commit()
                except Exception:
                    pass
            except Exception:
                pass

            resp = make_response(jsonify({"success": True, "message": "OTP verified"}), 200)
            return _add_cors_headers(resp)

    except Exception as e:
        return _err_resp("Server error while processing verify", e, 500)