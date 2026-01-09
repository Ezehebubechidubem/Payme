# otp.py
# OTP blueprint for PAYME
# Works with Postgres (psycopg2) and SQLite. Keeps same routes so app.register_blueprint(otp_bp, url_prefix="/api") -> /api/otp/...
# Detailed error responses are returned to help debugging (provider errors included).

import os
import random
import traceback
from datetime import datetime, timedelta
import hashlib
import binascii
import hmac

from flask_cors import CORS
from flask import Blueprint, request, jsonify, make_response

# try to import your project's DB helpers (get_conn / now_iso)
try:
    from utils import get_conn, now_iso
except Exception:
    # fallback minimal implementations if utils not available at import time
    get_conn = None

    def now_iso():
        return datetime.utcnow().isoformat()

# try to use existing "ryan" provider module if you have it
ryan = None
try:
    import ryan  # optional: your existing service wrapper
except Exception:
    ryan = None

# blueprint (registered in app.py with prefix /api)
otp_bp = Blueprint("otp_bp", __name__, url_prefix="/otp")
# enable CORS on this blueprint (app.py may already enable CORS globally)
try:
    CORS(otp_bp, supports_credentials=True)
except Exception:
    pass

# configuration via env
OTP_TTL_SECONDS = int(os.environ.get("OTP_TTL_SECONDS", 10 * 60))  # default 10 minutes
DEV_RETURN_OTP = os.environ.get("DEV_RETURN_OTP", "true").lower() not in ("0", "false", "no")
OTP_HASH_ITER = int(os.environ.get("OTP_HASH_ITER", 200_000))
OTP_SALT_BYTES = int(os.environ.get("OTP_SALT_BYTES", 16))


# --- small helpers ---

def _gen_code():
    return f"{random.randint(0, 999999):06d}"


def hash_otp(code: str):
    """
    Returns (salt_hex, hash_hex) using PBKDF2-HMAC-SHA256.
    """
    if not isinstance(code, str):
        code = str(code)
    salt = os.urandom(OTP_SALT_BYTES)
    dk = hashlib.pbkdf2_hmac("sha256", code.encode("utf-8"), salt, OTP_HASH_ITER)
    return binascii.hexlify(salt).decode(), binascii.hexlify(dk).decode()


def verify_otp(code: str, salt_hex: str, hash_hex: str) -> bool:
    """
    Verify OTP by recomputing PBKDF2-HMAC-SHA256 and comparing with constant-time compare.
    """
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
    Safe reader for both sqlite3.Row/tuple and psycopg2 RealDictCursor dict-like rows.
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
    Try cur.execute(sql, params). If it fails due to parameter style, retry with replacing '?'=> '%s'.
    This keeps the code working with sqlite3 (uses '?') and psycopg2 (uses '%s' or wrapper).
    """
    try:
        cur.execute(sql, params)
        return
    except Exception:
        # Try switching placeholder style: '?' -> '%s'
        try:
            alt = sql.replace("?", "%s")
            cur.execute(alt, params)
            return
        except Exception:
            # Last resort: try without params (some drivers/queries may accept this)
            try:
                cur.execute(sql)
                return
            except Exception:
                # re-raise original exception for logs
                raise


def _err_resp(user_message: str, exc: Exception = None, status: int = 500, provider_error: str = None):
    """
    Consistent error response generator that logs full traceback server-side,
    and returns JSON including the (short) exception message so frontend can display the real error.
    provider_error param used when 3rd-party provider returns its own error (e.g. 405 from provider).
    """
    try:
        tb = traceback.format_exc()
    except Exception:
        tb = "traceback unavailable"
    # server log (full)
    print(f"[OTP ERROR] {user_message}")
    if exc is not None:
        print("Exception:", repr(exc))
    print(tb)
    payload = {"success": False, "message": user_message}
    if exc is not None:
        # include short exception text for debugging (not the full traceback)
        try:
            payload["error"] = str(exc)
        except Exception:
            payload["error"] = "exception string unavailable"
    if provider_error:
        payload["provider_error"] = provider_error
    return jsonify(payload), status


# --- provider hooks (wire these to your Ryan functions) ---


def send_email(to_email: str, subject: str, body: str) -> bool:
    """
    Wire this to your email provider. If you have a 'ryan' module with send_email, it will be used.
    Return True on success, False on failure.
    """
    if ryan and hasattr(ryan, "send_email"):
        try:
            return bool(ryan.send_email(to=to_email, subject=subject, body=body))
        except Exception as e:
            # bubble exception upward so caller can include provider error text
            raise
    # provider isn't configured: raise so caller can fallback to DEV_RETURN_OTP
    raise NotImplementedError("send_email() not implemented. Wire it to your provider (ryan).")


def send_sms(phone: str, message: str) -> bool:
    """
    Wire this to your SMS provider. If you have a 'ryan' module with send_sms, it will be used.
    Return True on success, False on failure.
    """
    if ryan and hasattr(ryan, "send_sms"):
        try:
            return bool(ryan.send_sms(to=phone, message=message))
        except Exception:
            raise
    raise NotImplementedError("send_sms() not implemented. Wire it to your provider (ryan).")


# ensure table exists (best-effort; matches your init_db style)
def _ensure_table():
    if not get_conn:
        return
    try:
        with get_conn() as conn:
            cur = conn.cursor()
            # Try Postgres-style first (SERIAL) then fallback to SQLite AUTOINCREMENT if it errors
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
                # ignore and try SQLite-style
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


_ensure_table()


# --- routes ---


@otp_bp.route("/send-email", methods=["POST", "OPTIONS"])
def otp_send_email():
    # respond to OPTIONS for preflight quickly (return 204 No Content)
    if request.method == "OPTIONS":
        return make_response(('', 204))

    # debug print for logs
    try:
        body_debug = request.get_json(silent=True)
    except Exception:
        body_debug = None
    print(f"[DEBUG] send-email called: method={request.method}, path={request.path}, data={body_debug}")

    try:
        data = request.get_json() or {}
        # accept both "email" and "contact" keys to be robust
        email = (data.get("email") or data.get("contact") or "").strip()
        reason = (data.get("reason") or "registration").strip()

        if not email:
            return _err_resp("Missing email", None, 400)

        code = _gen_code()
        salt_hex, hash_hex = hash_otp(code)
        created_at = datetime.utcnow().isoformat()
        expires_at = (datetime.utcnow() + timedelta(seconds=OTP_TTL_SECONDS)).isoformat()

        # store hashed OTP (delete previous same contact/channel/reason)
        if not get_conn:
            return _err_resp("Database not configured", None, 500)
        try:
            with get_conn() as conn:
                cur = conn.cursor()
                execute_with_params(
                    cur, conn,
                    "DELETE FROM otp_codes WHERE contact = ? AND channel = ? AND reason = ?",
                    (email, "email", reason)
                )
                execute_with_params(
                    cur, conn,
                    "INSERT INTO otp_codes (contact, channel, code_hash, code_salt, reason, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (email, "email", hash_hex, salt_hex, reason, created_at, expires_at)
                )
                try:
                    conn.commit()
                except Exception:
                    pass
        except Exception as e:
            return _err_resp("Failed to store OTP", e, 500)

        # send via provider
        subject = "Your verification code"
        body = f"Your verification code is {code}. It expires in {OTP_TTL_SECONDS//60} minutes."
        try:
            ok = send_email(email, subject, body)
            if not ok:
                # provider returned falsy - surface that
                return _err_resp("Email provider returned falsy response", None, 500, provider_error="provider returned falsy")
        except NotImplementedError:
            # in dev we can return code even if provider not wired
            if DEV_RETURN_OTP:
                return jsonify({"success": True, "message": "OTP stored (email provider not wired)", "code": code, "expires_at": expires_at}), 200
            return _err_resp("Email provider not configured", None, 500)
        except Exception as e:
            # include provider exception text
            return _err_resp("Failed to send email OTP", e, 500, provider_error=str(e))

        resp = {"success": True, "message": "Email OTP sent"}
        if DEV_RETURN_OTP:
            resp["code"] = code
            resp["expires_at"] = expires_at
        return jsonify(resp), 200

    except Exception as e:
        return _err_resp("Server error while processing send-email", e, 500)


@otp_bp.route("/send-sms", methods=["POST", "OPTIONS"])
def otp_send_sms():
    # respond to OPTIONS for preflight quickly
    if request.method == "OPTIONS":
        return make_response(('', 204))

    # debug print for logs
    try:
        body_debug = request.get_json(silent=True)
    except Exception:
        body_debug = None
    print(f"[DEBUG] send-sms called: method={request.method}, path={request.path}, data={body_debug}")

    try:
        data = request.get_json() or {}
        phone = (data.get("phone") or data.get("contact") or "").strip()
        reason = (data.get("reason") or "registration").strip()

        if not phone:
            return _err_resp("Missing phone", None, 400)

        code = _gen_code()
        salt_hex, hash_hex = hash_otp(code)
        created_at = datetime.utcnow().isoformat()
        expires_at = (datetime.utcnow() + timedelta(seconds=OTP_TTL_SECONDS)).isoformat()

        if not get_conn:
            return _err_resp("Database not configured", None, 500)
        # store hashed OTP
        try:
            with get_conn() as conn:
                cur = conn.cursor()
                execute_with_params(
                    cur, conn,
                    "DELETE FROM otp_codes WHERE contact = ? AND channel = ? AND reason = ?",
                    (phone, "sms", reason)
                )
                execute_with_params(
                    cur, conn,
                    "INSERT INTO otp_codes (contact, channel, code_hash, code_salt, reason, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (phone, "sms", hash_hex, salt_hex, reason, created_at, expires_at)
                )
                try:
                    conn.commit()
                except Exception:
                    pass
        except Exception as e:
            return _err_resp("Failed to store OTP", e, 500)

        # send via provider
        msg = f"Your verification code is {code}. It expires in {OTP_TTL_SECONDS//60} minutes."
        try:
            ok = send_sms(phone, msg)
            if not ok:
                return _err_resp("SMS provider returned falsy response", None, 500, provider_error="provider returned falsy")
        except NotImplementedError:
            if DEV_RETURN_OTP:
                return jsonify({"success": True, "message": "OTP stored (sms provider not wired)", "code": code, "expires_at": expires_at}), 200
            return _err_resp("SMS provider not configured", None, 500)
        except Exception as e:
            return _err_resp("Failed to send SMS OTP", e, 500, provider_error=str(e))

        resp = {"success": True, "message": "SMS OTP sent"}
        if DEV_RETURN_OTP:
            resp["code"] = code
            resp["expires_at"] = expires_at
        return jsonify(resp), 200

    except Exception as e:
        return _err_resp("Server error while processing send-sms", e, 500)


@otp_bp.route("/verify", methods=["POST", "OPTIONS"])
def otp_verify():
    # respond to OPTIONS for preflight quickly
    if request.method == "OPTIONS":
        return make_response(('', 204))

    """
    POST /api/otp/verify
    Body: { "contact": "...", "channel": "email"|"sms", "code": "123456", "reason": "registration" }
    Response: { success: bool, message: str }
    """
    try:
        data = request.get_json() or {}
        # accept flexible keys for contact input
        contact = (data.get("contact") or data.get("email") or data.get("phone") or "").strip()
        channel = (data.get("channel") or ("sms" if data.get("phone") else "email")).strip()
        code = (data.get("code") or "").strip()
        reason = (data.get("reason") or "registration").strip()

        if not contact or not code:
            return _err_resp("Missing contact or code", None, 400)
        if channel not in ("email", "sms"):
            return _err_resp("Invalid channel", None, 400)

        if not get_conn:
            return _err_resp("Database not configured", None, 500)

        with get_conn() as conn:
            cur = conn.cursor()
            execute_with_params(
                cur, conn,
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

            # parse expiry (handle both ISO string and native datetime from Postgres)
            try:
                if isinstance(expires_at, str):
                    exp_dt = datetime.fromisoformat(expires_at)
                else:
                    # Some DB drivers (Postgres) may already return datetime objects
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
                return jsonify({"success": False, "message": "OTP expired"}), 400

            if not verify_otp(code, stored_salt, stored_hash):
                return jsonify({"success": False, "message": "Invalid OTP"}), 401

            # success: delete used OTP (single-use)
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
        return _err_resp("Server error while processing verify", e, 500)