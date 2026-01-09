# otp.py
# Register in app.py:
#   from otp import otp_bp
#   app.register_blueprint(otp_bp, url_prefix="/api")
#
# Works with Postgres (psycopg2) or SQLite via your utils.get_conn().

import os
import random
import traceback
from datetime import datetime, timedelta
import hashlib
import binascii
import hmac
from flask import Blueprint, request, jsonify, make_response

# Optional: flask_cors - we still add manual CORS headers on responses to be explicit.
try:
    from flask_cors import CORS
except Exception:
    CORS = None

# try to import project helpers
try:
    from utils import get_conn, now_iso
except Exception:
    get_conn = None

    def now_iso():
        return datetime.utcnow().isoformat()

# try to use existing provider module 'ryan' if present
ryan = None
try:
    import ryan
except Exception:
    ryan = None

# blueprint
otp_bp = Blueprint("otp_bp", __name__, url_prefix="/otp")
# enable CORS on blueprint (best-effort)
try:
    if CORS:
        CORS(otp_bp, supports_credentials=True)
except Exception:
    pass

# config
OTP_TTL_SECONDS = int(os.environ.get("OTP_TTL_SECONDS", 10 * 60))  # 10 minutes default
DEV_RETURN_OTP = os.environ.get("DEV_RETURN_OTP", "true").lower() not in ("0", "false", "no")
OTP_HASH_ITER = int(os.environ.get("OTP_HASH_ITER", 200_000))
OTP_SALT_BYTES = int(os.environ.get("OTP_SALT_BYTES", 16))

# Helpers -------------------------------------------------------------------


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
    Try cur.execute(sql, params). If that throws because of placeholder style,
    try replacing '?' -> '%s' for psycopg2.
    """
    try:
        cur.execute(sql, params)
        return
    except Exception:
        # try alt placeholder pattern
        try:
            alt = sql.replace("?", "%s")
            cur.execute(alt, params)
            return
        except Exception:
            # try without params as last resort
            try:
                cur.execute(sql)
                return
            except Exception:
                raise


def _add_cors_headers(resp):
    """
    Add CORS headers to a Flask response object. When credentials are used we echo Origin.
    """
    origin = request.headers.get("Origin") or request.headers.get("origin") or "*"
    # If front-end uses credentials, browser rejects Access-Control-Allow-Origin='*', but for dev we echo.
    if origin == "null":
        origin = "*"
    resp.headers["Access-Control-Allow-Origin"] = origin
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    resp.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return resp


def _err_resp(msg, exc: Exception = None, status=500):
    """
    Return a JSON error response with debug details (stacktrace string) — helpful for frontend debug.
    """
    detail = None
    if exc is not None:
        try:
            detail = str(exc)
        except Exception:
            detail = "exception (no message)"
    # include a short stack excerpt when available (do not leak secrets in prod!)
    tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)) if exc else None
    body = {"success": False, "message": msg, "status": "error", "error_detail": detail}
    if tb:
        body["stack"] = tb
    resp = make_response(jsonify(body), status)
    return _add_cors_headers(resp)


# Provider wiring -----------------------------------------------------------


def send_email_provider(to_email: str, subject: str, body: str) -> bool:
    """
    Wrapper that attempts to use ryan.send_email if available.
    If ryan is not present and we're in DEV_RETURN_OTP mode, we return True (simulated).
    If provider exists, surface its exceptions back to caller.
    """
    if ryan and hasattr(ryan, "send_email"):
        # user-provided provider may return status, bool, or raise error
        try:
            ok = ryan.send_email(to=to_email, subject=subject, body=body)
            # interpret truthy result as success
            return bool(ok)
        except Exception as e:
            # surface provider error
            raise
    # no provider wired
    if DEV_RETURN_OTP:
        # in dev/testing we simulate success so you get OTP returned in response
        print("[OTP] DEV mode - not sending real email (provider not configured).")
        return True
    # production-like: indicate provider not configured
    raise NotImplementedError("No email provider (ryan) configured")


# Ensure table exists ------------------------------------------------------


def _ensure_table():
    if not get_conn:
        print("[OTP] get_conn not available; skipping table creation.")
        return
    try:
        with get_conn() as conn:
            cur = conn.cursor()
            # Try Postgres SERIAL style first; fallback to SQLite AUTOINCREMENT
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
                # try sqlite style
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


# initialize table on import (safe best-effort)
_ensure_table()

# Routes --------------------------------------------------------------------


@otp_bp.route("/send-email", methods=["POST", "OPTIONS"])
def otp_send_email():
    # quick reply for preflight
    if request.method == "OPTIONS":
        resp = make_response(jsonify({"ok": True}), 200)
        return _add_cors_headers(resp)

    try:
        body_debug = request.get_json(silent=True)
    except Exception:
        body_debug = None
    print(f"[OTP] send-email called. data={body_debug}")

    try:
        data = request.get_json() or {}
        # be flexible: accept { email } or { contact }
        email = (data.get("email") or data.get("contact") or "").strip()
        reason = (data.get("reason") or "registration").strip()

        if not email:
            return _err_resp("Missing email", None, 400)

        # generate OTP
        code = _gen_code()
        salt_hex, hash_hex = hash_otp(code)
        created_at = datetime.utcnow().isoformat()
        expires_at = (datetime.utcnow() + timedelta(seconds=OTP_TTL_SECONDS)).isoformat()

        if not get_conn:
            return _err_resp("Database not configured (get_conn missing)", None, 500)

        # store hashed OTP (delete previous same contact/channel/reason)
        try:
            with get_conn() as conn:
                cur = conn.cursor()
                execute_with_params(
                    cur, conn,
                    "DELETE FROM otp_codes WHERE contact = ? AND channel = ? AND reason = ?",
                    (email, "email", reason),
                )
                execute_with_params(
                    cur, conn,
                    "INSERT INTO otp_codes (contact, channel, code_hash, code_salt, reason, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (email, "email", hash_hex, salt_hex, reason, created_at, expires_at),
                )
                try:
                    conn.commit()
                except Exception:
                    pass
        except Exception as e:
            return _err_resp("Failed to store OTP in DB", e, 500)

        # send email via provider (may raise)
        subject = "Your verification code"
        text_body = f"Your verification code is {code}. It expires in {OTP_TTL_SECONDS//60} minutes."

        try:
            ok = send_email_provider(email, subject, text_body)
            if not ok:
                # provider returned falsy
                raise Exception("email provider returned falsy")
        except NotImplementedError as e:
            # provider is not configured
            if DEV_RETURN_OTP:
                # respond with OTP in dev mode
                body = {"success": True, "message": "OTP stored (email provider not wired)", "code": code, "expires_at": expires_at}
                resp = make_response(jsonify(body), 200)
                return _add_cors_headers(resp)
            return _err_resp("Email provider not configured", e, 500)
        except Exception as e:
            # provider failure: return full error to frontend for debugging
            return _err_resp("Failed to send email OTP (provider error)", e, 500)

        # success (in dev mode also include code)
        resp_body = {"success": True, "message": "Email OTP sent"}
        if DEV_RETURN_OTP:
            resp_body["code"] = code
            resp_body["expires_at"] = expires_at
        resp = make_response(jsonify(resp_body), 200)
        return _add_cors_headers(resp)

    except Exception as e:
        return _err_resp("Server error while processing send-email", e, 500)


@otp_bp.route("/verify", methods=["POST", "OPTIONS"])
def otp_verify():
    # quick reply for preflight
    if request.method == "OPTIONS":
        resp = make_response(jsonify({"ok": True}), 200)
        return _add_cors_headers(resp)

    try:
        data = request.get_json() or {}
        contact = (data.get("contact") or data.get("email") or data.get("phone") or "").strip()
        channel = (data.get("channel") or ("email" if data.get("email") or True else "sms")).strip()
        code = (data.get("code") or "").strip()
        reason = (data.get("reason") or "registration").strip()

        if not contact or not code:
            return _err_resp("Missing contact or code", None, 400)
        if channel not in ("email", "sms"):
            return _err_resp("Invalid channel", None, 400)
        if not get_conn:
            return _err_resp("Database not configured (get_conn missing)", None, 500)

        with get_conn() as conn:
            cur = conn.cursor()
            execute_with_params(
                cur, conn,
                "SELECT id, code_hash, code_salt, expires_at FROM otp_codes WHERE contact = ? AND channel = ? AND reason = ? ORDER BY id DESC LIMIT 1",
                (contact, channel, reason),
            )
            row = cur.fetchone()
            if not row:
                return _err_resp("OTP not found", None, 404)

            otp_id = _row_get(row, 0)
            stored_hash = _row_get(row, 1)
            stored_salt = _row_get(row, 2)
            expires_at = _row_get(row, 3)

            # parse expiry (ISO or datetime)
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
                # do NOT reveal more details for security, but return 401
                return _err_resp("Invalid OTP", None, 401)

            # success: delete used OTP
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