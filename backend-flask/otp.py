# otp.py  (or otp_routes.py)
# Drop this file into your project and register the blueprint in app.py:
#   from otp import otp_bp
#   app.register_blueprint(otp_bp, url_prefix="/api")
#
# Works in testing mode by default (returns OTP in response when provider not wired).
# Supports both Postgres (psycopg2) and SQLite via your utils.get_conn().

import os
import random
import traceback
from datetime import datetime, timedelta
import hashlib
import binascii
import hmac
import json

from flask_cors import CORS
from flask import Blueprint, request, jsonify, make_response

# try to import your project's DB helpers (get_conn / now_iso)
try:
    from utils import get_conn, now_iso
except Exception:
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
# enable CORS on this blueprint (app.py usually enables CORS globally too)
try:
    CORS(otp_bp, supports_credentials=True)
except Exception:
    # don't crash if flask_cors isn't available
    pass

# configuration via environment
OTP_TTL_SECONDS = int(os.environ.get("OTP_TTL_SECONDS", 10 * 60))  # default 10 minutes
DEV_RETURN_OTP = os.environ.get("DEV_RETURN_OTP", "true").lower() not in ("0", "false", "no")
OTP_HASH_ITER = int(os.environ.get("OTP_HASH_ITER", 200_000))
OTP_SALT_BYTES = int(os.environ.get("OTP_SALT_BYTES", 16))

# --- utilities / helpers ---


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
    Try cur.execute(sql, params). If it fails due to parameter style, retry with replacing '?'=> '%s'.
    Keeps code compatible with sqlite3 and psycopg2.
    """
    try:
        cur.execute(sql, params)
        return
    except Exception as e1:
        try:
            alt = sql.replace("?", "%s")
            cur.execute(alt, params)
            return
        except Exception:
            try:
                # last-ditch: execute without params (may work for simple queries in some drivers)
                cur.execute(sql)
                return
            except Exception:
                # raise original so logs show root cause
                raise e1


def _err_resp(message: str, exc: Exception = None, status: int = 500):
    """
    Standardized error response. In DEV_RETURN_OTP mode we also include exc text/trace
    to help debugging; in production we avoid exposing internals.
    """
    print(f"[OTP][ERROR] {message}")
    if exc:
        traceback.print_exc()
    body = {"success": False, "message": message}
    if exc:
        body["error"] = str(exc)
    if DEV_RETURN_OTP and exc:
        body["trace"] = traceback.format_exc()
    return jsonify(body), status


# --- provider hooks (wire these to your provider) ---
# In testing mode we rely on DEV_RETURN_OTP behavior in the routes.
def send_email(to_email: str, subject: str, body: str) -> bool:
    """
    If you have a 'ryan' module with send_email, it will be called.
    Otherwise raise NotImplementedError and routes will return OTP in DEV mode.
    """
    if ryan and hasattr(ryan, "send_email"):
        try:
            return bool(ryan.send_email(to=to_email, subject=subject, body=body))
        except Exception:
            traceback.print_exc()
            return False
    raise NotImplementedError("send_email() not implemented; wire to provider (ryan) or implement this function.")


def send_sms(phone: str, message: str) -> bool:
    if ryan and hasattr(ryan, "send_sms"):
        try:
            return bool(ryan.send_sms(to=phone, message=message))
        except Exception:
            traceback.print_exc()
            return False
    raise NotImplementedError("send_sms() not implemented; wire to provider (ryan) or implement this function.")


# --- ensure table exists (best-effort) ---
def _ensure_table():
    if not get_conn:
        print("[OTP] no get_conn available; skipping table ensure")
        return
    try:
        with get_conn() as conn:
            cur = conn.cursor()
            # Try Postgres-style first then fallback to SQLite-style.
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
                # fallback for sqlite
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
    # respond to OPTIONS preflight quickly
    if request.method == "OPTIONS":
        return make_response(jsonify({"ok": True}), 200)

    # debug input
    try:
        body_debug = request.get_json(silent=True)
    except Exception:
        body_debug = None
    print(f"[DEBUG] send-email called: method={request.method}, path={request.path}, data={body_debug}")

    try:
        data = request.get_json() or {}
        email = (data.get("email") or data.get("contact") or "").strip()
        reason = (data.get("reason") or "registration").strip()

        if not email:
            return jsonify({"success": False, "message": "Missing email"}), 400

        code = _gen_code()
        salt_hex, hash_hex = hash_otp(code)
        created_at = datetime.utcnow().isoformat()
        expires_at = (datetime.utcnow() + timedelta(seconds=OTP_TTL_SECONDS)).isoformat()

        if not get_conn:
            return _err_resp("Database not configured", None, 500)

        # store hashed OTP (delete previous)
        try:
            with get_conn() as conn:
                cur = conn.cursor()
                execute_with_params(cur, conn, "DELETE FROM otp_codes WHERE contact = ? AND channel = ? AND reason = ?", (email, "email", reason))
                execute_with_params(cur, conn, "INSERT INTO otp_codes (contact, channel, code_hash, code_salt, reason, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                                    (email, "email", hash_hex, salt_hex, reason, created_at, expires_at))
                try:
                    conn.commit()
                except Exception:
                    pass
        except Exception as e:
            return _err_resp("Failed to store OTP", e, 500)

        # Try to send via provider. If provider not wired, routes return code in DEV mode.
        subject = "Your verification code"
        body_text = f"Your verification code is {code}. It expires in {OTP_TTL_SECONDS//60} minutes."
        try:
            ok = send_email(email, subject, body_text)
            if not ok:
                raise Exception("email provider returned falsy")
        except NotImplementedError:
            if DEV_RETURN_OTP:
                return jsonify({"success": True, "message": "OTP stored (email provider not wired)", "code": code, "expires_at": expires_at}), 200
            return _err_resp("Email provider not configured", None, 500)
        except Exception as e:
            # provider raised something (could be 405 coming from provider wrapper). Surface helpful message in DEV mode.
            return _err_resp("Failed to send email OTP", e, 500)

        resp = {"success": True, "message": "Email OTP sent"}
        if DEV_RETURN_OTP:
            resp["code"] = code
            resp["expires_at"] = expires_at
        return jsonify(resp), 200

    except Exception as e:
        return _err_resp("Server error while processing send-email", e, 500)


@otp_bp.route("/send-sms", methods=["POST", "OPTIONS"])
def otp_send_sms():
    if request.method == "OPTIONS":
        return make_response(jsonify({"ok": True}), 200)

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
            return jsonify({"success": False, "message": "Missing phone"}), 400

        code = _gen_code()
        salt_hex, hash_hex = hash_otp(code)
        created_at = datetime.utcnow().isoformat()
        expires_at = (datetime.utcnow() + timedelta(seconds=OTP_TTL_SECONDS)).isoformat()

        if not get_conn:
            return _err_resp("Database not configured", None, 500)

        try:
            with get_conn() as conn:
                cur = conn.cursor()
                execute_with_params(cur, conn, "DELETE FROM otp_codes WHERE contact = ? AND channel = ? AND reason = ?", (phone, "sms", reason))
                execute_with_params(cur, conn, "INSERT INTO otp_codes (contact, channel, code_hash, code_salt, reason, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                                    (phone, "sms", hash_hex, salt_hex, reason, created_at, expires_at))
                try:
                    conn.commit()
                except Exception:
                    pass
        except Exception as e:
            return _err_resp("Failed to store OTP", e, 500)

        msg = f"Your verification code is {code}. It expires in {OTP_TTL_SECONDS//60} minutes."
        try:
            ok = send_sms(phone, msg)
            if not ok:
                raise Exception("sms provider returned falsy")
        except NotImplementedError:
            if DEV_RETURN_OTP:
                return jsonify({"success": True, "message": "OTP stored (sms provider not wired)", "code": code, "expires_at": expires_at}), 200
            return _err_resp("SMS provider not configured", None, 500)
        except Exception as e:
            return _err_resp("Failed to send SMS OTP", e, 500)

        resp = {"success": True, "message": "SMS OTP sent"}
        if DEV_RETURN_OTP:
            resp["code"] = code
            resp["expires_at"] = expires_at
        return jsonify(resp), 200

    except Exception as e:
        return _err_resp("Server error while processing send-sms", e, 500)


@otp_bp.route("/verify", methods=["POST", "OPTIONS"])
def otp_verify():
    if request.method == "OPTIONS":
        return make_response(jsonify({"ok": True}), 200)

    try:
        data = request.get_json() or {}
        contact = (data.get("contact") or data.get("email") or data.get("phone") or "").strip()
        # default channel guess if not provided
        channel = (data.get("channel") or ("sms" if data.get("phone") else "email")).strip()
        code = (data.get("code") or "").strip()
        reason = (data.get("reason") or "registration").strip()

        if not contact or not code:
            return jsonify({"success": False, "message": "Missing contact or code"}), 400
        if channel not in ("email", "sms"):
            return jsonify({"success": False, "message": "Invalid channel"}), 400
        if not get_conn:
            return _err_resp("Database not configured", None, 500)

        with get_conn() as conn:
            cur = conn.cursor()
            execute_with_params(cur, conn,
                                "SELECT id, code_hash, code_salt, expires_at FROM otp_codes WHERE contact = ? AND channel = ? AND reason = ? ORDER BY id DESC LIMIT 1",
                                (contact, channel, reason))
            row = cur.fetchone()
            if not row:
                return jsonify({"success": False, "message": "OTP not found"}), 404

            otp_id = _row_get(row, 0)
            stored_hash = _row_get(row, 1)
            stored_salt = _row_get(row, 2)
            expires_at = _row_get(row, 3)

            # parse expiry (string iso or native datetime)
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
                return jsonify({"success": False, "message": "OTP expired"}), 400

            if not verify_otp(code, stored_salt, stored_hash):
                return jsonify({"success": False, "message": "Invalid OTP"}), 401

            # success: delete used OTP
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