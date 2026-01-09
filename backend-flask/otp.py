# otp.py
# OTP routes: email + sms (email wired to Resend if key present).
# Works with both PostgreSQL (psycopg2) and SQLite (sqlite3) via utils.get_conn().

import os
import random
import traceback
from datetime import datetime, timedelta
import hashlib
import binascii
import hmac
import json

import requests  # required for Resend provider path
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

# try to use existing "ryan" provider module if you have it (optional)
ryan = None
try:
    import ryan  # optional: your existing service wrapper
except Exception:
    ryan = None

otp_bp = Blueprint("otp_bp", __name__, url_prefix="/otp")
# enable CORS on this blueprint (app.py usually enables CORS globally too)
try:
    CORS(otp_bp, supports_credentials=True)
except Exception:
    pass

# config via env
OTP_TTL_SECONDS = int(os.environ.get("OTP_TTL_SECONDS", 10 * 60))  # default 10 minutes
DEV_RETURN_OTP = os.environ.get("DEV_RETURN_OTP", "true").lower() not in ("0", "false", "no")
OTP_HASH_ITER = int(os.environ.get("OTP_HASH_ITER", 200_000))
OTP_SALT_BYTES = int(os.environ.get("OTP_SALT_BYTES", 16))

# Resend config (email)
RESEND_API_KEY = os.environ.get("RESEND_API_KEY")  # if present, we'll use Resend
RESEND_FROM = os.environ.get("RESEND_FROM", "noreply@example.com")
RESEND_TIMEOUT = float(os.environ.get("RESEND_TIMEOUT", 10.0))
RESEND_ENABLED = bool(RESEND_API_KEY)

# helpers ---------------------------------------------------------------------

def _err_resp(msg, exc=None, status=500, include_trace=False):
    """Return a JSON error response with optional debug info (safe in dev)."""
    body = {"success": False, "message": msg}
    if exc and (DEV_RETURN_OTP or include_trace):
        try:
            body["error"] = str(exc)
            tb = traceback.format_exc()
            body["trace"] = tb
        except Exception:
            pass
    return jsonify(body), status

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
    Execute with either '?' (sqlite) or '%s' (psycopg2) placeholder styles.
    Falls back to execute(sql) if param execution fails.
    """
    try:
        cur.execute(sql, params)
        return
    except Exception:
        try:
            alt = sql.replace("?", "%s")
            cur.execute(alt, params)
            return
        except Exception:
            try:
                cur.execute(sql)
                return
            except Exception:
                raise

# provider hooks --------------------------------------------------------------

def send_email_via_resend(to_email: str, subject: str, body_text: str) -> dict:
    """
    Send email via Resend (https://resend.com). Returns provider response dict on success.
    Raises Exception on failure.
    """
    if not RESEND_API_KEY:
        raise NotImplementedError("Resend API key not configured")

    payload = {
        "from": RESEND_FROM,
        "to": [to_email],
        "subject": subject,
        "text": body_text
    }
    headers = {
        "Authorization": f"Bearer {RESEND_API_KEY}",
        "Content-Type": "application/json"
    }

    r = requests.post("https://api.resend.com/emails", headers=headers, json=payload, timeout=RESEND_TIMEOUT)
    # Raise for status so caller can decide how to handle
    r.raise_for_status()
    try:
        return r.json()
    except Exception:
        return {"status": "ok", "raw_text": r.text}

def send_email(to_email: str, subject: str, body: str) -> bool:
    """
    Public send_email function used by routes.
    - If ryan module implements send_email, prefer that.
    - Else if RESEND_API_KEY available, use Resend.
    - Else raise NotImplementedError so caller can decide (DEV_RETURN_OTP fallback).
    """
    # prefer user-supplied 'ryan' module if present
    if ryan and hasattr(ryan, "send_email"):
        try:
            return bool(ryan.send_email(to=to_email, subject=subject, body=body))
        except Exception as e:
            # bubble up to caller
            raise

    # fallback: Resend
    if RESEND_API_KEY:
        send_email_via_resend(to_email, subject, body)
        return True

    # no provider configured
    raise NotImplementedError("send_email provider not configured")

def send_sms(phone: str, message: str) -> bool:
    """
    SMS provider not wired here. Raise NotImplementedError so caller falls back to DEV_RETURN_OTP if desired.
    Later, implement with a provider (Twilio, Africa's Talking, etc).
    """
    if ryan and hasattr(ryan, "send_sms"):
        try:
            return bool(ryan.send_sms(to=phone, message=message))
        except Exception:
            raise
    raise NotImplementedError("send_sms provider not configured")

# DB table ensure -------------------------------------------------------------

def _ensure_table():
    if not get_conn:
        return
    try:
        with get_conn() as conn:
            cur = conn.cursor()
            # try Postgres SERIAL first
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
                # fallback to sqlite-style
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

# ROUTES ---------------------------------------------------------------------

@otp_bp.route("/send-email", methods=["POST", "OPTIONS"])
def otp_send_email():
    # respond to OPTIONS for preflight quickly
    if request.method == "OPTIONS":
        return make_response(jsonify({"ok": True}), 200)

    try:
        body_debug = request.get_json(silent=True)
    except Exception:
        body_debug = None
    print(f"[OTP] send-email called: method={request.method}, path={request.path}, data={body_debug}")

    try:
        data = request.get_json() or {}
        email = (data.get("email") or data.get("contact") or "").strip()
        reason = (data.get("reason") or "registration").strip()

        if not email:
            return jsonify({"success": False, "message": "Missing email"}), 400

        # generate code + hashes
        code = _gen_code()
        salt_hex, hash_hex = hash_otp(code)
        created_at = datetime.utcnow().isoformat()
        expires_at = (datetime.utcnow() + timedelta(seconds=OTP_TTL_SECONDS)).isoformat()

        if not get_conn:
            return _err_resp("Database not configured", None, 500)

        # store OTP (single most recent per contact/channel/reason)
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

        # attempt to send
        subject = "Your verification code"
        body = f"Your verification code is {code}. It expires in {OTP_TTL_SECONDS // 60} minutes."

        try:
            ok = send_email(email, subject, body)
            if not ok:
                raise Exception("provider returned falsy")
        except NotImplementedError:
            # provider not configured -> allow dev fallback
            if DEV_RETURN_OTP:
                return jsonify({"success": True, "message": "OTP stored (no email provider configured)", "code": code, "expires_at": expires_at}), 200
            return _err_resp("Email provider not configured", None, 500)
        except requests.exceptions.RequestException as re:
            # provider network/http error
            if DEV_RETURN_OTP:
                return jsonify({"success": True, "message": "OTP stored (email provider failing)", "code": code, "expires_at": expires_at, "provider_error": str(re)}), 200
            return _err_resp("Failed to send email OTP (provider error)", re, 502)
        except Exception as e:
            # other provider error
            if DEV_RETURN_OTP:
                return jsonify({"success": True, "message": "OTP stored (email provider failing)", "code": code, "expires_at": expires_at, "provider_error": str(e)}), 200
            return _err_resp("Failed to send email OTP", e, 500)

        # successful send
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
        return make_response(jsonify({"ok": True}), 200)

    try:
        body_debug = request.get_json(silent=True)
    except Exception:
        body_debug = None
    print(f"[OTP] send-sms called: method={request.method}, path={request.path}, data={body_debug}")

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

        # We don't have an SMS provider wired here by default.
        # If DEV_RETURN_OTP is true, return the code for testing.
        try:
            # If anyone wired ryan.send_sms, it will be used by send_sms()
            ok = send_sms(phone, f"Your verification code is {code}. It expires in {OTP_TTL_SECONDS // 60} minutes.")
            if not ok:
                raise Exception("provider returned falsy")
            resp = {"success": True, "message": "SMS OTP sent"}
            if DEV_RETURN_OTP:
                resp["code"] = code
                resp["expires_at"] = expires_at
            return jsonify(resp), 200
        except NotImplementedError:
            # provider not configured
            if DEV_RETURN_OTP:
                return jsonify({"success": True, "message": "OTP stored (no sms provider configured)", "code": code, "expires_at": expires_at}), 200
            return _err_resp("SMS provider not configured", None, 500)
        except requests.exceptions.RequestException as re:
            if DEV_RETURN_OTP:
                return jsonify({"success": True, "message": "OTP stored (sms provider failing)", "code": code, "expires_at": expires_at, "provider_error": str(re)}), 200
            return _err_resp("Failed to send SMS OTP (provider error)", re, 502)
        except Exception as e:
            if DEV_RETURN_OTP:
                return jsonify({"success": True, "message": "OTP stored (sms provider failing)", "code": code, "expires_at": expires_at, "provider_error": str(e)}), 200
            return _err_resp("Failed to send SMS OTP", e, 500)

    except Exception as e:
        return _err_resp("Server error while processing send-sms", e, 500)


@otp_bp.route("/verify", methods=["POST", "OPTIONS"])
def otp_verify():
    # respond to OPTIONS for preflight quickly
    if request.method == "OPTIONS":
        return make_response(jsonify({"ok": True}), 200)

    try:
        data = request.get_json() or {}
        contact = (data.get("contact") or data.get("email") or data.get("phone") or "").strip()
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

            # parse expiry
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