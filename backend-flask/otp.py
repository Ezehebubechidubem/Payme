# otp_routes.py
# Drop this file into your project and register the blueprint in app.py:
#   from otp_routes import otp_bp
#   app.register_blueprint(otp_bp, url_prefix="/api")
#
# This file follows your project's DB/get_conn pattern and stores OTPs as salted PBKDF2 hashes.

import os
import random
import traceback
from datetime import datetime, timedelta
import hashlib
import binascii
import hmac

from flask import Blueprint, request, jsonify

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

# configuration via env
OTP_TTL_SECONDS = int(os.environ.get("OTP_TTL_SECONDS", 10 * 60))  # default 10 minutes
DEV_RETURN_OTP = os.environ.get("DEV_RETURN_OTP", "true").lower() not in ("0", "false", "no")
OTP_HASH_ITER = int(os.environ.get("OTP_HASH_ITER", 200_000))
OTP_SALT_BYTES = int(os.environ.get("OTP_SALT_BYTES", 16))

# --- helpers ---

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

# --- provider hooks (wire these to your Ryan functions) ---

def send_email(to_email: str, subject: str, body: str) -> bool:
    """
    Wire this to your email provider. If you have a 'ryan' module with send_email, it will be used.
    Return True on success, False on failure.
    """
    if ryan and hasattr(ryan, "send_email"):
        try:
            return bool(ryan.send_email(to=to_email, subject=subject, body=body))
        except Exception:
            traceback.print_exc()
            return False
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
            traceback.print_exc()
            return False
    raise NotImplementedError("send_sms() not implemented. Wire it to your provider (ryan).")

# ensure table exists (best-effort; matches your init_db style)
def _ensure_table():
    if not get_conn:
        return
    try:
        with get_conn() as conn:
            cur = conn.cursor()
            # create table suitable for both Postgres and SQLite patterns used in your project
            # (Postgres will accept this; SQLite will accept it too with minor differences)
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
        # if DB is Postgres, above SQL will still work; if your app later runs a Postgres CREATE with SERIAL,
        # make sure init_db() contains the Postgres variant. This is just a safe fallback creation.
        traceback.print_exc()

_ensure_table()

# --- routes ---

@otp_bp.route("/send-email", methods=["POST"])
def otp_send_email():
    """
    POST /api/otp/send-email
    Body: { "email": "...", "reason": "registration" }
    Returns:
      { success: True, message: "...", code?: "123456" }  // code returned only in DEV_RETURN_OTP mode
    """
    try:
        data = request.get_json() or {}
        email = (data.get("email") or "").strip()
        reason = (data.get("reason") or "general").strip()

        if not email:
            return jsonify({"success": False, "message": "Missing email"}), 400

        code = _gen_code()
        salt_hex, hash_hex = hash_otp(code)
        created_at = datetime.utcnow().isoformat()
        expires_at = (datetime.utcnow() + timedelta(seconds=OTP_TTL_SECONDS)).isoformat()

        # store hashed OTP (delete previous same contact/channel/reason)
        try:
            with get_conn() as conn:
                cur = conn.cursor()
                cur.execute("DELETE FROM otp_codes WHERE contact = ? AND channel = ? AND reason = ?", (email, "email", reason))
                cur.execute(
                    "INSERT INTO otp_codes (contact, channel, code_hash, code_salt, reason, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (email, "email", hash_hex, salt_hex, reason, created_at, expires_at)
                )
                try:
                    conn.commit()
                except Exception:
                    pass
        except Exception:
            traceback.print_exc()
            return jsonify({"success": False, "message": "Failed to store OTP"}), 500

        # send via provider
        subject = "Your verification code"
        body = f"Your verification code is {code}. It expires in {OTP_TTL_SECONDS//60} minutes."
        try:
            ok = send_email(email, subject, body)
            if not ok:
                raise Exception("email provider returned falsy")
        except NotImplementedError:
            # in dev we can return code even if provider not wired
            if DEV_RETURN_OTP:
                return jsonify({"success": True, "message": "OTP stored (email provider not wired)", "code": code, "expires_at": expires_at}), 200
            return jsonify({"success": False, "message": "Email provider not configured"}), 500
        except Exception:
            traceback.print_exc()
            return jsonify({"success": False, "message": "Failed to send email OTP"}), 500

        resp = {"success": True, "message": "Email OTP sent"}
        if DEV_RETURN_OTP:
            resp["code"] = code
            resp["expires_at"] = expires_at
        return jsonify(resp), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({"success": False, "message": f"Server error: {str(e)}"}), 500


@otp_bp.route("/send-sms", methods=["POST"])
def otp_send_sms():
    """
    POST /api/otp/send-sms
    Body: { "phone": "...", "reason": "registration" }
    Returns:
      { success: True, message: "...", code?: "123456" }  // code returned only in DEV_RETURN_OTP mode
    """
    try:
        data = request.get_json() or {}
        phone = (data.get("phone") or "").strip()
        reason = (data.get("reason") or "general").strip()

        if not phone:
            return jsonify({"success": False, "message": "Missing phone"}), 400

        code = _gen_code()
        salt_hex, hash_hex = hash_otp(code)
        created_at = datetime.utcnow().isoformat()
        expires_at = (datetime.utcnow() + timedelta(seconds=OTP_TTL_SECONDS)).isoformat()

        # store hashed OTP
        try:
            with get_conn() as conn:
                cur = conn.cursor()
                cur.execute("DELETE FROM otp_codes WHERE contact = ? AND channel = ? AND reason = ?", (phone, "sms", reason))
                cur.execute(
                    "INSERT INTO otp_codes (contact, channel, code_hash, code_salt, reason, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (phone, "sms", hash_hex, salt_hex, reason, created_at, expires_at)
                )
                try:
                    conn.commit()
                except Exception:
                    pass
        except Exception:
            traceback.print_exc()
            return jsonify({"success": False, "message": "Failed to store OTP"}), 500

        # send via provider
        msg = f"Your verification code is {code}. It expires in {OTP_TTL_SECONDS//60} minutes."
        try:
            ok = send_sms(phone, msg)
            if not ok:
                raise Exception("sms provider returned falsy")
        except NotImplementedError:
            if DEV_RETURN_OTP:
                return jsonify({"success": True, "message": "OTP stored (sms provider not wired)", "code": code, "expires_at": expires_at}), 200
            return jsonify({"success": False, "message": "SMS provider not configured"}), 500
        except Exception:
            traceback.print_exc()
            return jsonify({"success": False, "message": "Failed to send SMS OTP"}), 500

        resp = {"success": True, "message": "SMS OTP sent"}
        if DEV_RETURN_OTP:
            resp["code"] = code
            resp["expires_at"] = expires_at
        return jsonify(resp), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({"success": False, "message": f"Server error: {str(e)}"}), 500


@otp_bp.route("/verify", methods=["POST"])
def otp_verify():
    """
    POST /api/otp/verify
    Body: { "contact": "...", "channel": "email"|"sms", "code": "123456", "reason": "registration" }
    Response: { success: bool, message: str }
    """
    try:
        data = request.get_json() or {}
        contact = (data.get("contact") or "").strip()
        channel = (data.get("channel") or "email").strip()
        code = (data.get("code") or "").strip()
        reason = (data.get("reason") or "general").strip()

        if not contact or not code:
            return jsonify({"success": False, "message": "Missing contact or code"}), 400
        if channel not in ("email", "sms"):
            return jsonify({"success": False, "message": "Invalid channel"}), 400

        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
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
                exp_dt = datetime.fromisoformat(expires_at) if isinstance(expires_at, str) else expires_at
            except Exception:
                exp_dt = datetime.utcnow() - timedelta(seconds=1)

            if exp_dt < datetime.utcnow():
                try:
                    cur.execute("DELETE FROM otp_codes WHERE id = ?", (otp_id,))
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
                cur.execute("DELETE FROM otp_codes WHERE id = ?", (otp_id,))
                try:
                    conn.commit()
                except Exception:
                    pass
            except Exception:
                pass

            return jsonify({"success": True, "message": "OTP verified"}), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({"success": False, "message": f"Server error: {str(e)}"}), 500