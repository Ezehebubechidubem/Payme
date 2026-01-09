# otp.py
# OTP blueprint for PayMe
# Place in your project and register with:
#   from otp import otp_bp
#   app.register_blueprint(otp_bp, url_prefix="/api")
#
# Works with both Postgres (psycopg2) and sqlite3 via utils.get_conn()

import os
import random
import traceback
import json
from datetime import datetime, timedelta
import hashlib
import binascii
import hmac

# Optional external libs (requests, twilio). We import lazily so app won't fail if not installed.
try:
    import requests
except Exception:
    requests = None

try:
    from twilio.rest import Client as TwilioClient
except Exception:
    TwilioClient = None

from flask_cors import CORS
from flask import Blueprint, request, jsonify, make_response

# Try to import app helpers
try:
    from utils import get_conn, now_iso
except Exception:
    get_conn = None

    def now_iso():
        return datetime.utcnow().isoformat()

# Optional project provider wrapper
ryan = None
try:
    import ryan
except Exception:
    ryan = None

# blueprint (registered in app.py with prefix /api)
otp_bp = Blueprint("otp_bp", __name__, url_prefix="/otp")
try:
    CORS(otp_bp, supports_credentials=True)
except Exception:
    pass

# configuration
OTP_TTL_SECONDS = int(os.environ.get("OTP_TTL_SECONDS", 10 * 60))  # 10 minutes
DEV_RETURN_OTP = os.environ.get("DEV_RETURN_OTP", "true").lower() not in ("0", "false", "no")
OTP_HASH_ITER = int(os.environ.get("OTP_HASH_ITER", 200_000))
OTP_SALT_BYTES = int(os.environ.get("OTP_SALT_BYTES", 16))

# Provider env (optional)
RESEND_API_KEY = os.environ.get("RESEND_API_KEY")
TWILIO_SID = os.environ.get("TWILIO_SID")
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN")
TWILIO_FROM = os.environ.get("TWILIO_FROM")  # e.g. "+1234567890"


# ---------------- helpers ----------------

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
    Attempt execute in both styles: sqlite uses '?', psycopg2 uses '%s'.
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


def _format_exc(e):
    """
    Return dict with exception details. If e has response attr (requests), include status/text.
    """
    base = {"type": e.__class__.__name__, "message": str(e)}
    # requests.Response attached
    resp = getattr(e, "response", None)
    if resp is not None:
        try:
            body = resp.text
        except Exception:
            body = None
        base["provider_response"] = {"status_code": getattr(resp, "status_code", None), "body": body}
    # sometimes third-party libs expose status_code / text directly on exception
    sc = getattr(e, "status_code", None)
    if sc is not None and "provider_response" not in base:
        base["provider_response"] = {"status_code": sc, "body": getattr(e, "text", None)}
    return base


def _error_json(message, exc=None, status=500):
    payload = {"success": False, "message": message}
    if exc is not None:
        try:
            payload["error"] = _format_exc(exc)
        except Exception:
            payload["error"] = {"message": str(exc)}
    return jsonify(payload), status


# ---------------- provider wiring ----------------

def send_email_via_resend(to_email: str, subject: str, html_body: str):
    """Send email using Resend API. Requires RESEND_API_KEY."""
    if not requests:
        raise RuntimeError("requests library required for Resend API calls")
    if not RESEND_API_KEY:
        raise RuntimeError("RESEND_API_KEY not configured")
    url = "https://api.resend.com/emails"
    headers = {"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"}
    payload = {
        "from": "PayMe <onboarding@resend.dev>",
        "to": [to_email],
        "subject": subject,
        "html": html_body
    }
    r = requests.post(url, json=payload, headers=headers, timeout=10)
    if r.status_code not in (200, 201):
        # include response in exception for upstream logging/result
        ex = Exception(f"Resend returned {r.status_code}")
        setattr(ex, "response", r)
        raise ex
    return True


def send_sms_via_twilio(to_phone: str, message: str):
    """Send SMS using Twilio. Requires TWILIO_SID, TWILIO_AUTH_TOKEN and TWILIO_FROM."""
    if TwilioClient is None:
        raise RuntimeError("twilio library not installed")
    if not (TWILIO_SID and TWILIO_AUTH_TOKEN and TWILIO_FROM):
        raise RuntimeError("Twilio credentials not configured")
    client = TwilioClient(TWILIO_SID, TWILIO_AUTH_TOKEN)
    msg = client.messages.create(body=message, from_=TWILIO_FROM, to=to_phone)
    # Twilio raises exceptions on non-2xx, so if we reached here assume success
    return True


def send_email(to_email: str, subject: str, body: str) -> bool:
    """
    Top-level email sender. Tries:
      1) ryan.send_email (if ryan module present)
      2) Resend API (if RESEND_API_KEY present and requests installed)
      3) raises NotImplementedError
    """
    # 1) ryan wrapper
    if ryan and hasattr(ryan, "send_email"):
        try:
            return bool(ryan.send_email(to=to_email, subject=subject, body=body))
        except Exception as e:
            # bubble exception up
            raise

    # 2) Resend
    if RESEND_API_KEY and requests:
        return send_email_via_resend(to_email, subject, f"<p>{body}</p>")

    # 3) not configured
    raise NotImplementedError("No email provider configured (ryan or RESEND_API_KEY required)")


def send_sms(phone: str, message: str) -> bool:
    """
    Top-level SMS sender. Tries:
      1) ryan.send_sms
      2) Twilio (if configured)
      3) NotImplementedError
    """
    if ryan and hasattr(ryan, "send_sms"):
        try:
            return bool(ryan.send_sms(to=phone, message=message))
        except Exception:
            raise

    if TWILIO_SID and TWILIO_AUTH_TOKEN and TwilioClient is not None:
        return send_sms_via_twilio(phone, message)

    raise NotImplementedError("No SMS provider configured (ryan or Twilio required)")


# ----------------- DB table creation (best-effort) -----------------

def _ensure_table():
    if not get_conn:
        return
    try:
        with get_conn() as conn:
            cur = conn.cursor()
            # try Postgres style first
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
                # try sqlite fallback
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


# ----------------- Routes -----------------

@otp_bp.route("/send-email", methods=["POST", "OPTIONS"])
def otp_send_email():
    # handle preflight
    if request.method == "OPTIONS":
        return make_response(jsonify({"ok": True}), 200)

    try:
        body_debug = request.get_json(silent=True)
    except Exception:
        body_debug = None
    print(f"[OTP] send-email called | method={request.method} path={request.path} data={body_debug}")

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

        # store hashed OTP
        if not get_conn:
            return _error_json("Database not configured", None, 500)

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
            return _error_json("Failed to store OTP", e, 500)

        # If in dev mode, return code (no external provider calls)
        if DEV_RETURN_OTP:
            print(f"[OTP][DEV] Email OTP for {email}: {code} (expires {expires_at})")
            resp = {"success": True, "message": "OTP stored (dev mode)", "code": code, "expires_at": expires_at}
            return jsonify(resp), 200

        # Otherwise attempt to send via provider
        subject = "Your verification code"
        body = f"Your verification code is {code}. It expires in {OTP_TTL_SECONDS // 60} minutes."
        try:
            ok = send_email(email, subject, body)
            if not ok:
                return _error_json("Email provider returned falsy", None, 500)
        except NotImplementedError as e:
            return _error_json("Email provider not configured", e, 500)
        except Exception as e:
            return _error_json("Failed to send email OTP", e, 500)

        resp = {"success": True, "message": "Email OTP sent"}
        return jsonify(resp), 200

    except Exception as e:
        traceback.print_exc()
        return _error_json("Server error while processing send-email", e, 500)


@otp_bp.route("/send-sms", methods=["POST", "OPTIONS"])
def otp_send_sms():
    # handle preflight
    if request.method == "OPTIONS":
        return make_response(jsonify({"ok": True}), 200)

    try:
        body_debug = request.get_json(silent=True)
    except Exception:
        body_debug = None
    print(f"[OTP] send-sms called | method={request.method} path={request.path} data={body_debug}")

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
            return _error_json("Database not configured", None, 500)

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
            return _error_json("Failed to store OTP", e, 500)

        if DEV_RETURN_OTP:
            print(f"[OTP][DEV] SMS OTP for {phone}: {code} (expires {expires_at})")
            resp = {"success": True, "message": "OTP stored (dev mode)", "code": code, "expires_at": expires_at}
            return jsonify(resp), 200

        msg = f"Your verification code is {code}. It expires in {OTP_TTL_SECONDS // 60} minutes."
        try:
            ok = send_sms(phone, msg)
            if not ok:
                return _error_json("SMS provider returned falsy", None, 500)
        except NotImplementedError as e:
            return _error_json("SMS provider not configured", e, 500)
        except Exception as e:
            return _error_json("Failed to send SMS OTP", e, 500)

        resp = {"success": True, "message": "SMS OTP sent"}
        return jsonify(resp), 200

    except Exception as e:
        traceback.print_exc()
        return _error_json("Server error while processing send-sms", e, 500)


@otp_bp.route("/verify", methods=["POST", "OPTIONS"])
def otp_verify():
    # handle preflight
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
            return _error_json("Database not configured", None, 500)

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
        traceback.print_exc()
        return _error_json("Server error while processing verify", e, 500)