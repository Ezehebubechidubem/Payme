from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
import sqlite3
from datetime import datetime, timedelta
import os
import random
import hashlib
import hmac

# ===== App Setup =====
app = Flask(__name__)
CORS(app, supports_credentials=True)

DATABASE_PATH = 'payme.db'

# ===== Database Helper =====
def get_conn():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                email TEXT UNIQUE,
                phone TEXT UNIQUE,
                password TEXT,
                account_number TEXT UNIQUE,
                balance REAL DEFAULT 0
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS transactions(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                type TEXT,
                amount REAL,
                created_at TEXT
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS otp_codes(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                contact TEXT,
                channel TEXT,
                code_hash TEXT,
                code_salt TEXT,
                reason TEXT,
                created_at TEXT,
                expires_at TEXT
            )
        """)
        conn.commit()
init_db()

# ===== Helpers =====
OTP_TTL_SECONDS = 300  # 5 min
DEV_RETURN_OTP = True

def _gen_code():
    return f"{random.randint(100000, 999999)}"

def hash_otp(code):
    salt = os.urandom(16).hex()
    hash_hex = hmac.new(salt.encode(), code.encode(), hashlib.sha256).hexdigest()
    return salt, hash_hex

def verify_otp(code, salt, hash_hex):
    return hmac.new(salt.encode(), code.encode(), hashlib.sha256).hexdigest() == hash_hex

def execute_with_params(cur, conn, query, params):
    cur.execute(query, params)

def _row_get(row, idx):
    return row[idx] if row else None

def _err_resp(msg, e=None, status=500):
    print(f"[ERROR] {msg}: {e}")
    return jsonify({"success": False, "message": msg, "error": str(e) if e else None, "status":"error"}), status

# ===== Registration Route =====
@app.route("/register", methods=["POST"])
def register():
    try:
        data = request.get_json() or {}
        username = (data.get("username") or "").strip()
        email = (data.get("email") or "").strip()
        phone = (data.get("phone") or "").strip()
        password = (data.get("password") or "").strip()

        if not username or not email or not phone or not password:
            return jsonify({"status":"error","message":"Missing fields"}), 400

        account_number = phone[-10:]  # simple mock
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute("INSERT INTO users (username,email,phone,password,account_number) VALUES (?, ?, ?, ?, ?)",
                        (username, email, phone, password, account_number))
            conn.commit()

        return jsonify({"status":"success","account_number":account_number}), 200
    except Exception as e:
        return _err_resp("Registration failed", e, 500)

# ===== OTP TEST PROVIDER =====
def send_email(to_email: str, subject: str, body: str) -> bool:
    print(f"[TEST MODE] send_email to {to_email}: {body}")
    return True

def send_sms(phone: str, message: str) -> bool:
    print(f"[TEST MODE] send_sms to {phone}: {message}")
    return True

# ===== OTP ROUTES =====
from flask import Blueprint
otp_bp = Blueprint('otp', __name__, url_prefix="/api/otp")

@otp_bp.route("/send-email", methods=["POST", "OPTIONS"])
def otp_send_email():
    if request.method == "OPTIONS":
        return make_response(jsonify({"ok": True}), 200)

    try:
        data = request.get_json() or {}
        email = (data.get("email") or data.get("contact") or "").strip()
        reason = (data.get("reason") or "registration").strip()
        if not email: return jsonify({"success":False,"message":"Missing email"}),400

        code = _gen_code()
        salt_hex, hash_hex = hash_otp(code)
        created_at = datetime.utcnow().isoformat()
        expires_at = (datetime.utcnow()+timedelta(seconds=OTP_TTL_SECONDS)).isoformat()

        with get_conn() as conn:
            cur = conn.cursor()
            execute_with_params(cur, conn,"DELETE FROM otp_codes WHERE contact=? AND channel=? AND reason=?",(email,"email",reason))
            execute_with_params(cur, conn,"INSERT INTO otp_codes (contact,channel,code_hash,code_salt,reason,created_at,expires_at) VALUES (?,?,?,?,?,?,?)",
                                (email,"email",hash_hex,salt_hex,reason,created_at,expires_at))
            conn.commit()

        ok = send_email(email,"Your OTP Code",f"Your OTP is {code}")
        if not ok: return _err_resp("Failed to send email OTP",None,500)

        resp={"success":True,"message":"Email OTP sent"}
        if DEV_RETURN_OTP: resp.update({"code":code,"expires_at":expires_at})
        return jsonify(resp),200
    except Exception as e:
        return _err_resp("Email OTP failed",e,500)

@otp_bp.route("/send-sms", methods=["POST", "OPTIONS"])
def otp_send_sms():
    if request.method=="OPTIONS": return make_response(jsonify({"ok": True}),200)
    try:
        data = request.get_json() or {}
        phone = (data.get("phone") or data.get("contact") or "").strip()
        reason = (data.get("reason") or "registration").strip()
        if not phone: return jsonify({"success":False,"message":"Missing phone"}),400

        code = _gen_code()
        salt_hex, hash_hex = hash_otp(code)
        created_at=datetime.utcnow().isoformat()
        expires_at=(datetime.utcnow()+timedelta(seconds=OTP_TTL_SECONDS)).isoformat()

        with get_conn() as conn:
            cur = conn.cursor()
            execute_with_params(cur,conn,"DELETE FROM otp_codes WHERE contact=? AND channel=? AND reason=?",(phone,"sms",reason))
            execute_with_params(cur,conn,"INSERT INTO otp_codes (contact,channel,code_hash,code_salt,reason,created_at,expires_at) VALUES (?,?,?,?,?,?,?)",
                                (phone,"sms",hash_hex,salt_hex,reason,created_at,expires_at))
            conn.commit()

        ok=send_sms(phone,f"Your OTP is {code}")
        if not ok: return _err_resp("Failed to send SMS OTP",None,500)

        resp={"success":True,"message":"SMS OTP sent"}
        if DEV_RETURN_OTP: resp.update({"code":code,"expires_at":expires_at})
        return jsonify(resp),200
    except Exception as e:
        return _err_resp("SMS OTP failed",e,500)

@otp_bp.route("/verify",methods=["POST","OPTIONS"])
def otp_verify():
    if request.method=="OPTIONS": return make_response(jsonify({"ok":True}),200)
    try:
        data=request.get_json() or {}
        contact=(data.get("contact") or data.get("email") or data.get("phone") or "").strip()
        channel=(data.get("channel") or ("sms" if data.get("phone") else "email")).strip()
        code=(data.get("code") or "").strip()
        reason=(data.get("reason") or "registration").strip()

        if not contact or not code: return jsonify({"success":False,"message":"Missing contact or code"}),400
        if channel not in ("email","sms"): return jsonify({"success":False,"message":"Invalid channel"}),400

        with get_conn() as conn:
            cur=conn.cursor()
            execute_with_params(cur,conn,
                                "SELECT id, code_hash, code_salt, expires_at FROM otp_codes WHERE contact=? AND channel=? AND reason=? ORDER BY id DESC LIMIT 1",
                                (contact,channel,reason))
            row=cur.fetchone()
            if not row: return jsonify({"success":False,"message":"OTP not found"}),404

            otp_id,stored_hash,stored_salt,expires_at=row
            exp_dt=datetime.fromisoformat(expires_at) if isinstance(expires_at,str) else expires_at
            if exp_dt < datetime.utcnow():
                execute_with_params(cur,conn,"DELETE FROM otp_codes WHERE id=?",(otp_id,))
                conn.commit()
                return jsonify({"success":False,"message":"OTP expired"}),400

            if not verify_otp(code,stored_salt,stored_hash):
                return jsonify({"success":False,"message":"Invalid OTP"}),401

            execute_with_params(cur,conn,"DELETE FROM otp_codes WHERE id=?",(otp_id,))
            conn.commit()
            return jsonify({"success":True,"message":"OTP verified"}),200
    except Exception as e:
        return _err_resp("OTP verification failed",e,500)

# ===== Register OTP Blueprint =====
app.register_blueprint(otp_bp)

# ===== Run =====
if __name__=="__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)