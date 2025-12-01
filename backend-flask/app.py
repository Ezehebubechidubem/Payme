# app.py - full PayMe backend consolidated
import os
import sys
import traceback
import sqlite3
import requests
import math
import time
import uuid
from datetime import datetime, timedelta

from flask import Flask, request, jsonify, make_response, session
from flask_cors import CORS


# optional postgres support
try:
    DATABASE_URL = os.environ.get("DATABASE_URL")
except Exception:
    DATABASE_URL = None

# security helpers
from werkzeug.security import generate_password_hash, check_password_hash

# Helper: safe now iso
def _now_iso():
    return datetime.now().isoformat()

# -------------------------------------------------
# Create single Flask app and configure CORS
# -------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")
# ---------- staff access guard ----------

# ✅ Proper CORS setup for session cookies
frontend_origin = os.environ.get("CORS_ORIGINS", "https://ezehebubechidubem.github.io")
CORS(app, resources={r"/*": {"origins": frontend_origin}}, supports_credentials=True)

# ✅ Correct cookie settings
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "None"
app.config["SESSION_COOKIE_SECURE"] = True  # keep True on Render (uses HTTPS)


# Now import & register pin blueprint (import below so `app` already exists)
try:
    from pin_routes import bp as pin_bp
    app.register_blueprint(pin_bp)
    print("pin_routes blueprint registered")
except Exception as e:
    # log error but allow app to start (useful when debugging)
    print("Failed to register pin_routes:", e)

# --- Betting Blueprint Import ---
try:
    from betting import betting_bp
    app.register_blueprint(betting_bp, url_prefix="/api")
    print("betting blueprint registered")
except Exception as e:
    print("Failed to register betting blueprint:", e)



# -------------------------------------------------
# DB helpers and compatibility for sqlite3 / psycopg2
# -------------------------------------------------
DB = os.environ.get("SQLITE_DB_PATH", "payme.db")

# Try import psycopg2 only if DATABASE_URL provided
psycopg2 = None
psycopg2_extras = None
if DATABASE_URL:
    try:
        import psycopg2
        import psycopg2.extras
        psycopg2_extras = psycopg2.extras
    except Exception:
        psycopg2 = None
        psycopg2_extras = None

class PGCursorWrapper:
    def __init__(self, cur):
        self._cur = cur

    def execute(self, sql, params=None):
        if params is None:
            return self._cur.execute(sql)
        safe_sql = sql.replace("?", "%s")
        return self._cur.execute(safe_sql, params)

    def executemany(self, sql, seq_of_params):
        safe_sql = sql.replace("?", "%s")
        return self._cur.executemany(safe_sql, seq_of_params)

    def fetchone(self):
        return self._cur.fetchone()

    def fetchall(self):
        return self._cur.fetchall()

    def __getattr__(self, name):
        return getattr(self._cur, name)

class PGConnectionContext:
    def __init__(self, dsn):
        self.dsn = dsn
        self.conn = None

    def __enter__(self):
        if psycopg2 is None:
            raise RuntimeError("psycopg2 not installed; cannot use PostgreSQL. Install psycopg2-binary.")
        self.conn = psycopg2.connect(self.dsn)
        self.conn.autocommit = False
        return self

    def cursor(self):
        raw_cur = self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        return PGCursorWrapper(raw_cur)

    def commit(self):
        if self.conn:
            self.conn.commit()

    def rollback(self):
        if self.conn:
            self.conn.rollback()

    def close(self):
        if self.conn:
            try:
                self.conn.close()
            except:
                pass

    def __exit__(self, exc_type, exc, tb):
        if exc_type:
            try:
                self.conn.rollback()
            except:
                pass
        else:
            try:
                self.conn.commit()
            except:
                pass
        try:
            self.conn.close()
        except:
            pass

def get_conn():
    if DATABASE_URL:
        return PGConnectionContext(DATABASE_URL)
    else:
        conn = sqlite3.connect(DB, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        with conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
        return conn

def init_db():
    if DATABASE_URL:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users(
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE,
                    phone TEXT UNIQUE,
                    password TEXT,
                    account_number TEXT UNIQUE,
                    balance NUMERIC DEFAULT 0
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS transactions(
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER,
                    type TEXT,
                    amount NUMERIC,
                    other_party TEXT,
                    date TEXT,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS savings(
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER,
                    amount NUMERIC,
                    type TEXT CHECK(type IN ('flexible','fixed')),
                    start_date TEXT,
                    duration_days INTEGER,
                    end_date TEXT,
                    status TEXT DEFAULT 'active',
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
            """)
    else:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
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
                    other_party TEXT,
                    date TEXT,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS savings(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    amount REAL,
                    type TEXT CHECK(type IN ('flexible','fixed')),
                    start_date TEXT,
                    duration_days INTEGER,
                    end_date TEXT,
                    status TEXT DEFAULT 'active',
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
            """)

def init_db():
    if DATABASE_URL:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute("""
            CREATE TABLE IF NOT EXISTS staff (
                id UUID PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                role TEXT NOT NULL,
                password TEXT NOT NULL,
                created_at TIMESTAMP
            )
            """)
            conn.commit()
    else:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute("""
            CREATE TABLE IF NOT EXISTS staff (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                role TEXT NOT NULL,
                password TEXT NOT NULL,
                created_at TEXT
            )
            """)
            conn.commit()

# -------------------------------------------------
# Utilities
# -------------------------------------------------
def json_required(keys):
    if not request.is_json:
        return None, jsonify({"status": "error", "message": "Content-Type must be application/json"}), 400
    data = request.get_json(silent=True) or {}
    missing = [k for k in keys if data.get(k) in (None, "")]
    if missing:
        return None, jsonify({"status": "error", "message": f"Missing fields: {', '.join(missing)}"}), 400
    return data, None, None

def _now_iso():
    return datetime.now().isoformat()

# -------------------------------------------------
# Logging + error handling + security headers
# -------------------------------------------------
@app.before_request
def _log_request():
    print(f"> {request.method} {request.path}", file=sys.stdout, flush=True)

@app.errorhandler(Exception)
def _handle_exception(e):
    traceback.print_exc()
    return jsonify({"status": "error", "message": str(e)}), 500

@app.after_request
def _security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-XSS-Protection"] = "1; mode=block"
    return resp

@app.route("/", methods=["OPTIONS"])
@app.route("/<path:_any>", methods=["OPTIONS"])
def options(_any=None):
    return make_response(("", 204))

# -------------------------------------------------
# Health
# -------------------------------------------------
@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "✅ PayMe backend is running"}), 200

# -------------------------------------------------
# Auth & User
# -------------------------------------------------
@app.route("/register", methods=["POST"])
def register():
    data, err, code = json_required(["username", "phone", "password"])
    if err:
        return err, code

    username = data["username"].strip()
    phone = data["phone"].strip()
    password = data["password"]

    if not phone.isdigit() or len(phone) != 11:
        return jsonify({"status": "error", "message": "Phone must be exactly 11 digits"}), 400

    account_number = phone[-10:]
    hashed_pw = generate_password_hash(password)

    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO users (username, phone, password, account_number, balance) VALUES (?, ?, ?, ?, ?)",
                (username, phone, hashed_pw, account_number, 0.0),
            )
        return jsonify({"status": "success", "account_number": account_number}), 200
    except Exception as ie:
        msg = "User already exists"
        if "username" in str(ie).lower():
            msg = "Username already exists"
        elif "phone" in str(ie).lower():
            msg = "Phone already exists"
        return jsonify({"status": "error", "message": msg}), 400



@app.route("/login", methods=["POST"])
def login():
    data, err, code = json_required(["login", "password"])
    if err:
        return err, code

    login_value = (data.get("login") or "").strip()
    password = data.get("password", "")
    payload_email = (data.get("email") or "").strip() or None

    # -------------------------
    # ADMIN: environment-driven (UNCHANGED)
    # -------------------------
    ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH")
    if login_value == ADMIN_USERNAME or (payload_email and payload_email == ADMIN_USERNAME):
        if ADMIN_PASSWORD_HASH and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session["is_admin"] = True
            session["admin_name"] = ADMIN_USERNAME
            return jsonify({"status":"success","role":"admin","admin_name":ADMIN_USERNAME,"user":None}), 200
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401

    # -------------------------
    # STAFF: database-driven (UPDATED)
    # -------------------------
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, name, email, role, password "
            "FROM staff WHERE email = ? LIMIT 1",
            (login_value,)
        )
        staff_row = cur.fetchone()

    if staff_row:
        try:
            stored_pw = staff_row["password"]
            staff_id = staff_row["id"]
            staff_name = staff_row["name"]
            staff_role = staff_row["role"]
            staff_email = staff_row["email"]
        except Exception:
            # fallback for tuple-like rows
            stored_pw = staff_row[4] if len(staff_row) > 4 else None
            staff_id = staff_row[0] if len(staff_row) > 0 else None
            staff_name = staff_row[1] if len(staff_row) > 1 else None
            staff_role = staff_row[3] if len(staff_row) > 3 else None
            staff_email = staff_row[2] if len(staff_row) > 2 else None

        if stored_pw and check_password_hash(stored_pw, password):
            # set session (keeps existing behavior)
            session["is_staff"] = True
            session["staff_id"] = staff_id
            session["staff_name"] = staff_name
            # normalized role (lowercase) — used by auth_check and for any server-side checks
            normalized_role = (staff_role or "").strip().lower()
            session["staff_role"] = normalized_role

            # --------------- role -> full GitHub Pages URL ---------------
            BASE = "https://ezehebubechidubem.github.io/Payme"
            ROLE_ROUTES = {
                "customer-support": f"{BASE}/Admin/scaling.html",
                "customer support": f"{BASE}/Admin/scaling.html",
                "transaction-review": f"{BASE}/Admin/review.html",
                "transaction review": f"{BASE}/Admin/review.html",
                "scaling": f"{BASE}/Admin/scaling.html",
                "api manager": f"{BASE}/Admin/api_manager.html",
                "api-manager": f"{BASE}/Admin/api_manager.html",
                "developer": f"{BASE}/Admin/developer.html",
                "kyc": f"{BASE}/Admin/kyc.html",
                "fraud": f"{BASE}/Admin/fraud.html",
                "log": f"{BASE}/Admin/log.html",
                "notification": f"{BASE}/Admin/notifications.html"
            }

            redirect_to = ROLE_ROUTES.get(normalized_role, f"{BASE}/Admin/staff.html")

            return jsonify({
                "status": "success",
                "role": "staff",
                "user": {
                    "id": staff_id,
                    "name": staff_name,
                    "email": staff_email,
                    "role": staff_role
                },
                "redirect": redirect_to
            }), 200

        return jsonify({"status": "error", "message": "Invalid credentials"}), 401

    # -------------------------
    # REGULAR USER: database (UNCHANGED)
    # -------------------------
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, username, phone, password, account_number, balance "
            "FROM users WHERE username = ? OR phone = ? LIMIT 1",
            (login_value, login_value),
        )
        row = cur.fetchone()

    if not row:
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401

    try:
        stored_pw = row["password"]
        user_id = int(row["id"])
        username = row["username"]
        phone = row["phone"]
        account_number = row["account_number"]
        balance = row["balance"]
    except Exception:
        # fallback for tuple-like rows
        stored_pw = row[3] if len(row) > 3 else None
        user_id = int(row[0]) if len(row) > 0 else None
        username = row[1] if len(row) > 1 else None
        phone = row[2] if len(row) > 2 else None
        account_number = row[4] if len(row) > 4 else None
        balance = row[5] if len(row) > 5 else 0

    if not stored_pw or not check_password_hash(stored_pw, password):
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401

    # Set session for regular user
    session['user_id'] = user_id

    user = {
        "id": user_id,
        "username": username,
        "phone": phone,
        "account_number": account_number,
        "balance": balance,
    }

    return jsonify({"status":"success","role":"user","user":user}), 200


# ---------- small endpoint used by GitHub-hosted Admin pages to validate session ----------
@app.route("/auth/check", methods=["GET", "OPTIONS"])
def auth_check():
    if request.method == "OPTIONS":
        return "", 204
    # return role only if staff logged-in
    if session.get("is_staff"):
        return jsonify({"status": "ok", "role": session.get("staff_role")}), 200
    # allow admin detection if desired
    if session.get("is_admin"):
        return jsonify({"status": "ok", "role": "admin"}), 200
    return jsonify({"status": "error", "message": "unauthorized"}), 401

# -------------------------------------------------
# Money: balance, add, send, transactions, users
# -------------------------------------------------
@app.route("/balance/<phone>", methods=["GET"])
def balance(phone: str):
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT balance FROM users WHERE phone = ?", (phone,))
        row = cur.fetchone()
    return jsonify({"balance": (row["balance"] if row else 0.0)}), 200

@app.route("/add_money", methods=["POST"])
def add_money():
    data, err, code = json_required(["phone", "amount"])
    if err:
        return err, code

    phone = str(data["phone"]).strip()
    try:
        amount = float(data["amount"])
    except Exception:
        return jsonify({"status": "error", "message": "amount must be a number"}), 400

    if amount <= 0:
        return jsonify({"status": "error", "message": "Amount must be > 0"}), 400

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE phone = ?", (phone,))
        row = cur.fetchone()
        if not row:
            return jsonify({"status": "error", "message": "User not found"}), 404

        user_id = row["id"]
        cur.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, user_id))
        cur.execute(
            "INSERT INTO transactions (user_id, type, amount, other_party, date) VALUES (?, ?, ?, ?, ?)",
            (user_id, "Deposit", amount, "Self", datetime.now().isoformat()),
        )

    return jsonify({"status": "success", "message": f"₦{amount} added"}), 200

@app.route("/send_money", methods=["POST"])
def send_money():
    data, err, code = json_required(["sender_phone", "receiver_acc", "amount"])
    if err:
        return err, code

    sender_phone = str(data["sender_phone"]).strip()
    receiver_acc = str(data["receiver_acc"]).strip()
    try:
        amount = float(data["amount"])
    except Exception:
        return jsonify({"status": "error", "message": "amount must be number"}), 400

    if amount <= 0:
        return jsonify({"status": "error", "message": "Amount must be > 0"}), 400
    if not receiver_acc.isdigit() or len(receiver_acc) != 10:
        return jsonify({"status": "error", "message": "receiver_acc must be 10 digits"}), 400

    with get_conn() as conn:
        cur = conn.cursor()

        # Get sender
        cur.execute("SELECT id, balance FROM users WHERE phone = ?", (sender_phone,))
        sender_row = cur.fetchone()
        if not sender_row or sender_row["balance"] < amount:
            return jsonify({"status": "error", "message": "Insufficient funds"}), 400

        sender_id = sender_row["id"]
        # Deduct sender
        cur.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, sender_id))
        cur.execute(
            "INSERT INTO transactions (user_id, type, amount, other_party, date) VALUES (?, ?, ?, ?, ?)",
            (sender_id, "Transfer Out", amount, receiver_acc, datetime.now().isoformat()),
        )

        # Credit receiver (if exists)
        cur.execute("SELECT id FROM users WHERE account_number = ?", (receiver_acc,))
        recv = cur.fetchone()
        if recv:
            recv_id = recv["id"]
            cur.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, recv_id))
            cur.execute(
                "INSERT INTO transactions (user_id, type, amount, other_party, date) VALUES (?, ?, ?, ?, ?)",
                (recv_id, "Transfer In", amount, sender_phone, datetime.now().isoformat()),
            )

    return jsonify({"status": "success", "message": f"₦{amount} sent"}), 200

@app.route("/transactions/<phone>", methods=["GET"])
def transactions(phone: str):
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT type, amount, other_party, date FROM transactions "
            "WHERE user_id = (SELECT id FROM users WHERE phone = ?) ORDER BY id DESC",
            (phone,),
        )
        rows = cur.fetchall()
    result = [
        {"type": r["type"], "amount": r["amount"], "other_party": r["other_party"], "date": r["date"]}
        for r in rows
    ]
    return jsonify(result), 200

@app.route("/user_by_account/<account_number>", methods=["GET"])
def user_by_account(account_number: str):
    if not account_number.isdigit() or len(account_number) != 10:
        return jsonify({"status": "error", "message": "Invalid account number"}), 400

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT username, phone FROM users WHERE account_number = ?", (account_number,))
        row = cur.fetchone()

    if not row:
        return jsonify({"status": "error", "message": "Account not found"}), 404

    return jsonify({
        "status": "success",
        "username": row["username"],
        "phone": row["phone"]
    }), 200

@app.route("/user/<phone>", methods=["GET"])
def get_user(phone: str):
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT username, phone, account_number, balance FROM users WHERE phone = ?", (phone,))
        row = cur.fetchone()
    if not row:
        return jsonify({"status": "error", "message": "User not found"}), 404
    return jsonify({"status": "success", "user": dict(row)}), 200

@app.route("/update_user", methods=["POST"])
def update_user():
    data, err, code = json_required(["phone"])
    if err:
        return err, code

    phone = str(data["phone"]).strip()
    new_phone = str(data.get("new_phone", "")).strip()
    new_password = str(data.get("new_password", "")).strip()

    if new_phone and (not new_phone.isdigit() or len(new_phone) != 11):
        return jsonify({"status": "error", "message": "New phone must be 11 digits"}), 400

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE phone = ?", (phone,))
        user = cur.fetchone()
        if not user:
            return jsonify({"status": "error", "message": "User not found"}), 404

        if new_phone:
            cur.execute("UPDATE users SET phone = ?, account_number = ? WHERE id = ?", 
                        (new_phone, new_phone[-10:], user["id"]))
        if new_password:
            cur.execute("UPDATE users SET password = ? WHERE id = ?", (generate_password_hash(new_password), user["id"]))

        cur.execute("SELECT username, phone, account_number, balance FROM users WHERE id = ?", (user["id"],))
        updated = dict(cur.fetchone())

    return jsonify({"status": "success", "user": updated}), 200
# --- Admin metrics ---
@app.route("/admin/metrics", methods=["GET"])
def admin_metrics():
    try:
        with get_conn() as conn:
            cur = conn.cursor()

            # Total deposits
            cur.execute("SELECT COALESCE(SUM(amount),0) as deposits FROM transactions WHERE type='Deposit'")
            deposits = cur.fetchone()["deposits"]

            # Total withdrawals
            cur.execute("SELECT COALESCE(SUM(amount),0) as withdrawals FROM transactions WHERE type='Transfer Out'")
            withdrawals = cur.fetchone()["withdrawals"]

            # Total volume
            total_volume = deposits + withdrawals

            # Active users (users with at least 1 transaction)
            cur.execute("SELECT COUNT(DISTINCT user_id) as active_users FROM transactions")
            active_users = cur.fetchone()["active_users"]

    except Exception as e:
        return jsonify({"status":"error","message":str(e)}), 500

    return jsonify({
        "status":"success",
        "deposits": deposits,
        "withdrawals": withdrawals,
        "total_volume": total_volume,
        "active_users": active_users
    }), 200


# --- Admin recent transactions ---
@app.route("/admin/recent_tx", methods=["GET"])
def admin_recent_tx():
    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT id, type, amount, other_party, date 
                FROM transactions ORDER BY id DESC LIMIT 10
            """)
            rows = cur.fetchall()

            result = [
                {
                    "id": r["id"],
                    "type": r["type"],
                    "amount": float(r["amount"]),
                    "other_party": r["other_party"],
                    "date": r["date"]
                } for r in rows
            ]
    except Exception as e:
        return jsonify({"status":"error","message":str(e)}), 500

    return jsonify(result), 200
# -------------------------------------------------
# Flutterwave / Banks / Resolve (global)
# -------------------------------------------------
@app.route("/banks", methods=["GET"])
def get_banks():
    try:
        flw_key = os.environ.get("FLW_SECRET_KEY")
        if not flw_key:
            return jsonify({
                "status": "error",
                "message": "FLW_SECRET_KEY not configured on server. Set FLW_SECRET_KEY to fetch Flutterwave banks."
            }), 400

        url = "https://api.flutterwave.com/v3/banks/NG"
        headers = {"Authorization": f"Bearer {flw_key}", "User-Agent": "PayMe/1.0"}
        resp = requests.get(url, headers=headers, timeout=10)

        if resp.status_code != 200:
            try:
                body_json = resp.json()
            except Exception:
                body_json = resp.text or ""
            return jsonify({
                "status": "error",
                "message": "Flutterwave returned non-200 for /banks",
                "fw_status": resp.status_code,
                "fw_response": body_json
            }), resp.status_code

        data = resp.json()
        banks = {}
        for item in data.get("data", []):
            code = str(item.get("code") or "").strip()
            name = (item.get("name") or "").strip()
            if code and name:
                banks[code] = name

        return jsonify({"status": "success", "message": "Banks fetched from Flutterwave", "banks": banks}), 200

    except requests.exceptions.RequestException as e:
        return jsonify({
            "status": "error",
            "message": "Network error when contacting Flutterwave /banks",
            "details": str(e)
        }), 502
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": "Internal error while fetching banks from Flutterwave",
            "details": str(e)
        }), 500

@app.route("/resolve-account", methods=["POST"])
def resolve_account():
    try:
        data = request.get_json(silent=True) or {}
        account_number = str(data.get("account_number", "")).strip()
        bank_code = data.get("bank_code", "")

        if not account_number.isdigit() or len(account_number) != 10:
            return jsonify({"status": "error", "message": "Invalid account number"}), 400

        def try_parse_json(resp):
            try:
                return resp.json(), None
            except ValueError:
                text = resp.text or ""
                return None, text[:3000]

                flw_key = os.environ.get("FLW_SECRET_KEY")
        if not flw_key:
            return jsonify({"status": "error", "message": "FLW_SECRET_KEY not configured on server"}), 500

        account_bank = None
        mapping_error = None
        try:
            bank_code_raw = "" if bank_code is None else str(bank_code)
            bank_code_clean = ''.join(ch for ch in bank_code_raw if ch.isdigit()).strip()
            try:
                account_bank, mapping_error = find_flutter_code(bank_code_raw)
                if isinstance(account_bank, (int, float)):
                    account_bank = str(account_bank)
                if account_bank:
                    account_bank = ''.join(ch for ch in str(account_bank) if ch.isdigit())
            except NameError:
                account_bank = bank_code_clean if bank_code_clean else None
                if not account_bank:
                    mapping_error = "No helper available and bank_code not numeric"
            except Exception as e:
                account_bank = None
                mapping_error = f"Helper error: {str(e)}"

            if account_bank and not (3 <= len(account_bank) <= 6):
                mapping_error = f"bank_code numeric but invalid length ({len(account_bank)})"
                account_bank = None

        except Exception as e:
            account_bank = None
            mapping_error = f"Normalization error: {str(e)}"

        if not account_bank and "test" in flw_key.lower():
            account_bank = "044"
            mapping_error = None

        try:
            print("🧾 resolve-account inputs -> account_number:", account_number,
                  "bank_code_raw:", repr(bank_code), "bank_code_clean:", account_bank, flush=True)
        except Exception:
            pass

        if not account_bank:
            return jsonify({
                "status": "error",
                "message": "Could not determine Flutterwave numeric bank code",
                "details": mapping_error
            }), 400

        try:
            flw_url = "https://api.flutterwave.com/v3/accounts/resolve"
            payload = {"account_number": account_number, "account_bank": account_bank}
            headers = {
                "Authorization": f"Bearer {flw_key}",
                "Content-Type": "application/json",
                "User-Agent": "PayMe/1.0"
            }

            flw_res = requests.post(flw_url, headers=headers, json=payload, timeout=12)
            flw_status = flw_res.status_code
            flw_json, flw_preview = try_parse_json(flw_res)

            print("Flutterwave resolve status:", flw_status, flush=True)
            print("Flutterwave resolve preview:", (flw_res.text or "")[:1200], flush=True)

            if flw_json and (flw_json.get("status") == "success" or str(flw_status).startswith("2")):
                acct_name = None
                if isinstance(flw_json.get("data"), dict):
                    acct_name = flw_json["data"].get("account_name") or flw_json["data"].get("accountName") or flw_json["data"].get("accountname")
                if not acct_name:
                    acct_name = flw_json.get("account_name") or (flw_json.get("data") or {}).get("account_name")

                if acct_name:
                    return jsonify({
                        "status": "success",
                        "provider": "flutterwave",
                        "account_name": acct_name,
                        "account_number": account_number,
                        "bank_code": account_bank,
                        "raw": flw_json
                    }), 200

                return jsonify({
                    "status": "error",
                    "provider": "flutterwave",
                    "message": "Flutterwave returned success but no account_name",
                    "raw": flw_json
                }), 400

            if flw_json:
                msg = flw_json.get("message") or flw_json.get("error") or "Flutterwave unresolved"
            else:
                msg = "Flutterwave did not return valid JSON"
            helper_unavail_texts = [
                "No helper available",
                "bank_code not numeric",
                "Could not determine Flutterwave numeric bank code",
                "No route to resolve"
            ]
            helper_issue = False
            if isinstance(msg, str):
                for token in helper_unavail_texts:
                    if token.lower() in msg.lower():
                        helper_issue = True
                        break

            if helper_issue:
                return jsonify({
                    "status": "warning",
                    "provider": "flutterwave",
                    "message": "Name lookup not available for this bank via Flutterwave. Proceed with caution.",
                    "can_proceed": True,
                    "bank_code": account_bank,
                    "raw": flw_json if flw_json is not None else flw_preview
                }), 200

            return jsonify({
                "status": "error",
                "provider": "flutterwave",
                "message": msg,
                "raw": flw_json if flw_json is not None else flw_preview
            }), flw_status if isinstance(flw_status, int) and flw_status >= 400 else 400

        except requests.exceptions.RequestException as e:
            print("Flutterwave request exception:", str(e), flush=True)
            return jsonify({"status": "error", "message": f"Network error contacting Flutterwave: {str(e)}"}), 502

    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": f"Internal error: {str(e)}"}), 500

# -------------------------------------------------
# Savings
# -------------------------------------------------
INTEREST_RATE = 0.20  # 20% annual simple interest

def _calc_interest(amount: float, days: int) -> float:
    if days <= 0:
        return 0.0
    return amount * INTEREST_RATE * (days / 365.0)

def _sweep_matured_savings_for_user(conn, user_id: int):
    cur = conn.cursor()
    now = datetime.now()

    if DATABASE_URL:
        sql = """
            SELECT id, amount, type, start_date, duration_days, end_date
            FROM savings
            WHERE user_id = ? AND status = 'active' AND CAST(end_date AS timestamp) <= ?
        """
    else:
        sql = """
            SELECT id, amount, type, start_date, duration_days, end_date
            FROM savings
            WHERE user_id = ? AND status = 'active' AND datetime(end_date) <= ?
        """

    cur.execute(sql, (user_id, now.isoformat()))
    matured = cur.fetchall()

    for s in matured:
        amount = float(s["amount"])
        duration_days = int(s["duration_days"])
        interest = _calc_interest(amount, duration_days)
        payout = amount + interest

        cur.execute("UPDATE savings SET status = 'withdrawn' WHERE id = ?", (s["id"],))
        cur.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (payout, user_id))
        cur.execute(
            "INSERT INTO transactions (user_id, type, amount, other_party, date) VALUES (?, ?, ?, ?, ?)",
            (user_id, "Savings Maturity", payout, "System", datetime.now().isoformat()),
        )

    return len(matured)

@app.route("/savings/create", methods=["POST"])
def savings_create():
    data = request.get_json() or {}
    user_id = data.get("user_id")
    phone = data.get("phone")
    amount = data.get("amount")
    savings_type = str(data.get("savings_type", "")).strip().lower()
    duration_days = int(data.get("duration_days", 0))

    if not (user_id or phone):
        return jsonify({"status": "error", "message": "user_id or phone required"}), 400
    try:
        if not amount or float(amount) <= 0:
            return jsonify({"status": "error", "message": "Amount must be > 0"}), 400
    except Exception:
        return jsonify({"status": "error", "message": "Invalid amount"}), 400
    if savings_type not in ("flexible", "fixed"):
        return jsonify({"status": "error", "message": "savings_type must be 'flexible' or 'fixed'"}), 400
    if duration_days <= 0:
        return jsonify({"status": "error", "message": "duration_days must be > 0"}), 400

    with get_conn() as conn:
        cur = conn.cursor()
        if user_id:
            cur.execute("SELECT id, balance FROM users WHERE id = ?", (user_id,))
        else:
            cur.execute("SELECT id, balance FROM users WHERE phone = ?", (phone,))
        row = cur.fetchone()
        if not row:
            return jsonify({"status": "error", "message": "User not found"}), 404

        user_id = row["id"]
        balance = float(row["balance"])
        if balance < float(amount):
            return jsonify({"status": "error", "message": "Insufficient balance"}), 400

        start = datetime.now()
        end = start + timedelta(days=duration_days)

        cur.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, user_id))
        cur.execute(
            """
            INSERT INTO savings (user_id, amount, type, start_date, duration_days, end_date, status)
            VALUES (?, ?, ?, ?, ?, ?, 'active')
            """,
            (user_id, amount, savings_type, start.isoformat(), duration_days, end.isoformat()),
        )
        cur.execute(
            "INSERT INTO transactions (user_id, type, amount, other_party, date) VALUES (?, ?, ?, ?, ?)",
            (user_id, "Savings Start", amount, savings_type, datetime.now().isoformat()),
        )

    return jsonify({"status": "success", "message": f"₦{amount} saved for {duration_days} days"}), 200

@app.route("/savings/list/<int:user_id>", methods=["GET"])
def savings_list(user_id: int):
    with get_conn() as conn:
        _sweep_matured_savings_for_user(conn, user_id)

        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, amount, type, start_date, duration_days, end_date, status
            FROM savings
            WHERE user_id = ?
            ORDER BY id DESC
            """,
            (user_id,),
        )
        rows = cur.fetchall()

    savings = []
    now = datetime.now()

    for r in rows:
        savings.append({
            "id": r["id"],
            "amount": r["amount"],
            "savings_type": r["type"],
            "start_date": r["start_date"],
            "end_date": r["end_date"],
            "duration_days": r["duration_days"],
            "status": r["status"],
            "can_withdraw": (
                r["status"] == "active" and (
                    r["type"] == "flexible" or 
                    (r["type"] == "fixed" and datetime.fromisoformat(r["end_date"]) <= now)
                )
            )
        })

    return jsonify({"status": "success", "savings": savings}), 200
@app.route("/savings/withdraw", methods=["POST"])
def savings_withdraw():
    data, err, code = json_required(["user_id", "savings_id"])
    if err:
        return err, code

    try:
        user_id = int(data["user_id"])
        savings_id = int(data["savings_id"])
    except Exception:
        return jsonify({"status": "error", "message": "Invalid payload"}), 400

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, amount, type, start_date, duration_days, end_date, status "
            "FROM savings WHERE id = ? AND user_id = ?",
            (savings_id, user_id),
        )
        s = cur.fetchone()

        if not s:
            return jsonify({"status": "error", "message": "Savings not found"}), 404
        if s["status"] != "active":
            return jsonify({"status": "error", "message": "Already withdrawn"}), 400

        amount = float(s["amount"])
        start = datetime.fromisoformat(s["start_date"])
        end = datetime.fromisoformat(s["end_date"])
        now = datetime.now()
        payout = amount

        if s["type"] == "flexible":
            if now >= end:
                interest = _calc_interest(amount, s["duration_days"])
                payout += interest
        elif s["type"] == "fixed":
            if now < end:
                return jsonify({"status": "error", "message": "Fixed savings cannot be withdrawn before maturity"}), 400
            interest = _calc_interest(amount, s["duration_days"])
            payout += interest
        else:
            return jsonify({"status": "error", "message": "Invalid savings type"}), 400

        cur.execute("UPDATE savings SET status = 'withdrawn' WHERE id = ?", (s["id"],))
        cur.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (payout, user_id))
        cur.execute(
            "INSERT INTO transactions (user_id, type, amount, other_party, date) VALUES (?, ?, ?, ?, ?)",
            (user_id, "Savings Withdraw", payout, s["type"], datetime.now().isoformat()),
        )

    return jsonify({"status": "success", "message": f"₦{payout} credited to main balance"}), 200

# -------------------------------------------------
# Airtime
# -------------------------------------------------
@app.route("/buy_airtime", methods=["POST"])
def buy_airtime():
    data, err, code = json_required(["phone", "network", "amount", "recipient"])
    if err:
        return err, code

    phone = str(data["phone"]).strip()
    network = str(data["network"]).strip()
    recipient = str(data["recipient"]).strip()
    try:
        amount = float(data["amount"])
    except Exception:
        return jsonify({"status": "error", "message": "amount must be a number"}), 400

    if amount <= 0:
        return jsonify({"status": "error", "message": "Amount must be > 0"}), 400

    fee = int(math.ceil(amount * 0.01))
    total = float(amount + fee)
    now_iso = datetime.now().isoformat()

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, balance FROM users WHERE phone = ?", (phone,))
        user = cur.fetchone()
        if not user:
            return jsonify({"status": "error", "message": "User not found"}), 404

        user_id = user["id"]
        balance = float(user["balance"])
        if balance < total:
            return jsonify({"status": "error", "message": "Insufficient balance", "balance": balance}), 400

        cur.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (total, user_id))
        other_party = f"airtime|network:{network}|to:{recipient}|fee:{fee}|value:{amount}"

        if DATABASE_URL:
            cur.execute(
                "INSERT INTO transactions (user_id, type, amount, other_party, date) VALUES (?, ?, ?, ?, ?) RETURNING id",
                (user_id, "Airtime", total, other_party, now_iso),
            )
            row = cur.fetchone()
            txn_id = row["id"] if row and "id" in row else None
        else:
            cur.execute(
                "INSERT INTO transactions (user_id, type, amount, other_party, date) VALUES (?, ?, ?, ?, ?)",
                (user_id, "Airtime", total, other_party, now_iso),
            )
            txn_id = cur.lastrowid

        cur.execute("SELECT balance FROM users WHERE id = ?", (user_id,))
        newbal = cur.fetchone()
        new_balance = float(newbal["balance"]) if newbal else None

    txn = {
        "id": txn_id,
        "type": "Airtime",
        "network": network,
        "recipient": recipient,
        "amount": amount,
        "fee": fee,
        "total": total,
        "date": now_iso,
        "status": "success",
    }

    return jsonify({"status": "success", "message": "Airtime purchased", "balance": new_balance, "transaction": txn}), 200

# -------------------------------------------------
# ----------------- BEGIN: towallet endpoints -----------------
# -------------------------------------------------
@app.route("/towallet/balance/<phone>", methods=["GET"])
def towallet_balance(phone):
    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT balance FROM users WHERE phone = ?", (phone,))
            row = cur.fetchone()
        bal = float(row["balance"]) if row else 0.0
        return jsonify({"status":"success","balance": bal}), 200
    except Exception as e:
        traceback.print_exc()
        return jsonify({"status":"error","message": str(e)}), 500

@app.route("/towallet/transactions/<phone>", methods=["GET"])
def towallet_transactions(phone):
    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT t.id, t.type, t.amount, t.other_party, t.date "
                "FROM transactions t JOIN users u ON t.user_id = u.id WHERE u.phone = ? ORDER BY t.id DESC",
                (phone,)
            )
            rows = cur.fetchall()
        out = []
        for r in rows:
            out.append({
                "id": r["id"],
                "type": r["type"],
                "amount": r["amount"],
                "other_party": r["other_party"],
                "date": r["date"]
            })
        return jsonify({"status":"success","transactions": out}), 200
    except Exception as e:
        traceback.print_exc()
        return jsonify({"status":"error","message": str(e)}), 500
@app.route("/towallet/resolve-account", methods=["POST"])
def towallet_resolve_account():
    try:
        data = request.get_json(silent=True) or {}
        account_number = str(data.get("account_number","")).strip()
        bank_code_raw = data.get("bank_code", "")

        if not account_number.isdigit() or len(account_number) != 10:
            return jsonify({"status":"error","message":"Invalid account number"}), 400

        # PayMe internal bypass (00023)
        if str(bank_code_raw) == "00023":
            with get_conn() as conn:
                cur = conn.cursor()
                cur.execute("SELECT username FROM users WHERE account_number = ?", (account_number,))
                r = cur.fetchone()
            acct_name = (r["username"] if r else "PayMe user")
            return jsonify({
                "status":"success",
                "provider":"payme",
                "account_name": acct_name,
                "account_number": account_number,
                "bank_code": "00023"
            }), 200

        bank_code_clean = "".join([c for c in ("" if bank_code_raw is None else str(bank_code_raw)) if c.isdigit()]).strip()
        account_bank = bank_code_clean if bank_code_clean else None

        flw_key = os.environ.get("FLW_SECRET_KEY")
        if not flw_key:
            return jsonify({"status":"error","message":"FLW_SECRET_KEY not configured on server"}), 500

        if not account_bank:
            return jsonify({"status":"error","message":"Could not determine Flutterwave numeric bank code", "details":"bank_code not numeric"}), 400

        try:
            flw_url = "https://api.flutterwave.com/v3/accounts/resolve"
            payload = {"account_number": account_number, "account_bank": account_bank}
            headers = {"Authorization": f"Bearer {flw_key}", "Content-Type": "application/json", "User-Agent":"PayMe/1.0"}
            flw_res = requests.post(flw_url, headers=headers, json=payload, timeout=12)
            flw_status = flw_res.status_code
            try:
                flw_json = flw_res.json()
            except Exception:
                flw_json = None
                flw_preview = (flw_res.text or "")[:2000]

            if flw_json and (flw_json.get("status") == "success" or str(flw_status).startswith("2")):
                acct_name = None
                if isinstance(flw_json.get("data"), dict):
                    acct_name = flw_json["data"].get("account_name") or flw_json["data"].get("accountName")
                acct_name = acct_name or flw_json.get("account_name") or (flw_json.get("data") or {}).get("account_name")
                if acct_name:
                    return jsonify({
                        "status":"success",
                        "provider":"flutterwave",
                        "account_name": acct_name,
                        "account_number": account_number,
                        "bank_code": account_bank,
                        "raw": flw_json
                    }), 200
                return jsonify({"status":"error","provider":"flutterwave","message":"Flutterwave returned success but no account_name","raw":flw_json}), 400

            msg = (flw_json.get("message") if flw_json else "Flutterwave did not return valid JSON")
            helper_tokens = ["no helper", "bank_code not numeric", "could not determine flutterwave numeric", "helper unavailable"]
            if isinstance(msg, str) and any(tok in msg.lower() for tok in helper_tokens):
                return jsonify({
                    "status":"warning",
                    "provider":"flutterwave",
                    "message":"Name lookup not available for this bank via Flutterwave. Proceed with caution.",
                    "can_proceed": True,
                    "bank_code": account_bank,
                    "raw": flw_json if flw_json is not None else flw_preview if 'flw_preview' in locals() else None
                }), 200

            return jsonify({"status":"error","provider":"flutterwave","message": msg, "raw": flw_json if flw_json is not None else flw_preview if 'flw_preview' in locals() else None}), flw_status if isinstance(flw_status,int) and flw_status>=400 else 400

        except requests.RequestException as ex:
            return jsonify({"status":"error","message": f"Network error contacting Flutterwave: {str(ex)}"}), 502

    except Exception as e:
        traceback.print_exc()
        return jsonify({"status":"error","message": f"Internal error: {str(e)}"}), 500

@app.route("/towallet/send_money", methods=["POST"])
def towallet_send_money():
    try:
        data = request.get_json(silent=True) or {}
        sender_phone = str(data.get("sender_phone", "")).strip()
        receiver_acc = str(data.get("receiver_acc", "")).strip()
        receiver_bank = str(data.get("receiver_bank", "")).strip()

        try:
            amount = float(data.get("amount", 0) or 0)
        except Exception:
            return jsonify({"status": "error", "message": "Invalid amount"}), 400

        if not sender_phone:
            return jsonify({"status": "error", "message": "Missing sender_phone"}), 400
        if not (receiver_acc.isdigit() and len(receiver_acc) == 10):
            return jsonify({"status": "error", "message": "Invalid receiver_acc"}), 400
        if amount <= 0:
            return jsonify({"status": "error", "message": "Invalid amount"}), 400

        with get_conn() as conn:
            cur = conn.cursor()

            # ✅ Fetch sender
            cur.execute("SELECT id, balance, account_number FROM users WHERE phone = ?", (sender_phone,))
            srow = cur.fetchone()
            if not srow:
                return jsonify({"status": "error", "message": "Sender not found"}), 404

            sender_id = srow["id"]
            sender_bal = float(srow["balance"])
            if sender_bal < amount:
                return jsonify({"status": "error", "message": "Insufficient funds"}), 400

            # ✅ Deduct from sender
            cur.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, sender_id))

            if DATABASE_URL:
                cur.execute(
                    "INSERT INTO transactions (user_id, type, amount, other_party, date) VALUES (?, ?, ?, ?, ?) RETURNING id",
                    (sender_id, "Transfer Out", amount, receiver_acc + "|" + receiver_bank, _now_iso())
                )
                tx_row = cur.fetchone()
                tid_out = tx_row["id"] if tx_row and "id" in tx_row else None
            else:
                cur.execute(
                    "INSERT INTO transactions (user_id, type, amount, other_party, date) VALUES (?, ?, ?, ?, ?)",
                    (sender_id, "Transfer Out", amount, receiver_acc + "|" + receiver_bank, _now_iso())
                )
                tid_out = cur.lastrowid

            meta = {"transaction_out_id": tid_out}

            # ✅ If internal transfer
            if receiver_bank == "00023":
                cur.execute("SELECT id, phone, balance FROM users WHERE account_number = ?", (receiver_acc,))
                rrow = cur.fetchone()
                if rrow:
                    recv_id = rrow["id"]
                    recv_phone = rrow["phone"]
                    cur.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, recv_id))

                    # record incoming transaction
                    if DATABASE_URL:
                        cur.execute(
                            "INSERT INTO transactions (user_id, type, amount, other_party, date) VALUES (?, ?, ?, ?, ?) RETURNING id",
                            (recv_id, "Transfer In", amount, sender_phone, _now_iso())
                        )
                        rr = cur.fetchone()
                        tid_in = rr["id"] if rr and "id" in rr else None
                    else:
                        cur.execute(
                            "INSERT INTO transactions (user_id, type, amount, other_party, date) VALUES (?, ?, ?, ?, ?)",
                            (recv_id, "Transfer In", amount, sender_phone, _now_iso())
                        )
                        tid_in = cur.lastrowid

                    meta.update({
                        "internal": True,
                        "recipient_found": True,
                        "recipient_id": recv_id,
                        "recipient_phone": recv_phone,
                        "transaction_in_id": tid_in
                    })
                else:
                    meta.update({"internal": True, "recipient_found": False})

            else:
                # External transfer
                meta.update({"external": True, "recipient_found": False})

            # ✅ fetch updated sender balance always
            cur.execute("SELECT balance FROM users WHERE id = ?", (sender_id,))
            newbal_row = cur.fetchone()
            new_bal = float(newbal_row["balance"]) if newbal_row else sender_bal
            meta["sender_balance"] = new_bal

            conn.commit()

            return jsonify({
                "status": "success",
                "message": f"Transfer of ₦{amount} processed",
                "meta": meta
            }), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({
            "status": "error",
            "message": f"Internal error: {str(e)}"
        }), 500


# -------------------------
# Route: GET /balance/<phone>
# -------------------------
@app.route("/balance/<phone>", methods=["GET"])
def get_balance(phone):
    """
    Return user's balance by phone.
    Response: 200 + {"balance": <number>} or 404 / 500 on error.
    """
    p = str(phone or "").strip()
    if not p:
        return jsonify({"status": "error", "message": "phone required"}), 400

    try:
        conn, kind = _get_db_conn()
        cur = conn.cursor()
        # try balances table first
        try:
            if kind == "sqlite":
                cur.execute("SELECT balance FROM balances WHERE phone = ? LIMIT 1", (p,))
                row = cur.fetchone()
            else:
                cur.execute("SELECT balance FROM balances WHERE phone = %s LIMIT 1", (p,))
                row = cur.fetchone()
            if row:
                bal = (row["balance"] if isinstance(row, dict) else row[0])
                return jsonify({"balance": float(bal)}), 200
        except Exception:
            # ignore and try users table
            pass

        # try users table
        try:
            if kind == "sqlite":
                cur.execute("SELECT balance FROM users WHERE phone = ? LIMIT 1", (p,))
                row = cur.fetchone()
            else:
                cur.execute("SELECT balance FROM users WHERE phone = %s LIMIT 1", (p,))
                row = cur.fetchone()
            if row:
                bal = row["balance"] if isinstance(row, sqlite3.Row) else (row[0] if isinstance(row, tuple) else getattr(row, 'balance', None))
                return jsonify({"balance": float(bal or 0)}), 200
        except Exception:
            pass

        return jsonify({"status": "error", "message": "User or balance not found"}), 404

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"status": "error", "message": "Internal server error", "details": str(e)}), 500

# -------------------------
# Route: POST /execute-transfer
# -------------------------
@app.route("/execute-transfer", methods=["POST"])
def execute_transfer():
    """
    Execute a wallet-to-wallet transfer.
    Expects JSON:
      {
        "sender_phone": "0800xxx",
        "receiver_account": "2198579728",
        "amount": 1000,
        "note": "...optional..."
      }
    Returns 200 + transaction payload on success.
    """
    try:
        payload = request.get_json(silent=True) or {}
        sender_phone = str(payload.get("sender_phone") or "").strip()
        receiver_acc = str(payload.get("receiver_account") or "").strip()
        amount = payload.get("amount")

        if not sender_phone or not receiver_acc or amount is None:
            return jsonify({"status":"error","message":"sender_phone, receiver_account and amount required"}), 400

        try:
            amt = int(amount)
            if amt <= 0:
                return jsonify({"status":"error","message":"amount must be positive integer"}), 400
        except Exception:
            return jsonify({"status":"error","message":"amount must be integer"}), 400

        conn, kind = _get_db_conn()
        cur = conn.cursor()

        # 1) Fetch sender balance
        # try balances table then users
        sender_balance = None
        try:
            if kind == "sqlite":
                cur.execute("SELECT balance FROM balances WHERE phone = ? LIMIT 1", (sender_phone,))
                r = cur.fetchone()
                if r:
                    sender_balance = float(r["balance"])
            else:
                cur.execute("SELECT balance FROM balances WHERE phone = %s LIMIT 1", (sender_phone,))
                r = cur.fetchone()
                if r:
                    sender_balance = float(r[0])
        except Exception:
            sender_balance = None

        if sender_balance is None:
            try:
                if kind == "sqlite":
                    cur.execute("SELECT balance FROM users WHERE phone = ? LIMIT 1", (sender_phone,))
                    r = cur.fetchone()
                    if r:
                        sender_balance = float(r["balance"])
                else:
                    cur.execute("SELECT balance FROM users WHERE phone = %s LIMIT 1", (sender_phone,))
                    r = cur.fetchone()
                    if r:
                        sender_balance = float(r[0])
            except Exception:
                sender_balance = None

        if sender_balance is None:
            return jsonify({"status":"error","message":"Sender balance not found"}), 404

        if sender_balance < amt:
            return jsonify({"status":"error","message":"Insufficient funds"}), 400

        # 2) Find receiver user (may be external). Prefer to credit users table if exists, else fallback to balances table,
        # or return success but mark as external (you might want to push to bank where appropriate).
        receiver_found = False
        try:
            if kind == "sqlite":
                cur.execute("SELECT id, phone, account_number FROM users WHERE account_number = ? OR acc_number = ? OR account = ? LIMIT 1", (receiver_acc, receiver_acc, receiver_acc))
                rcv = cur.fetchone()
            else:
                cur.execute("SELECT id, phone, account_number FROM users WHERE account_number = %s OR acc_number = %s OR account = %s LIMIT 1", (receiver_acc, receiver_acc, receiver_acc))
                rcv = cur.fetchone()
        except Exception:
            rcv = None

        # Begin transaction
        if kind == "pg":
            conn.autocommit = False
        else:
            # sqlite default autocommit false when using connection
            pass

        try:
            # deduct sender
            if kind == "sqlite":
                cur.execute("UPDATE users SET balance = balance - ? WHERE phone = ? OR account_number = ? OR acc_number = ? OR account = ?",
                            (amt, sender_phone, sender_phone, sender_phone, sender_phone))
                if cur.rowcount == 0:
                    # maybe balances table
                    cur.execute("UPDATE balances SET balance = balance - ? WHERE phone = ?", (amt, sender_phone))
            else:
                cur.execute("UPDATE users SET balance = balance - %s WHERE phone = %s OR account_number = %s OR acc_number = %s OR account = %s",
                            (amt, sender_phone, sender_phone, sender_phone, sender_phone))
                if cur.rowcount == 0:
                    cur.execute("UPDATE balances SET balance = balance - %s WHERE phone = %s", (amt, sender_phone))

            # credit receiver if exists in users or balances
            if rcv:
                receiver_found = True
                # rcv may be sqlite Row or tuple
                # try users table credit
                if kind == "sqlite":
                    cur.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amt, rcv["id"]))
                else:
                    cur.execute("UPDATE users SET balance = balance + %s WHERE id = %s", (amt, rcv[0]))
            else:
                # try balances table (maybe receiver stored there)
                try:
                    if kind == "sqlite":
                        cur.execute("SELECT balance FROM balances WHERE phone = ? LIMIT 1", (receiver_acc,))
                        r = cur.fetchone()
                        if r:
                            cur.execute("UPDATE balances SET balance = balance + ? WHERE phone = ?", (amt, receiver_acc))
                        else:
                            # create a balances record for this receiver_acc so multi-phone transfers possible
                            cur.execute("INSERT INTO balances (phone, balance) VALUES (?, ?)", (receiver_acc, amt))
                    else:
                        cur.execute("SELECT balance FROM balances WHERE phone = %s LIMIT 1", (receiver_acc,))
                        r = cur.fetchone()
                        if r:
                            cur.execute("UPDATE balances SET balance = balance + %s WHERE phone = %s", (amt, receiver_acc))
                        else:
                            cur.execute("INSERT INTO balances (phone, balance) VALUES (%s, %s)", (receiver_acc, amt))
                except Exception as e:
                    # if balances table doesn't exist or insert fails, rollback and return error
                    conn.rollback()
                    return jsonify({"status":"error","message":"Receiver credit failed","details": str(e)}), 500

            # Optionally insert into transactions table if exists
            try:
                txn_ref = str(uuid.uuid4())
                now = datetime.utcnow().isoformat()
                if kind == "sqlite":
                    cur.execute("""INSERT INTO transactions (reference, sender_phone, receiver_account, amount, created_at, status)
                                   VALUES (?, ?, ?, ?, ?, ?)""", (txn_ref, sender_phone, receiver_acc, amt, now, "success"))
                else:
                    cur.execute("""INSERT INTO transactions (reference, sender_phone, receiver_account, amount, created_at, status)
                                   VALUES (%s, %s, %s, %s, %s, %s)""", (txn_ref, sender_phone, receiver_acc, amt, now, "success"))
            except Exception:
                # ignore if transactions table missing
                txn_ref = None

            conn.commit()
        except Exception as e:
            conn.rollback()
            import traceback
            traceback.print_exc()
            return jsonify({"status":"error","message":"Transfer failed","details": str(e)}), 500
        finally:
            try:
                cur.close()
            except Exception:
                pass
            try:
                if kind == "pg":
                    conn.autocommit = True
            except Exception:
                pass

        result = {
            "status": "success",
            "sender_phone": sender_phone,
            "receiver_account": receiver_acc,
            "amount": amt,
            "transaction_ref": txn_ref
        }
        return jsonify(result), 200

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"status":"error","message":"Internal server error", "details": str(e)}), 500

# ---------------------------------------
# IMPORT ADMIN BLUEPRINT (after get_conn)
# ---------------------------------------
from admin import admin_bp, init_admin

# pass DB connector function to admin module
init_admin(get_conn)

# register blueprint
app.register_blueprint(admin_bp, url_prefix="/api")
print("admin blueprint registered")
# -------------------------------------------------
# Startup
# -------------------------------------------------
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
else:
    # ensure DB exists when imported
    with app.app_context():
        init_db()