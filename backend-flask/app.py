from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
import sqlite3
from datetime import datetime, timedelta  # + timedelta added to support savings durations
import os
import sys
import traceback
import requests
import math
import time
from services.flutterwave_service import FlutterwaveService

# ✅ Step 1: Create the Flask app
app = Flask(__name__)
CORS(app)



# -------------------------------------------------
# Postgres Support
# -------------------------------------------------
DATABASE_URL = os.environ.get("DATABASE_URL")  # ✅ only use DATABASE_URL
if DATABASE_URL:
    try:
        import psycopg2
        import psycopg2.extras
    except Exception as e:
        # If psycopg2 isn't installed, we'll raise an informative error later when trying to use Postgres.
        psycopg2 = None
        psycopg2_extras = None

NUBAPI_KEY = os.environ.get("NUBAPI_KEY")  # stored safely in Render


# -------------------------------------------------
# App & CORS
# -------------------------------------------------
app = Flask(__name__)

cors_origins = os.environ.get("CORS_ORIGINS", "*")
CORS(app, resources={r"/*": {"origins": cors_origins}}, supports_credentials=True)

DB = os.environ.get("SQLITE_DB_PATH", "payme.db")


# -------------------------------------------------
# DB helpers
# -------------------------------------------------
# We provide a get_conn() context manager that supports both sqlite3 and psycopg2.
# It returns an object with cursor() that supports execute(...), fetchone(), fetchall() etc.
# For psycopg2 we wrap execute to convert "?" placeholders -> "%s" so existing SQL works.

class PGCursorWrapper:
    """Wrap a psycopg2 cursor and convert ? -> %s in SQL automatically."""
    def __init__(self, cur):
        self._cur = cur

    def execute(self, sql, params=None):
        if params is None:
            return self._cur.execute(sql)
        # Replace ? placeholders with %s for psycopg2
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
        # connect using the provided DATABASE_URL/DSN
        # allow connection parameters in URL form
        self.conn = psycopg2.connect(self.dsn)
        # We'll use transactions and commit at the end of the context
        self.conn.autocommit = False
        return self

    def cursor(self):
        # Return a wrapped cursor that converts placeholders
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
        if exc:
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
        print("✅ Using Postgres", flush=True)
        return PGConnectionContext(DATABASE_URL)
    else:
        print("⚠️ Using SQLite fallback", flush=True)
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


# -------------------------------------------------
# Global error & logging
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

    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO users (username, phone, password, account_number, balance) VALUES (?, ?, ?, ?, ?)",
                (username, phone, password, account_number, 0.0),
            )
        return jsonify({"status": "success", "account_number": account_number}), 200
    except Exception as ie:
        # Try to provide the same messages as original (works for sqlite and Postgres)
        msg = "User already exists"
        if "username" in str(ie).lower():
            msg = "Username already exists"
        elif "phone" in str(ie).lower():
            msg = "Phone already exists"
        return jsonify({"status": "error", "message": msg}), 400

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    login = data.get("login")
    password = data.get("password")

    conn = sqlite3.connect("payme.db")
    c = conn.cursor()

    c.execute("SELECT id, username, phone, account_number, balance, password FROM users WHERE username=? OR phone=?", (login, login))
    row = c.fetchone()
    conn.close()

    if row:
        user = {
            "id": row[0],
            "username": row[1],
            "phone": row[2],
            "account_number": row[3],
            "balance": row[4],
            "password": row[5],
        }

        # Direct comparison (no hashing)
        if user["password"] == password:
            return jsonify({"status": "success", "user": user}), 200
        else:
            return jsonify({"status": "error", "message": "Invalid password"}), 401

    return jsonify({"status": "error", "message": "User not found"}), 404
# -------------------------------------------------
# Money
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
            cur.execute("UPDATE users SET password = ? WHERE id = ?", (new_password, user["id"]))

        # fetch updated user
        cur.execute("SELECT username, phone, account_number, balance FROM users WHERE id = ?", (user["id"],))
        updated = dict(cur.fetchone())

    return jsonify({"status": "success", "user": updated}), 200

# -------------------------------------------------
# Entry
# -------------------------------------------------
if __name__ != "__main__":
    with app.app_context():
        init_db()


# GET balance for towallet (alias; uses existing get_conn)
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

# GET transactions for towallet user (convenience)
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

# POST towallet resolve-account (separate from global /resolve-account)
@app.route("/towallet/resolve-account", methods=["POST"])
def towallet_resolve_account():
    """
    POST { account_number, bank_code }
    - bank_code == "00023" -> always resolve as internal (PayMe bypass)
    - otherwise, if FLW_SECRET_KEY present -> call Flutterwave resolve
    - if flutterwave returns helper-unavailable style message -> return warning with can_proceed:true
    """
    try:
        data = request.get_json(silent=True) or {}
        account_number = str(data.get("account_number","")).strip()
        bank_code_raw = data.get("bank_code", "")

        if not account_number.isdigit() or len(account_number) != 10:
            return jsonify({"status":"error","message":"Invalid account number"}), 400

        # PayMe internal bypass
        if str(bank_code_raw) == "00023":
            # Try to show local username if present
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

        # Normalize bank code into digits only if possible
        bank_code_clean = "".join([c for c in ("" if bank_code_raw is None else str(bank_code_raw)) if c.isdigit()]).strip()
        account_bank = bank_code_clean if bank_code_clean else None

        flw_key = os.environ.get("FLW_SECRET_KEY")
        if not flw_key:
            return jsonify({"status":"error","message":"FLW_SECRET_KEY not configured on server"}), 500

        if not account_bank:
            return jsonify({"status":"error","message":"Could not determine Flutterwave numeric bank code", "details":"bank_code not numeric"}), 400

        # Call Flutterwave resolve
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

            # Success-ish from Flutterwave
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

            # Non-success from Flutterwave
            msg = (flw_json.get("message") if flw_json else "Flutterwave did not return valid JSON")
            # If message indicates helper/unavailable, return warning so frontend can proceed
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

# POST towallet send_money
@app.route("/towallet/send_money", methods=["POST"])
def towallet_send_money():
    """
    POST { sender_phone, receiver_acc, amount, receiver_bank }
    - Deducts from sender balance (must exist & sufficient).
    - If receiver_bank == '00023' => internal: credit recipient if local user exists (by account_number).
      otherwise treat as external (do not credit recipient).
    - Records transactions in transactions table for the sender and recipient (if credited).
    """
    try:
        data = request.get_json(silent=True) or {}
        sender_phone = str(data.get("sender_phone","")).strip()
        receiver_acc = str(data.get("receiver_acc","")).strip()
        receiver_bank = str(data.get("receiver_bank","")).strip()
        try:
            amount = float(data.get("amount", 0) or 0)
        except Exception:
            return jsonify({"status":"error","message":"Invalid amount"}), 400

        if not sender_phone:
            return jsonify({"status":"error","message":"Missing sender_phone"}), 400
        if not (receiver_acc.isdigit() and len(receiver_acc) == 10):
            return jsonify({"status":"error","message":"Invalid receiver_acc"}), 400
        if amount <= 0:
            return jsonify({"status":"error","message":"Invalid amount"}), 400

        with get_conn() as conn:
            cur = conn.cursor()
            # find sender
            cur.execute("SELECT id, balance, account_number FROM users WHERE phone = ?", (sender_phone,))
            srow = cur.fetchone()
            if not srow:
                return jsonify({"status":"error","message":"Sender not found"}), 404
            sender_id = srow["id"]
            sender_bal = float(srow["balance"])
            if sender_bal < amount:
                return jsonify({"status":"error","message":"Insufficient funds"}), 400

            # deduct sender
            cur.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, sender_id))
            # record sender transaction
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

            # default response meta
            meta = {"transaction_out_id": tid_out}

            # If internal PayMe code -> attempt to credit recipient if exists by account_number
            if receiver_bank == "00023":
                cur.execute("SELECT id, phone, balance FROM users WHERE account_number = ?", (receiver_acc,))
                rrow = cur.fetchone()
                if rrow:
                    recv_id = rrow["id"]
                    recv_phone = rrow["phone"]
                    # credit recipient
                    cur.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, recv_id))
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
                    # internal code provided but recipient not found locally -> treat as external
                    meta.update({"internal": True, "recipient_found": False, "note":"internal code but no local recipient; money treated external"})
            else:
                # external transfer: do not credit recipient even if account exists locally
                meta.update({"external": True, "recipient_found": False})

            # get updated sender balance
            cur.execute("SELECT balance FROM users WHERE id = ?", (sender_id,))
            newbal_row = cur.fetchone()
            new_bal = float(newbal_row["balance"]) if newbal_row else None
            meta["sender_balance"] = new_bal

        return jsonify({"status":"success","message": f"Transfer of ₦{amount} processed", "meta": meta}), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({"status":"error","message": f"Internal error: {str(e)}"}), 500

# ----------------- END: towallet endpoints -----------------

@app.route("/banks", methods=["GET"])
def get_banks():
    """
    Return live Flutterwave banks only. Requires FLW_SECRET_KEY in env.
    Returns 200 + {"status":"success","banks": {code: name, ...}} on success.
    Returns 4xx/5xx with a clear error message when Flutterwave can't be used.
    """
    try:
        flw_key = os.environ.get("FLW_SECRET_KEY")
        if not flw_key:
            return jsonify({
                "status": "error",
                "message": "FLW_SECRET_KEY not configured on server. Set FLW_SECRET_KEY to fetch Flutterwave banks."
            }), 400

        # Prefer cached helper if available
        try:
            banks_map, err = get_flutter_banks(force_refresh=False)
            if banks_map:
                return jsonify({"status": "success", "message": "Banks fetched from Flutterwave (cache)", "banks": banks_map}), 200
            # if helper returned err or None, fall through to direct fetch
        except NameError:
            # get_flutter_banks not defined — will fetch directly below
            pass

        # Direct fetch as fallback (or if helper returned no data)
        url = "https://api.flutterwave.com/v3/banks/NG"
        headers = {"Authorization": f"Bearer {flw_key}", "User-Agent": "PayMe/1.0"}
        resp = requests.get(url, headers=headers, timeout=10)

        # Surface exact Flutterwave error if any
        if resp.status_code != 200:
            body_text = resp.text or ""
            # Try to parse JSON body if possible
            try:
                body_json = resp.json()
            except Exception:
                body_json = body_text
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
        # network / timeout
        return jsonify({
            "status": "error",
            "message": "Network error when contacting Flutterwave /banks",
            "details": str(e)
        }), 502
    except Exception as e:
        # catch-all
        return jsonify({
            "status": "error",
            "message": "Internal error while fetching banks from Flutterwave",
            "details": str(e)
        }), 500


@app.route("/resolve-account", methods=["POST"])
def resolve_account():
    """
    Resolve account_number + bank_code using Flutterwave only.
    Expects JSON body: { "account_number": "2198579728", "bank_code": "000004" }
    """
    try:
        data = request.get_json(silent=True) or {}
        account_number = str(data.get("account_number", "")).strip()
        bank_code = data.get("bank_code", "")  # keep original type for flexible handling

        # Basic validation
        if not account_number.isdigit() or len(account_number) != 10:
            return jsonify({"status": "error", "message": "Invalid account number"}), 400

        # Helper to safely parse JSON from requests responses
        def try_parse_json(resp):
            try:
                return resp.json(), None
            except ValueError:
                text = resp.text or ""
                return None, text[:3000]

        # Get FLW secret
        flw_key = os.environ.get("FLW_SECRET_KEY")
        if not flw_key:
            return jsonify({"status": "error", "message": "FLW_SECRET_KEY not configured on server"}), 500

        # ---- Resolve the numeric code to send to Flutterwave (robust) ----
        account_bank = None
        mapping_error = None

        try:
            # Normalize incoming bank_code into a string (guard against ints, None etc.)
            bank_code_raw = "" if bank_code is None else str(bank_code)

            # Trim whitespace and remove non-digit characters (hidden/formatting chars)
            bank_code_clean = ''.join(ch for ch in bank_code_raw if ch.isdigit()).strip()

            # If a helper exists, prefer it (maintains backward compatibility if implementer added it)
            try:
                # find_flutter_code should return (numeric_code, optional_error)
                account_bank, mapping_error = find_flutter_code(bank_code_raw)
                # ensure returned account_bank is a clean numeric string
                if isinstance(account_bank, (int, float)):
                    account_bank = str(account_bank)
                if account_bank:
                    account_bank = ''.join(ch for ch in str(account_bank) if ch.isdigit())
            except NameError:
                # No helper present — fall back to cleaned numeric code
                account_bank = bank_code_clean if bank_code_clean else None
                if not account_bank:
                    mapping_error = "No helper available and bank_code not numeric"
            except Exception as e:
                account_bank = None
                mapping_error = f"Helper error: {str(e)}"

            # Accept common flutterwave code lengths (3..6 digits). Fintech codes are typically 5-6 digits.
            if account_bank and not (3 <= len(account_bank) <= 6):
                mapping_error = f"bank_code numeric but invalid length ({len(account_bank)})"
                account_bank = None

        except Exception as e:
            account_bank = None
            mapping_error = f"Normalization error: {str(e)}"

        # Sandbox limitation: force Access Bank (044) in test mode (preserve original behavior)
        if not account_bank and "test" in flw_key.lower():
            account_bank = "044"
            mapping_error = None

        # Debug log: raw + cleaned inputs
        try:
            print("🧾 resolve-account inputs -> account_number:", account_number,
                  "bank_code_raw:", repr(bank_code), "bank_code_clean:", account_bank, flush=True)
        except Exception:
            pass

        # If still no numeric account_bank, return error (same shape as before)
        if not account_bank:
            return jsonify({
                "status": "error",
                "message": "Could not determine Flutterwave numeric bank code",
                "details": mapping_error
            }), 400

        # Call Flutterwave resolve API
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

            # Log minimal info to stdout for server logs (helpful for debugging)
            print("Flutterwave resolve status:", flw_status, flush=True)
            # print truncated preview to avoid giant logs
            print("Flutterwave resolve preview:", (flw_res.text or "")[:1200], flush=True)

            # If Flutterwave returned JSON and success-ish status, try extract account_name
            if flw_json and (flw_json.get("status") == "success" or str(flw_status).startswith("2")):
                # Try to extract account name from common locations
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

                # success status but no name (preserve original behavior)
                return jsonify({
                    "status": "error",
                    "provider": "flutterwave",
                    "message": "Flutterwave returned success but no account_name",
                    "raw": flw_json
                }), 400

            # If Flutterwave returned a non-success JSON, check for helper-related messages
            if flw_json:
                msg = flw_json.get("message") or flw_json.get("error") or "Flutterwave unresolved"
                details = flw_json
            else:
                msg = "Flutterwave did not return valid JSON"
                details = flw_preview

            # Special-case: if Flutterwave explicitly says helper unavailable, allow frontend to proceed with warning
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
                # Return a 200-ish warning with can_proceed:true so frontend can allow a manual proceed
                return jsonify({
                    "status": "warning",
                    "provider": "flutterwave",
                    "message": "Name lookup not available for this bank via Flutterwave. Proceed with caution.",
                    "can_proceed": True,
                    "bank_code": account_bank,
                    "raw": flw_json if flw_json is not None else flw_preview
                }), 200

            # Otherwise surface provider message and HTTP status
            return jsonify({
                "status": "error",
                "provider": "flutterwave",
                "message": msg,
                "raw": details
            }), flw_status if isinstance(flw_status, int) and flw_status >= 400 else 400

        except requests.exceptions.RequestException as e:
            print("Flutterwave request exception:", str(e), flush=True)
            return jsonify({"status": "error", "message": f"Network error contacting Flutterwave: {str(e)}"}), 502

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"status": "error", "message": f"Internal error: {str(e)}"}), 500
                    

# Savings (added, routes match your front-end)
# -------------------------------------------------
INTEREST_RATE = 0.20  # 20% annual simple interest

def _calc_interest(amount: float, days: int) -> float:
    if days <= 0:
        return 0.0
    return amount * INTEREST_RATE * (days / 365.0)

def _sweep_matured_savings_for_user(conn, user_id: int):
    """
    Auto-credit matured savings for a user.
    Pays principal + full scheduled interest at maturity.
    Marks savings as withdrawn and logs a transaction.
    """
    cur = conn.cursor()
    now = datetime.now()

    # Use different SQL for SQLite vs Postgres because sqlite has datetime() function,
    # while Postgres requires casting the text to timestamp.
    if DATABASE_URL:
        # Postgres: cast end_date (stored as ISO text) to timestamp for comparison
        sql = """
            SELECT id, amount, type, start_date, duration_days, end_date
            FROM savings
            WHERE user_id = ? AND status = 'active' AND CAST(end_date AS timestamp) <= ?
        """
    else:
        # SQLite: use datetime() wrapper
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
        # full tenure interest paid at maturity
        interest = _calc_interest(amount, duration_days)
        payout = amount + interest

        # Mark withdrawn
        cur.execute("UPDATE savings SET status = 'withdrawn' WHERE id = ?", (s["id"],))
        # Credit user
        cur.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (payout, user_id))
        # Transaction
        cur.execute(
            "INSERT INTO transactions (user_id, type, amount, other_party, date) VALUES (?, ?, ?, ?, ?)",
            (user_id, "Savings Maturity", payout, "System", datetime.now().isoformat()),
        )

    return len(matured)


@app.route("/savings/create", methods=["POST"])
def savings_create():
    """
    Body: { user_id OR phone, amount, savings_type, duration_days }
    """
    data = request.get_json()

    # Accept either user_id or phone
    user_id = data.get("user_id")
    phone = data.get("phone")
    amount = data.get("amount")
    savings_type = str(data.get("savings_type", "")).strip().lower()
    duration_days = int(data.get("duration_days", 0))

    if not (user_id or phone):
        return jsonify({"status": "error", "message": "user_id or phone required"}), 400
    if not amount or float(amount) <= 0:
        return jsonify({"status": "error", "message": "Amount must be > 0"}), 400
    if savings_type not in ("flexible", "fixed"):
        return jsonify({"status": "error", "message": "savings_type must be 'flexible' or 'fixed'"}), 400
    if duration_days <= 0:
        return jsonify({"status": "error", "message": "duration_days must be > 0"}), 400

    with get_conn() as conn:
        cur = conn.cursor()

        # Look up user either by id or phone
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

        # Deduct and create savings
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
            # ✅ only allow withdraw if still active
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
    """
    Body: { user_id, savings_id }
    Flexible:
        - Withdraw anytime
        - If early: only principal
        - If matured: principal + interest
    Fixed:
        - Only withdraw at maturity
    """
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

        # Get savings record
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

        payout = amount  # default principal only

        # Flexible logic
        if s["type"] == "flexible":
            if now >= end:
                # matured → add interest
                interest = _calc_interest(amount, s["duration_days"])
                payout += interest
        # Fixed logic
        elif s["type"] == "fixed":
            if now < end:
                return jsonify({"status": "error", "message": "Fixed savings cannot be withdrawn before maturity"}), 400
            # matured → add interest
            interest = _calc_interest(amount, s["duration_days"])
            payout += interest
        else:
            return jsonify({"status": "error", "message": "Invalid savings type"}), 400

        # Update DB: mark withdrawn, credit user, record transaction
        cur.execute("UPDATE savings SET status = 'withdrawn' WHERE id = ?", (s["id"],))
        cur.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (payout, user_id))
        cur.execute(
            "INSERT INTO transactions (user_id, type, amount, other_party, date) VALUES (?, ?, ?, ?, ?)",
            (user_id, "Savings Withdraw", payout, s["type"], datetime.now().isoformat()),
        )

    return jsonify({"status": "success", "message": f"₦{payout} credited to main balance"}), 200

@app.route("/buy_airtime", methods=["POST"])
def buy_airtime():
    """
    Body (JSON): { phone: <user phone (11 digits)>, network: <MTN|Glo|Airtel|9Mobile>, amount: <number>, recipient: <destination phone> }
    Deducts (amount + 1% fee) from user's balance, writes a transaction, returns new balance + transaction.
    """
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

    # fee: 1% rounded up
    fee = int(math.ceil(amount * 0.01))
    total = float(amount + fee)

    now_iso = datetime.now().isoformat()

    with get_conn() as conn:
        cur = conn.cursor()

        # find user by phone
        cur.execute("SELECT id, balance FROM users WHERE phone = ?", (phone,))
        user = cur.fetchone()
        if not user:
            return jsonify({"status": "error", "message": "User not found"}), 404

        user_id = user["id"]
        balance = float(user["balance"])

        if balance < total:
            return jsonify({"status": "error", "message": "Insufficient balance", "balance": balance}), 400

        # deduct user balance
        cur.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (total, user_id))

        # build 'other_party' with readable info
        other_party = f"airtime|network:{network}|to:{recipient}|fee:{fee}|value:{amount}"

        # insert transaction - compatible with SQLite and Postgres
        if DATABASE_URL:
            # Postgres: RETURNING id
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
            # sqlite cursor supports lastrowid
            txn_id = cur.lastrowid

        # fetch new balance
        cur.execute("SELECT balance FROM users WHERE id = ?", (user_id,))
        newbal = cur.fetchone()
        new_balance = float(newbal["balance"]) if newbal else None

    # prepare response transaction object
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
# Startup
# -------------------------------------------------
if __name__ == "__main__":
    init_db()  # ✅ Ensure tables exist on startup
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

