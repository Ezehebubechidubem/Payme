from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
import sqlite3
from datetime import datetime, timedelta  # + timedelta added to support savings durations
import os
import sys
import traceback
import requests
import math
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
    data, err, code = json_required(["login", "password"])
    if err:
        return err, code

    login_value = data["login"].strip()
    password = data["password"]

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, username, phone, password, account_number, balance "
            "FROM users WHERE (username = ? OR phone = ?) AND password = ?",
            (login_value, login_value, password),
        )
        row = cur.fetchone()

    if not row:
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401

    user = {
        "id": row["id"],
        "username": row["username"],
        "phone": row["phone"],
        "account_number": row["account_number"],
        "balance": row["balance"],
    }
    return jsonify({"status": "success", "user": user}), 200


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

 # ---------- Replace/insert this into your existing Flask app ----------
# (Only replace the BANKS dict and the two routes; the rest of your app remains unchanged.)

# BANKS: ~50 popular Nigerian banks/wallets (canonical keys as in your earlier list)
BANKS = {
    "000013": "GTBANK PLC",
    "000014": "ACCESS BANK",
    "000015": "ZENITH BANK",
    "000016": "FIRST BANK OF NIGERIA",
    "000004": "UNITED BANK FOR AFRICA",
    "000005": "ACCESS(DIAMOND) BANK",
    "000001": "STERLING BANK",
    "000017": "WEMA BANK",
    "000018": "UNION BANK",
    "000020": "HERITAGE BANK",
    "000025": "TITAN TRUST BANK",
    "000026": "TAJ BANK",
    "000027": "GLOBUS BANK",
    "000029": "LOTUS BANK",
    "000030": "PARALLEX BANK",
    "000033": "ENAIRA",
    "000040": "UBA MONI",
    "000010": "ECOBANK",
    "000011": "UNITY BANK",
    "000012": "STANBIC IBTC BANK",
    "000021": "STANDARD CHARTERED BANK",
    "000024": "RAND MERCHANT BANK",
    "000028": "CBN",
    "000031": "PREMIUM TRUST  BANK",
    "000034": "SIGNATURE BANK",
    "000036": "OPTIMUS BANK",
    "060001": "CORONATION MERCHANT BANK",
    "100004": "OPAY",
    "100033": "PALMPAY",
    "100014": "FIRSTMONIE WALLET",
    "100009": "GT MOBILE",
    "100008": "ECOBANK XPRESS ACCOUNT",
    "100031": "FCMB MOBILE",
    "100025": "KONGAPAY",
    "100012": "VT NETWORKS",
    "090110": "VFD MFB",
    "090267": "KUDA MICROFINANCE BANK",
    "090111": "FINATRUST MICROFINANCE BANK",
    "090151": "MUTUAL TRUST MICROFINANCE BANK",
    "090260": "ABOVE ONLY MICROFINANCE BANK",
    "090145": "FULLRANGE MICROFINANCE BANK",
    "090140": "SAGAMU MICROFINANCE BANK",
    "090123": "TRUSTBANC J6 MICROFINANCE BANK LIMITED",
    "090110": "VFD MFB",
    "000006": "JAIZ BANK",
    "000007": "FIDELITY BANK",
    "000008": "POLARIS BANK",
    "000009": "CITI BANK",
    "000019": "ENTERPRISE BANK"
}
# (This gives you a balanced list across mainstream banks, merchant banks, and wallets.)

# GET /banks
@app.route("/banks", methods=["GET"])
def get_banks():
    """Return available banks (code -> name)."""
    return jsonify(BANKS), 200


# Helper: normalize bank code input
def normalize_bank_code(input_code_or_name: str):
    """
    Accepts:
      - exact code (e.g. "000004")
      - short numeric code (e.g. "4", "004", "058")
      - bank name fragment (e.g. "UBA", "United")
    Returns canonical code key from BANKS, or None if not found.
    """
    if not input_code_or_name:
        return None
    s = str(input_code_or_name).strip()

    # 1) exact match
    if s in BANKS:
        return s

    # 2) numeric match after removing leading zeros
    s_num = s.lstrip("0")
    if s_num.isdigit():
        for k in BANKS:
            if k.lstrip("0") == s_num:
                return k

    # 3) match by name fragment (case-insensitive)
    s_up = s.upper()
    for k, v in BANKS.items():
        if s_up in v.upper() or v.upper() in s_up:
            return k

    return None


# Resolve Account (GET + POST)
@app.route("/resolve_account", methods=["GET", "POST"])
def resolve_account():
    """
    Proxy NubAPI account verification.
    Accepts:
      GET  -> query params ?account_number=...&bank_code=...
      POST -> JSON body {"account_number": "...", "bank_code": "..."}
    Returns:
      - success: {status:"success", account_name: "...", account_number: "...", bank_code: "..."}
      - error: {status:"error", message: "...", nubapi_preview?: "..."}
    """
    # Input handling
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        account_number = str(data.get("account_number", "")).strip()
        bank_code_in = str(data.get("bank_code", "")).strip()
    else:
        account_number = str(request.args.get("account_number", "")).strip()
        bank_code_in = str(request.args.get("bank_code", "")).strip()

    # Basic validation: account number
    if not account_number.isdigit() or len(account_number) != 10:
        return jsonify({"status": "error", "message": "Invalid account number"}), 400

    # Normalize/resolve bank code
    resolved_code = normalize_bank_code(bank_code_in)
    if not resolved_code:
        return jsonify({"status": "error", "message": f"Unknown bank code ({bank_code_in})"}), 400

    bank_code = resolved_code  # canonical code from BANKS

    # Get API key from env (try common names)
    NUBAPI_KEY = os.environ.get("NUBAPI_KEY") or os.environ.get("NUBAPI_API") or os.environ.get("NUPABI_API")
    if not NUBAPI_KEY:
        return jsonify({"status": "error", "message": "NUBAPI_KEY not set"}), 500

    nubapi_url = "https://nubapi.com/api/verify"

    # Safe JSON parse helper
    def try_parse_json(resp):
        try:
            return resp.json(), None
        except ValueError:
            text = resp.text or ""
            return None, text[:3000]

    try:
        # Attempt 1: Bearer token in headers (modern pattern)
        headers = {
            "Authorization": f"Bearer {NUBAPI_KEY}",
            "Accept": "application/json",
            "User-Agent": "PayMe/1.0"
        }
        params = {"account_number": account_number, "bank_code": bank_code}

        res = requests.get(nubapi_url, headers=headers, params=params, timeout=12)
        print("NubAPI (header) status:", res.status_code, flush=True)
        print("NubAPI (header) preview:", (res.text or "")[:1000], flush=True)

        if res.status_code == 200:
            data, preview = try_parse_json(res)
            if data:
                # JSON returned
                if data.get("status") == "success" and data.get("account_name"):
                    return jsonify({
                        "status": "success",
                        "account_name": data["account_name"],
                        "account_number": account_number,
                        "bank_code": bank_code
                    }), 200
                # JSON but indicates failure
                return jsonify({
                    "status": "error",
                    "message": data.get("message", "Unable to verify account"),
                    "raw": data
                }), 400
            else:
                # non-JSON returned; continue to fallback
                header_preview = preview
        else:
            header_preview = (res.text or "")[:3000]

        # Attempt 2: query param style with api_key in URL (legacy)
        url_with_key = f"{nubapi_url}?account_number={account_number}&bank_code={bank_code}&api_key={NUBAPI_KEY}"
        res2 = requests.get(url_with_key, timeout=12, headers={"Accept": "application/json", "User-Agent": "PayMe/1.0"})
        print("NubAPI (query) status:", res2.status_code, flush=True)
        print("NubAPI (query) preview:", (res2.text or "")[:1000], flush=True)

        if res2.status_code == 200:
            data2, preview2 = try_parse_json(res2)
            if data2:
                if data2.get("status") == "success" and data2.get("account_name"):
                    return jsonify({
                        "status": "success",
                        "account_name": data2["account_name"],
                        "account_number": account_number,
                        "bank_code": bank_code
                    }), 200
                return jsonify({
                    "status": "error",
                    "message": data2.get("message", "Unable to verify account"),
                    "raw": data2
                }), 400
            else:
                query_preview = preview2
        else:
            query_preview = (res2.text or "")[:3000]

        # Nothing returned valid JSON success — surface previews for debugging
        nubapi_preview = None
        if 'preview2' in locals() and preview2:
            nubapi_preview = preview2
        elif 'preview' in locals() and preview:
            nubapi_preview = preview
        else:
            nubapi_preview = (header_preview if 'header_preview' in locals() else "") + "\n\n" + (query_preview if 'query_preview' in locals() else "")
            nubapi_preview = nubapi_preview[:3000]

        return jsonify({
            "status": "error",
            "message": "Invalid response from NubAPI",
            "nubapi_preview": nubapi_preview
        }), 502

    except requests.exceptions.RequestException as re:
        print("NubAPI request exception:", str(re), flush=True)
        return jsonify({"status": "error", "message": f"Request failed: {str(re)}"}), 502
    except Exception as e:
        print("resolve_account unexpected exception:", str(e), flush=True)
        traceback.print_exc()
        return jsonify({"status": "error", "message": f"Internal error: {str(e)}"}), 500

# ---------- End of replacement code ----------

# -------------------------------------------------
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

