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

# -------------------------
# BANKS (full list you provided)
# -------------------------
BANKS = {
    "000034":"SIGNATURE BANK","000036":"OPTIMUS BANK","000001":"STERLING BANK","000002":"KEYSTONE BANK",
    "000003":"FIRST CITY MONUMENT BANK","000004":"UNITED BANK FOR AFRICA","000006":"JAIZ BANK","000007":"FIDELITY BANK",
    "000008":"POLARIS BANK","000009":"CITI BANK","000010":"ECOBANK","000011":"UNITY BANK","000012":"STANBIC IBTC BANK",
    "000013":"GTBANK PLC","000014":"ACCESS BANK","000015":"ZENITH BANK","000016":"FIRST BANK OF NIGERIA",
    "000017":"WEMA BANK","000018":"UNION BANK","000019":"ENTERPRISE BANK","000021":"STANDARD CHARTERED BANK",
    "000022":"SUNTRUST BANK","000023":"PROVIDUS BANK","060001":"CORONATION MERCHANT BANK","070001":"NPF MICROFINANCE BANK",
    "070002":"FORTIS MICROFINANCE BANK","070008":"PAGE MFBANK","090001":"ASO SAVINGS","090003":"JUBILEE LIFE",
    "090006":"SAFETRUST","090107":"FIRST TRUST MORTGAGE BANK PLC","090108":"NEW PRUDENTIAL BANK","100002":"PAGA",
    "100003":"PARKWAY-READYCASH","100005":"CELLULANT","100006":"ETRANZACT","100007":"STANBIC IBTC @EASE WALLET",
    "100008":"ECOBANK XPRESS ACCOUNT","100009":"GT MOBILE","100010":"TEASY MOBILE","090267":"KUDA MICROFINANCE BANK",
    "100012":"VT NETWORKS","100036":"KEGOW(CHAMSMOBILE)","100039":"PAYSTACK-TITAN","100016":"FORTIS MOBILE",
    "100017":"HEDONMARK","100018":"ZENITH MOBILE","100019":"FIDELITY MOBILE","100020":"MONEY BOX",
    "100021":"EARTHOLEUM","100022":"STERLING MOBILE","100023":"TAGPAY","100024":"IMPERIAL HOMES MORTGAGE BANK",
    "999999":"NIP VIRTUAL BANK","090111":"FINATRUST MICROFINANCE BANK","090112":"SEED CAPITAL MICROFINANCE BANK",
    "090115":"IBANK MICROFINANCE BANK","090114":"EMPIRE TRUST MICROFINANCE BANK","090113":"MICROVIS MICROFINANCE BANK ",
    "090116":"AMML MICROFINANCE BANK ","090117":"BOCTRUST MICROFINANCE BANK LIMITED","090120":"WETLAND  MICROFINANCE BANK",
    "090118":"IBILE MICROFINANCE BANK","090125":"REGENT MICROFINANCE BANK","090128":"NDIORAH MICROFINANCE BANK",
    "090127":"BC KASH MICROFINANCE BANK","090121":"HASAL MICROFINANCE BANK","060002":"FBNQUEST MERCHANT BANK",
    "090132":"RICHWAY MICROFINANCE BANK","090135":"PERSONAL TRUST MICROFINANCE BANK","090136":"MICROCRED MICROFINANCE BANK",
    "090122":"GOWANS MICROFINANCE BANK","000024":"RAND MERCHANT BANK","090142":"YES MICROFINANCE BANK",
    "090140":"SAGAMU MICROFINANCE BANK","090129":"MONEY TRUST MICROFINANCE BANK","070012":"LAGOS BUILDING AND INVESTMENT COMPANY",
    "070009":"GATEWAY MORTGAGE BANK","070010":"ABBEY MORTGAGE BANK","070014":"FIRST GENERATION MORTGAGE BANK",
    "070013":"PLATINUM MORTGAGE BANK","070016":"INFINITY TRUST MORTGAGE BANK","090119":"OHAFIA MICROFINANCE BANK",
    "090124":"XSLNCE MICROFINANCE BANK","090130":"CONSUMER MICROFINANCE BANK","090131":"ALLWORKERS MICROFINANCE BANK",
    "090134":"ACCION MICROFINANCE BANK","090139":"VISA MICROFINANCE BANK","090141":"CHIKUM MICROFINANCE BANK",
    "090143":"APEKS MICROFINANCE BANK","090144":"CIT MICROFINANCE BANK","090145":"FULLRANGE MICROFINANCE BANK","090153":"FFS MICROFINANCE BANK",
    "090160":"ADDOSSER MICROFINANCE BANK","090126":"FIDFUND MICROFINANCE BANK","100028":"AG MORTGAGE BANK",
    "090137":"PECANTRUST MICROFINANCE BANK","090148":"BOWEN MICROFINANCE BANK","090158":"FUTO MICROFINANCE BANK",
    "070011":"REFUGE MORTGAGE BANK","070015":"BRENT MORTGAGE BANK","090138":"ROYAL EXCHANGE MICROFINANCE BANK",
    "090147":"HACKMAN MICROFINANCE BANK","090146":"TRIDENT MICROFINANCE BANK","090157":"INFINITY MICROFINANCE BANK",
    "090159":"CREDIT AFRIQUE MICROFINANCE BANK","090156":"E-BARCS MICROFINANCE BANK","090110":"VFD MFB","100030":"ECOMOBILE",
    "100029":"INNOVECTIVES KESH","090097":"EKONDO MICROFINANCE BANK","090150":"VIRTUE MICROFINANCE BANK","090149":"IRL MICROFINANCE BANK",
    "100031":"FCMB MOBILE","090151":"MUTUAL TRUST MICROFINANCE BANK","090161":"OKPOGA MICROFINANCE BANK","060003":"NOVA MERCHANT BANK",
    "090154":"CEMCS MICROFINANCE BANK","090167":"DAYLIGHT MICROFINANCE BANK","070017":"HAGGAI MORTGAGE BANK LIMITED",
    "090171":"MAINSTREET MICROFINANCE BANK","090178":"GREENBANK MICROFINANCE BANK","090179":"FAST MICROFINANCE BANK","090177":"LAPO MICROFINANCE BANK",
    "000020":"HERITAGE BANK","090251":"UNIVERSITY OF NIGERIA, NSUKKA MICROFINANCE BANK","090196":"PENNYWISE MICROFINANCE BANK ",
    "090197":"ABU MICROFINANCE BANK ","090194":"NIRSAL NATIONAL MICROFINANCE BANK","090176":"BOSAK MICROFINANCE BANK","090172":"ASTRAPOLARIS MICROFINANCE BANK",
    "090261":"QUICKFUND MICROFINANCE BANK","090259":"ALEKUN MICROFINANCE BANK","090198":"RENMONEY MICROFINANCE BANK ","090262":"STELLAS MICROFINANCE BANK ",
    "090205":"NEW DAWN MICROFINANCE BANK","090169":"ALPHA KAPITAL MICROFINANCE BANK ","090264":"AUCHI MICROFINANCE BANK ","090270":"AB MICROFINANCE BANK ",
    "090263":"NIGERIAN NAVY MICROFINANCE BANK ","090258":"IMO STATE MICROFINANCE BANK","090276":"TRUSTFUND MICROFINANCE BANK ","090706":"UCEE MFB",
    "090701":"ISUA MFB","090708":"TransPay MICROFINANCE BANK ","090445":"CAPSTONE MF BANK","090596":"DAL MICROFINANCE BANK ","000040":"UBA MONI",
    "090710":"ILE-OLUJI MICROFINANCE BANK","090716":"TENN MICROFINANCE BANK","090725":"IHALA MICROFINANCE BANK","050019":"ZEDVANCE FINANCE LIMITED",
    "090700":"OMAK MICROFINANCE BANK","090698":"AKALABO MICROFINANCE BANK ","090195":"GROOMING MICROFINANCE BANK","090714":"TOFA MICROFINANCE BANK",
    "090712":"EMAAR MICROFINANCE BANK","090711":"THE MILLENNIUM MICROFINANCE BANK","090260":"ABOVE ONLY MICROFINANCE BANK ","090272":"OLABISI ONABANJO UNIVERSITY MICROFINANCE ",
    "090268":"ADEYEMI COLLEGE STAFF MICROFINANCE BANK","090280":"MEGAPRAISE MICROFINANCE BANK","000026":"TAJ BANK","090282":"ARISE MICROFINANCE BANK",
    "090274":"PRESTIGE MICROFINANCE BANK","090278":"GLORY MICROFINANCE BANK","090188":"BAINES CREDIT MICROFINANCE BANK","000005":"ACCESS(DIAMOND) BANK",
    "090289":"PILLAR MICROFINANCE BANK","090286":"SAFE HAVEN MICROFINANCE BANK","090292":"AFEKHAFE MICROFINANCE BANK","000027":"GLOBUS BANK",
    "090285":"FIRST OPTION MICROFINANCE BANK","090296":"POLYUNWANA MICROFINANCE BANK","090295":"OMIYE MICROFINANCE BANK","090287":"ASSETMATRIX MICROFINANCE BANK",
    "000025":"TITAN TRUST BANK","090271":"LAVENDER MICROFINANCE BANK","090290":"FCT MICROFINANCE BANK","090279":"IKIRE MICROFINANCE BANK","090303":"PURPLEMONEY MICROFINANCE BANK",
    "100052":"ACCESS YELLO & BETA","090123":"TRUSTBANC J6 MICROFINANCE BANK LIMITED","090305":"SULSPAP MICROFINANCE BANK","090166":"ESO-E MICROFINANCE BANK",
    "090273":"EMERALD MICROFINANCE BANK","100013":"ACCESS MONEY","090297":"ALERT MICROFINANCE BANK","090308":"BRIGHTWAY MICROFINANCE BANK","100033":"PALMPAY",
    "090325":"SPARKLE","090326":"BALOGUN GAMBARI MICROFINANCE BANK","090317":"PATRICKGOLD MICROFINANCE BANK","070019":"MAYFRESH MORTGAGE BANK",
    "090327":"TRUST MICROFINANCE BANK","090133":"AL-BARAKAH MICROFINANCE BANK","090328":"EYOWO","090304":"EVANGEL MICROFINANCE BANK ","090332":"EVERGREEN MICROFINANCE BANK",
    "090333":"OCHE MICROFINANCE BANK","090364":"NUTURE MICROFINANCE BANK","100014":"FIRSTMONIE WALLET","090329":"NEPTUNE MICROFINANCE BANK","090315":"U & C MICROFINANCE BANK",
    "090331":"UNAAB MICROFINANCE BANK","090324":"IKENNE MICROFINANCE BANK","090321":"MAYFAIR MICROFINANCE BANK","090322":"REPHIDIM MICROFINANCE BANK",
    "090299":"KONTAGORA MICROFINANCE BANK","090360":"CASHCONNECT MICROFINANCE BANK","090336":"BIPC MICROFINANCE BANK","090362":"MOLUSI MICROFINANCE BANK",
    "090372":"LEGEND MICROFINANCE BANK","090369":"SEEDVEST MICROFINANCE BANK","090294":"EAGLE FLIGHT MICROFINANCE BANK","090373":"THINK FINANCE MICROFINANCE BANK",
    "100001":"FETS","090374":"COASTLINE MICROFINANCE BANK","090281":"MINT-FINEX MFB","090363":"HEADWAY MICROFINANCE BANK","090377":"ISALEOYO MICROFINANCE BANK",
    "090378":"NEW GOLDEN PASTURES MICROFINANCE BANK","400001":"FSDH","090365":"CORESTEP MICROFINANCE BANK","090298":"FEDPOLY NASARAWA MICROFINANCE BANK",
    "090366":"FIRMUS MICROFINANCE BANK","090383":"MANNY MICROFINANCE BANK","090391":"DAVODANI  MICROFINANCE BANK","090389":"EK-RELIABLE MICROFINANCE BANK",
    "090385":"GTI MICROFINANCE BANK","090252":"YOBE MICROFINANCE  BANK","120001":"9 PAYMENT SOLUTIONS BANK","100004":"OPAY","090175":"RUBIES MICROFINANCE BANK",
    "090392":"MOZFIN MICROFINANCE BANK","090386":"INTERLAND MICROFINANCE BANK","090400":"FINCA MICROFINANCE BANK","100025":"KONGAPAY",
    "090370":"ILISAN MICROFINANCE BANK","090399":"NWANNEGADI MICROFINANCE BANK","090186":"GIREI MICROFINANACE BANK","090396":"OSCOTECH MICROFINANCE BANK",
    "090393":"BRIDGEWAY MICROFINANACE BANK","090380":"KREDI MONEY MICROFINANCE BANK ","090401":"SHERPERD TRUST MICROFINANCE BANK","100032":"NOWNOW DIGITAL SYSTEMS LIMITED",
    "090394":"AMAC MICROFINANCE BANK","070007":"LIVINGTRUST MORTGAGE BANK PLC","100035":"M36","090283":"NNEW WOMEN MICROFINANCE BANK ","090408":"GMB MICROFINANCE BANK",
    "090005":"TRUSTBOND MORTGAGE BANK","090152":"NAGARTA MICROFINANCE BANK","090155":"ADVANS LA FAYETTE  MICROFINANCE BANK","090162":"STANFORD MICROFINANCE BANK",
    "090164":"FIRST ROYAL MICROFINANCE BANK","090165":"PETRA MICROFINANCE BANK","090168":"GASHUA MICROFINANCE BANK","090173":"RELIANCE MICROFINANCE BANK",
    "090174":"MALACHY MICROFINANCE BANK","090180":"AMJU UNIQUE MICROFINANCE BANK","090189":"ESAN MICROFINANCE BANK","090190":"MUTUAL BENEFITS MICROFINANCE BANK",
    "090191":"KCMB MICROFINANCE BANK","090192":"MIDLAND MICROFINANCE BANK","090193":"UNICAL MICROFINANCE BANK","090265":"LOVONUS MICROFINANCE BANK",
    "090266":"UNIBEN MICROFINANCE BANK","090269":"GREENVILLE MICROFINANCE BANK","090277":"AL-HAYAT MICROFINANCE BANK","090293":"BRETHREN MICROFINANCE BANK",
    "090310":"EDFIN MICROFINANCE BANK","090318":"FEDERAL UNIVERSITY DUTSE MICROFINANCE BANK","090320":"KADPOLY MICROFINANCE BANK","090323":"MAINLAND MICROFINANCE BANK",
    "090376":"APPLE MICROFINANCE BANK","090395":"BORGU  MICROFINANCE BANK","090398":"FEDERAL POLYTECHNIC NEKEDE MICROFINANCE BANK","090404":"OLOWOLAGBA MICROFINANCE BANK",
    "090406":"BUSINESS SUPPORT MICROFINANCE BANK","090202":"ACCELEREX NETWORK LIMITED","120002":"HOPEPSB","090316":"BAYERO UNIVERSITY MICROFINANCE BANK",
    "090410":"MARITIME MICROFINANCE BANK","090371":"AGOSASA MICROFINANCE BANK","100034":"ZENITH EASY WALLET","070021":"COOP MORTGAGE BANK",
    "100026":"CARBON","090435":"LINKS MICROFINANCE BANK","090433":"RIGO MICROFINANCE BANK","090402":"PEACE MICROFINANCE BANK","090436":"SPECTRUM MICROFINANCE BANK ",
    "060004":"GREENWICH MERCHANT BANK","000029":"LOTUS BANK","090426":"TANGERINE MONEY","000030":"PARALLEX BANK","090448":"Moyofade MF Bank","000031":"PREMIUM TRUST  BANK",
    "090449":"REX  Microfinance Bank","090450":"Kwasu MF Bank","090451":"ATBU  Microfinance Bank","090452":"UNILAG  Microfinance Bank","090453":"Uzondu MF Bank",
    "090454":"Borstal Microfinance Bank","090471":"Oluchukwu Microfinance Bank","090472":"Caretaker Microfinance Bank","090473":"Assets Microfinance Bank","090709":"FOCUS MFB",
    "090605":"MADOBI MFB","090474":"Verdant Microfinance Bank","090475":"Giant Stride Microfinance Bank","090476":"Anchorage Microfinance Bank","090477":"Light Microfinance Bank",
    "090478":"Avuenegbe Microfinance Bank","090479":"First Heritage Microfinance Bank","090480":"KOLOMONI MICROFINANCE BANK","090481":"Prisco  Microfinance Bank",
    "090483":"Ada Microfinance Bank","090484":"Garki Microfinance Bank","090485":"SAFEGATE MICROFINANCE BANK","090486":"Fortress Microfinance Bank","090487":"Kingdom College  Microfinance Bank",
    "090488":"Ibu-Aje Microfinance","090489":"Alvana Microfinance Bank","090455":"MKOBO MICROFINANCE BANK LTD","090456":"Ospoly Microfinance Bank","090459":"Nice Microfinance Bank",
    "090460":"Oluyole Microfinance Bank","090461":"Uniibadan Microfinance Bank","090462":"Monarch Microfinance Bank","090463":"Rehoboth Microfinance Bank","090464":"UNIMAID MICROFINANCE BANK",
    "090465":"Maintrust Microfinance Bank","090466":"YCT MICROFINANCE BANK","090467":"Good Neighbours Microfinance Bank","090468":"Olofin Owena Microfinance Bank","090469":"Aniocha Microfinance Bank",
    "090446":"SUPPORT MICROFINANCE BANK","000028":"CBN","090482":"CLEARPAY MICROFINANCE BANK","090470":"DOT MICROFINANCE BANK","090504":"ZIKORA MICROFINANCE BANK",
    "090506":"SOLID ALLIANZE MICROFINANCE BANK","120004":"SMARTCASH PAYMENT SERVICE BANK","090405":"MONIEPOINT MICROFINANCE BANK","070024":"HOMEBASE MORTGAGE BANK","120003":"MOMO PAYMENT SERVICE BANK ",
    "090490":"Chukwunenye  Microfinance Bank","090491":"Nsuk  Microfinance Bank","090492":"Oraukwu  Microfinance Bank","090493":"Iperu Microfinance Bank","090494":"Boji Boji Microfinance Bank",
    "090495":"Prospa Capital MICROFINANCE BANK","090496":"Radalpha Microfinance Bank","090497":"Palmcoast Microfinance Bank","090498":"Catland Microfinance Bank","090499":"Pristine Divitis Microfinance Bank",
    "050002":"FEWCHORE FINANCE COMPANY LIMITED","070006":"COVENANT MICROFINANCE BANK","090500":"Gwong Microfinance Bank","090501":"Boromu Microfinance Bank","090502":"Shalom Microfinance Bank",
    "090503":"Projects Microfinance Bank","090505":"Nigeria Prisons Microfinance Bank","090507":"Fims Microfinance Bank","090508":"Borno Renaissance Microfinance Bank",
    "090509":"Capitalmetriq Swift Microfinance Bank","090510":"Umunnachi Microfinance Bank","090511":"Cloverleaf  Microfinance Bank","090512":"Bubayero Microfinance Bank","090513":"Seap Microfinance Bank",
    "090514":"Umuchinemere Procredit Microfinance Bank","090515":"Rima Growth Pathway Microfinance Bank ","090516":"Numo Microfinance Bank","090517":"Uhuru Microfinance Bank",
    "090518":"Afemai Microfinance Bank","090519":"Ibom Fadama Microfinance Bank","090520":"IC Globalmicrofinance Bank","090521":"Foresight Microfinance Bank","090523":"Chase Microfinance Bank",
    "090524":"Solidrock Microfinance Bank","090525":"Triple A Microfinance Bank","090526":"Crescent Microfinance Bank","090527":"Ojokoro Microfinance Bank","090528":"Mgbidi Microfinance Bank",
    "090529":"Bankly Microfinance Bank","090530":"Confidence Microfinance Bank Ltd","090531":"Aku Microfinance Bank","090532":"Ibolo Micorfinance Bank Ltd","090534":"PolyIbadan Microfinance Bank",
    "090535":"Nkpolu-Ust Microfinance","090536":"Ikoyi-Osun Microfinance Bank","090537":"Lobrem Microfinance Bank","090538":"Blue Investments Microfinance Bank",
    "090539":"Enrich Microfinance Bank","090540":"Aztec Microfinance Bank","090541":"Excellent Microfinance Bank","090542":"Otuo Microfinance Bank Ltd","090543":"Iwoama Microfinance Bank",
    "090544":"Aspire Microfinance Bank Ltd","090545":"Abulesoro Microfinance Bank Ltd","090546":"Ijebu-Ife Microfinance Bank Ltd","090547":"Rockshield Microfinance Bank",
    "090548":"Ally Microfinance Bank","090549":"Kc Microfinance Bank","090550":"Green Energy Microfinance Bank Ltd","090551":"Fairmoney Microfinance Bank Ltd","090552":"Ekimogun Microfinance Bank","090553":"Consistent Trust Microfinance Bank Ltd","090554":"Kayvee Microfinance Bank","090555":"Bishopgate Microfinance Bank","090556":"Egwafin Microfinance Bank Ltd","090557":"Lifegate Microfinance Bank Ltd","090558":"Shongom Microfinance Bank Ltd","090559":"Shield Microfinance Bank Ltd","090560":"TANADI MFB (CRUST)","090561":"Akuchukwu Microfinance Bank Ltd","090562":"Cedar Microfinance Bank Ltd","090563":"Balera Microfinance Bank Ltd","090564":"Supreme Microfinance Bank Ltd","090565":"Oke-Aro Oredegbe Microfinance Bank Ltd","090566":"Okuku Microfinance Bank Ltd","090567":"Orokam Microfinance Bank Ltd","090568":"Broadview Microfinance Bank Ltd","090569":"Qube Microfinance Bank Ltd","090570":"Iyamoye Microfinance Bank Ltd","090571":"Ilaro Poly Microfinance Bank Ltd","090572":"Ewt Microfinance Bank","090573":"Snow Microfinance Bank","090574":"GOLDMAN MICROFINANCE BANK","090575":"Firstmidas Microfinance Bank Ltd","090576":"Octopus Microfinance Bank Ltd","090578":"Iwade Microfinance Bank Ltd","090579":"Gbede Microfinance Bank","090580":"Otech Microfinance Bank Ltd","090581":"BANC CORP MICROFINANCE BANK","090583":"STATESIDE MFB","090584":"Island MFB","090586":"GOMBE MICROFINANCE BANK LTD","090587":"Microbiz Microfinance Bank","090588":"Orisun MFB","090589":"Mercury MFB","090590":"WAYA MICROFINANCE BANK LTD","090591":"Gabsyn Microfinance Bank","090592":"KANO POLY MFB","090593":"TASUED MICROFINANCE BANK LTD","090598":"IBA MFB ","090599":"Greenacres MFB","090600":"AVE MARIA MICROFINANCE BANK LTD","090602":"KENECHUKWU MICROFINANCE BANK","090603":"Macrod MFB","090606":"KKU Microfinance Bank","090608":"Akpo Microfinance Bank","090609":"Ummah Microfinance Bank ","090610":"AMOYE MICROFINANCE BANK","090611":"Creditville Microfinance Bank","090612":"Medef Microfinance Bank","090613":"Total Trust Microfinance Bank","090614":"AELLA MFB","090615":"Beststar Microfinance Bank","090616":"RAYYAN Microfinance Bank","090620":"Iyin Ekiti MFB","090621":"GIDAUNIYAR ALHERI MICROFINANCE BANK","090623":"Mab Allianz MFB","090649":"CASHRITE MICROFINANCE BANK","090657":"PYRAMID MICROFINANCE BANK","090659":"MICHAEL OKPARA UNIAGRIC MICROFINANCE BANK","090424":"ABUCOOP  MICROFINANCE BANK","070025":"AKWA SAVINGS & LOANS LIMITED","000037":"ALTERNATIVE BANK LIMITED","090307":"ARAMOKO MICROFINANCE BANK","090181":"BALOGUN FULANI  MICROFINANCE BANK","090425":"BANEX MICROFINANCE BANK","090413":"BENYSTA MICROFINANCE BANK","090431":"BLUEWHALES  MICROFINANCE BANK","090444":"BOI MF BANK","090319":"BONGHE MICROFINANCE BANK","050006":"Branch International Finance Company Limited","090415":"CALABAR MICROFINANCE BANK","999001":"CBN_TSA","090397":"CHANELLE BANK","090440":"CHERISH MICROFINANCE BANK","090416":"CHIBUEZE MICROFINANCE BANK","090343":"CITIZEN TRUST MICROFINANCE BANK LTD","090254":"COALCAMP MICROFINANCE BANK","050001":"COUNTY FINANCE LTD","090429":"CROSSRIVER  MICROFINANCE BANK","090414":"CRUTECH  MICROFINANCE BANK","070023":"DELTA TRUST MORTGAGE BANK","050013":"DIGNITY FINANCE","090427":"EBSU MICROFINANCE BANK","000033":"ENAIRA","050012":"ENCO FINANCE","090330":"FAME MICROFINANCE BANK","050009":"FAST CREDIT","090409":"FCMB MICROFINANCE BANK","070026":"FHA MORTGAGE BANK LTD","090163":"FIRST MULTIPLE MICROFINANCE BANK","050010":"FUNDQUEST FINANCIAL SERVICES LTD","090438":"FUTMINNA MICROFINANCE BANK","090411":"GIGINYA MICROFINANCE BANK","090441":"GIWA MICROFINANCE BANK","090335":"GRANT MF BANK","090291":"HALACREDIT MICROFINANCE BANK","090418":"HIGHLAND MICROFINANCE BANK","050005":"AAA FINANCE","090439":"IBETO  MICROFINANCE BANK","090350":"ILLORIN MICROFINANCE BANK","090430":"ILORA MICROFINANCE BANK","090417":"IMOWO MICROFINANCE BANK","090434":"INSIGHT MICROFINANCE BANK","090428":"ISHIE  MICROFINANCE BANK","090353":"ISUOFIA MICROFINANCE BANK","090211":"ITEX INTEGRATED SERVICES LIMITED","090337":"IYERU OKIN MICROFINANCE BANK LTD","090421":"IZON MICROFINANCE BANK","090352":"JESSEFIELD MICROFINANCE BANK","090422":"LANDGOLD  MICROFINANCE BANK","090420":"LETSHEGO MFB","090423":"MAUTECH MICROFINANCE BANK","090432":"MEMPHIS MICROFINANCE BANK","090275":"MERIDIAN MICROFINANCE BANK","090349":"NASARAWA MICROFINANCE BANK","050004":"NEWEDGE FINANCE LTD","090676":"NUGGETS MFB","090437":"OAKLAND MICROFINANCE BANK","090345":"OAU MICROFINANCE BANK LTD","090390":"PARKWAY MF BANK","090004":"PARRALEX MICROFINANCE BANK","090379":"PENIEL MICORFINANCE BANK LTD","090412":"PREEMINENT MICROFINANCE BANK","090170":"RAHAMA MICROFINANCE BANK","090443":"RIMA MICROFINANCE BANK","050003":"SAGEGREY FINANCE LIMITED","050008":"SIMPLE FINANCE LIMITED","090182":"STANDARD MICROFINANCE BANK","100015":"KEGOW","100040":"XPRESS WALLET","070022":"STB MORTGAGE BANK","090340":"STOCKCORP  MICROFINANCE BANK","090302":"SUNBEAM MICROFINANCE BANK","080002":"TAJWALLET","050007":"TEKLA FINANCE LTD","050014":"TRINITY FINANCIAL SERVICES LIMITED","090403":"UDA MICROFINANCE BANK","090341":"UNILORIN MICROFINANCE BANK","090338":"UNIUYO MICROFINANCE BANK","050020":"VALE FINANCE LIMITED","090419":"WINVIEW BANK","090631":"WRA MICROFINANCE BANK"

 
    # 👉 Add the full NubAPI list you have here (or leave as-is if you prefer)
}

# GET /banks (unchanged)
@app.route("/banks", methods=["GET"])
def get_banks():
    return jsonify(BANKS), 200


# -------------------------
# helper: normalize bank code
# -------------------------
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

    # 2) same numeric removing leading zeros -> match keys after removing leading zeros
    s_num = s.lstrip("0")
    if s_num:
        for k in BANKS:
            if k.lstrip("0") == s_num:
                return k

    # 3) try by bank name substring (case-insensitive)
    s_up = s.upper()
    for k, v in BANKS.items():
        if s_up in v.upper() or v.upper() in s_up:
            return k

    return None
 

# -------------------------
# Resolve Account (GET + POST)
# -------------------------
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

    # Input handling (GET or POST)
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        account_number = str(data.get("account_number", "")).strip()
        bank_code = str(data.get("bank_code", "")).strip()
    else:
        account_number = str(request.args.get("account_number", "")).strip()
        bank_code = str(request.args.get("bank_code", "")).strip()

    # Basic validation
    if not account_number.isdigit() or len(account_number) != 10:
        return jsonify({"status": "error", "message": "Invalid account number"}), 400
    if bank_code not in BANKS:
        return jsonify({"status": "error", "message": "Unknown bank code"}), 400

    # Read key from env (try multiple names in case)
    NUBAPI_KEY = os.environ.get("NUBAPI_KEY") or os.environ.get("NUBAPI_API") or os.environ.get("NUPABI_API")
    if not NUBAPI_KEY:
        return jsonify({"status": "error", "message": "NUBAPI_KEY not set"}), 500

    nubapi_url = "https://nubapi.com/api/verify"
    # helper: try to parse JSON safely
    def try_parse_json(resp):
        try:
            return resp.json(), None
        except ValueError:
            # non-JSON: return None plus a short preview of text
            text = resp.text or ""
            preview = text[:3000]
            return None, preview

    try:
        # 1) Try header-based Bearer auth first (preferred)
        headers = {
            "Authorization": f"Bearer {NUBAPI_KEY}",
            "Accept": "application/json",
            "User-Agent": "PayMe/1.0"
        }
        params = {"account_number": account_number, "bank_code": bank_code}

        res = requests.get(nubapi_url, headers=headers, params=params, timeout=12)
        print("NubAPI (header) status:", res.status_code, flush=True)
        print("NubAPI (header) headers:", dict(res.headers), flush=True)
        # don't print full body to logs, but short preview for debugging
        print("NubAPI (header) body preview:", (res.text or "")[:1000], flush=True)

        # If we got 200, try parse JSON
        if res.status_code == 200:
            data, preview = try_parse_json(res)
            if data:
                # NubAPI returned JSON
                if data.get("status") == "success" and data.get("account_name"):
                    return jsonify({
                        "status": "success",
                        "account_name": data["account_name"],
                        "account_number": account_number,
                        "bank_code": bank_code
                    }), 200
                # JSON but unsuccessful
                return jsonify({
                    "status": "error",
                    "message": data.get("message", "Unable to verify account"),
                    "raw": data
                }), 400
            else:
                # non-JSON body; fall through to query param fallback
                header_preview = preview
        else:
            header_preview = (res.text or "")[:3000]

        # 2) Fallback: try query param style with api_key in URL (older style)
        url_with_key = f"{nubapi_url}?account_number={account_number}&bank_code={bank_code}&api_key={NUBAPI_KEY}"
        res2 = requests.get(url_with_key, timeout=12, headers={"Accept": "application/json", "User-Agent": "PayMe/1.0"})
        print("NubAPI (query) status:", res2.status_code, flush=True)
        print("NubAPI (query) body preview:", (res2.text or "")[:1000], flush=True)

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

        # If we get here, neither attempt returned JSON success. Return previews for diagnosis.
        # Prefer to return the JSON preview if available; otherwise return the header/query previews.
        nubapi_preview = None
        if 'preview2' in locals() and preview2:
            nubapi_preview = preview2
        elif 'preview' in locals() and preview:
            nubapi_preview = preview
        else:
            # fallback to combined short text
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

