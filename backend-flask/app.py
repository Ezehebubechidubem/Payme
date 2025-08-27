from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import os
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent
DB_FILE = BASE_DIR / "users.json"

app = Flask(__name__)
CORS(app)

if DB_FILE.exists():
    try:
        with DB_FILE.open("r", encoding="utf-8") as f:
            users = json.load(f)
    except:
        users = []
else:
    users = []

def save_users():
    with DB_FILE.open("w", encoding="utf-8") as f:
        json.dump(users, f, indent=2, ensure_ascii=False)

def digits_only(s): return "".join(c for c in (s or "") if c.isdigit())
def account_number_from_phone(phone): return digits_only(phone)[-10:] if len(digits_only(phone))>=10 else None
def find_user_by_id(uid): return next((u for u in users if int(u.get("id",0))==int(uid)), None)
def find_user_by_account(acc): return next((u for u in users if u.get("accountNumber")==str(acc)), None)
def is_unique(username,email,phone,acc):
    for u in users:
        if u.get("username","").lower()==(username or "").lower() or u.get("email","").lower()==(email or "").lower() or u.get("phone")==phone or u.get("accountNumber")==acc: return False
    return True
def next_id():
    try: return max(int(u.get("id",0)) for u in users)+1
    except: return 1
def now_iso(): return datetime.utcnow().isoformat()+"Z"

@app.route("/")
def home(): return jsonify({"message":"PayMe API running"}), 200

@app.route("/register", methods=["POST"])
def register():
    data=request.get_json() or {}
    username,email,phone,password=data.get("username"),data.get("email"),data.get("phone"),data.get("password")
    if not username or not email or not phone or not password: return jsonify({"message":"All fields required"}),400
    acc=account_number_from_phone(phone)
    phone_digits=digits_only(phone)
    if not acc or len(acc)!=10 or not is_unique(username,email,phone_digits,acc): return jsonify({"message":"Invalid or duplicate info"}),400
    user={"id":next_id(),"username":username,"email":email,"phone":phone_digits,"accountNumber":acc,"password":password,"balance":0,"transactions":[]}
    users.append(user); save_users()
    safe_user={k:v for k,v in user.items() if k!="password"}
    return jsonify({"message":"Registration successful","user":safe_user}),201

@app.route("/login", methods=["POST"])
def login():
    data=request.get_json() or {}
    email,password=data.get("email"),data.get("password")
    if not email or not password: return jsonify({"message":"Email & password required"}),400
    user=next((u for u in users if u.get("email","").lower()==email.lower() and u.get("password")==password), None)
    if not user: return jsonify({"message":"Invalid credentials"}),400
    safe_user={k:v for k,v in user.items() if k!="password"}
    return jsonify({"message":"Login successful","user":safe_user}),200

@app
