"""EcoClaim server.

Serves the claim form (Mileage-Expenses-Claim-Form.html) and keeps users and claims in a shared
database, so everyone signs in to the same system. Every permission rule is enforced here.

Database: PostgreSQL when DATABASE_URL is set (Railway), otherwise a local SQLite file.
Run locally:   python app.py            -> http://127.0.0.1:8000
On Railway:    gunicorn app:app (see railway.json)
"""
import hashlib
import json
import os
import re
import secrets
import sqlite3
import time
import uuid
from datetime import date, datetime, timezone
from functools import wraps

from flask import Flask, g, jsonify, request, send_file

BASE = os.path.dirname(os.path.abspath(__file__))
PAGE = os.path.join(BASE, "Mileage-Expenses-Claim-Form.html")
DATABASE_URL = os.environ.get("DATABASE_URL", "")
USE_PG = DATABASE_URL.startswith(("postgres://", "postgresql://"))
ON_RAILWAY = bool(os.environ.get("RAILWAY_PROJECT_ID"))
SETUP_KEY = os.environ.get("SETUP_KEY", "")
SECURE_COOKIE = ON_RAILWAY or os.environ.get("SECURE_COOKIE") == "1"
COOKIE = "ecoclaim_session"
IDLE_SECONDS = 30 * 60
MAX_SESSION_SECONDS = 12 * 3600
PBKDF2_ITERATIONS = 150_000  # same scheme the browser-only version used, so old backups keep their passwords
ROLES = ("staff", "hod", "approver", "admin")
STATUSES = ("draft", "pending", "approved", "rejected")
DEFAULT_SETTINGS = {
    "company": "LVC EcoPack Sdn Bhd", "rate": 0.5, "seq": 1, "notify": True, "demo": False,
    "departments": ["Sales", "Operations", "Logistics", "Finance", "Admin", "Management"],
}
DEMO_PW = "Demo1234"

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

# ---------------------------------------------------------------- database

if USE_PG:
    import psycopg


def connect():
    if USE_PG:
        return psycopg.connect(DATABASE_URL)
    return sqlite3.connect(os.environ.get("SQLITE_PATH", os.path.join(BASE, "ecoclaim.db")), timeout=10)


def db():
    if "db" not in g:
        g.db = connect()
    return g.db


@app.teardown_request
def _close_db(exc):
    conn = g.pop("db", None)
    if conn is not None:
        if exc is None:
            conn.commit()
        else:
            conn.rollback()
        conn.close()


def q(sql, params=(), one=False):
    if USE_PG:
        sql = sql.replace("?", "%s")
    cur = db().cursor()
    cur.execute(sql, params)
    if cur.description is None:
        return None
    cols = [d[0] for d in cur.description]
    rows = [dict(zip(cols, r)) for r in cur.fetchall()]
    return (rows[0] if rows else None) if one else rows


SCHEMA = [
    "CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, data TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS claims (id TEXT PRIMARY KEY, data TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id TEXT NOT NULL, created DOUBLE PRECISION NOT NULL, seen DOUBLE PRECISION NOT NULL)",
    "CREATE TABLE IF NOT EXISTS locks (k TEXT PRIMARY KEY, n INTEGER NOT NULL, until DOUBLE PRECISION NOT NULL)",
]


def init_db():
    conn = connect()
    try:
        cur = conn.cursor()
        for stmt in SCHEMA:
            cur.execute(stmt)
        conn.commit()
    finally:
        conn.close()


init_db()


def load_users():
    return [json.loads(r["data"]) for r in q("SELECT data FROM users")]


def save_user(u):
    q("INSERT INTO users (id, username, data) VALUES (?, ?, ?) "
      "ON CONFLICT (id) DO UPDATE SET username = excluded.username, data = excluded.data",
      (u["id"], u["username"], json.dumps(u)))


def load_claims():
    return [json.loads(r["data"]) for r in q("SELECT data FROM claims")]


def get_claim(cid):
    r = q("SELECT data FROM claims WHERE id = ?", (cid,), one=True)
    return json.loads(r["data"]) if r else None


def save_claim(c):
    q("INSERT INTO claims (id, data) VALUES (?, ?) ON CONFLICT (id) DO UPDATE SET data = excluded.data",
      (c["id"], json.dumps(c)))


def get_settings():
    r = q("SELECT v FROM settings WHERE k = 'settings'", one=True)
    s = dict(DEFAULT_SETTINGS)
    if r:
        s.update(json.loads(r["v"]))
    return s


def save_settings(s):
    q("INSERT INTO settings (k, v) VALUES ('settings', ?) ON CONFLICT (k) DO UPDATE SET v = excluded.v", (json.dumps(s),))


# ---------------------------------------------------------------- helpers

def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def today():
    return date.today().isoformat()


def new_id():
    return uuid.uuid4().hex[:16]


def err(code, msg):
    return jsonify(ok=False, error=msg), code


def body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def s(v, limit=200):
    return str(v if v is not None else "").strip()[:limit]


def num(v):
    try:
        n = float(v)
        return n if n == n and abs(n) != float("inf") else 0.0
    except (TypeError, ValueError):
        return 0.0


ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
ISO_MONTH = re.compile(r"^\d{4}-\d{2}$")
USERNAME = re.compile(r"^[a-z0-9._-]{3,30}$")
EMAIL = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def iso_date(v):
    v = s(v, 10)
    return v if ISO_DATE.match(v) else ""


def pw_ok(pw):
    return len(pw) >= 8 and re.search(r"[A-Za-z]", pw) and re.search(r"\d", pw)


def hash_pw(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), PBKDF2_ITERATIONS).hex()


def set_pw(u, pw):
    u["salt"] = secrets.token_hex(16)
    u["passHash"] = hash_pw(pw, u["salt"])


def check_pw(u, pw):
    return bool(u.get("salt")) and secrets.compare_digest(hash_pw(pw, u["salt"]), u.get("passHash", ""))


def public_user(u):
    return {k: v for k, v in u.items() if k not in ("passHash", "salt")}


def directory_entry(u):
    return {k: u.get(k) for k in ("id", "name", "username", "email", "department", "role", "approveDepts", "active")}


# ---------------------------------------------------------------- permissions (mirrors the page)

def approve_depts(u):
    if u["role"] == "hod":
        return [u["department"]]
    if u["role"] == "approver":
        return u.get("approveDepts") or []
    return []


def owns(u, c):
    if c.get("ownerId"):
        return c["ownerId"] == u["id"]
    return s(c.get("claimant")).lower() == s(u.get("name")).lower()


def can_see(u, c):
    return u["role"] == "admin" or owns(u, c) or c.get("department") in approve_depts(u)


def can_approve(u, c):
    return c["status"] == "pending" and c.get("department") in approve_depts(u) and not owns(u, c)


def can_revoke(u, c):
    return c["status"] == "approved" and c.get("department") in approve_depts(u) and not owns(u, c)


def can_edit(u, c):
    return owns(u, c) and c["status"] in ("draft", "rejected")


def can_delete(u, c):
    return u["role"] == "admin" or (owns(u, c) and c["status"] in ("draft", "rejected"))


# ---------------------------------------------------------------- sessions

def token_hash(tok):
    return hashlib.sha256(tok.encode()).hexdigest()


def start_session(resp, u):
    tok = secrets.token_urlsafe(32)
    t = time.time()
    q("INSERT INTO sessions (token, user_id, created, seen) VALUES (?, ?, ?, ?)", (token_hash(tok), u["id"], t, t))
    resp.set_cookie(COOKIE, tok, httponly=True, secure=SECURE_COOKIE, samesite="Lax", max_age=MAX_SESSION_SECONDS)
    return resp


def end_session(resp):
    tok = request.cookies.get(COOKIE)
    if tok:
        q("DELETE FROM sessions WHERE token = ?", (token_hash(tok),))
    resp.delete_cookie(COOKIE)
    return resp


def current_user():
    if "user" in g:
        return g.user
    g.user = None
    tok = request.cookies.get(COOKIE)
    if not tok:
        return None
    h, t = token_hash(tok), time.time()
    row = q("SELECT user_id, created, seen FROM sessions WHERE token = ?", (h,), one=True)
    if not row:
        return None
    if t - row["seen"] > IDLE_SECONDS or t - row["created"] > MAX_SESSION_SECONDS:
        q("DELETE FROM sessions WHERE token = ?", (h,))
        return None
    u = next((x for x in load_users() if x["id"] == row["user_id"] and x.get("active", True)), None)
    if u:
        q("UPDATE sessions SET seen = ? WHERE token = ?", (t, h))
    g.user = u
    return u


def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not current_user():
            return err(401, "Your session has ended. Please sign in again.")
        return f(*a, **kw)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        u = current_user()
        if not u:
            return err(401, "Your session has ended. Please sign in again.")
        if u["role"] != "admin":
            return err(403, "Administrator only.")
        return f(*a, **kw)
    return wrapper


@app.before_request
def csrf_guard():
    # browsers can't add this header cross-site without CORS approval, which this server never grants
    if request.path.startswith("/api/") and request.method != "GET" and request.headers.get("X-Requested-With") != "EcoClaim":
        return err(403, "Bad request origin.")


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


# ---------------------------------------------------------------- claims

ITEM_KEYS = ("date", "from", "to", "km", "toll", "parking", "other", "desc", "receipt")


def clean_items(items):
    out = []
    for it in (items if isinstance(items, list) else [])[:300]:
        if not isinstance(it, dict):
            continue
        row = {"id": s(it.get("id"), 40) or new_id(), "date": iso_date(it.get("date"))}
        for k in ("from", "to", "receipt"):
            row[k] = s(it.get(k), 120)
        row["desc"] = s(it.get("desc"), 500)
        for k in ("km", "toll", "parking", "other"):
            v = s(it.get(k), 20)
            row[k] = v if v == "" or num(v) or v in ("0", "0.0", "0.00") else ""
        if any(row[k] not in ("", None) for k in ITEM_KEYS):
            out.append(row)
    return out


def totals(c):
    km = sum(num(i.get("km")) for i in c["items"])
    other = sum(num(i.get("toll")) + num(i.get("parking")) + num(i.get("other")) for i in c["items"])
    return round(km * num(c.get("rate")) + other, 2)


def apply_fields(c, d):
    c["claimName"] = s(d.get("claimName"), 150)
    c["purpose"] = s(d.get("purpose"), 1000)
    c["month"] = s(d.get("month"), 7) if ISO_MONTH.match(s(d.get("month"), 7)) else ""
    for k in ("dateClaimed", "periodFrom", "periodTo"):
        c[k] = iso_date(d.get(k))
    c["rate"] = max(0.0, num(d.get("rate")))
    c["items"] = clean_items(d.get("items"))


def submit_problem(c):
    if not all(c.get(k) for k in ("claimName", "month", "dateClaimed", "purpose")):
        return "Please complete the required claim details."
    if not c["items"]:
        return "Add at least one mileage trip or expense."
    if not c["items"][0]["date"]:
        return "The first row needs a date."
    if any(num(i[k]) < 0 for i in c["items"] for k in ("km", "toll", "parking", "other")):
        return "Amounts cannot be negative."
    if totals(c) <= 0:
        return "The claim total must be more than RM 0.00."
    return None


def add_history(c, action, by, note=""):
    c["updatedAt"] = now_iso()
    c.setdefault("history", []).append({"at": c["updatedAt"], "by": by, "action": action, "note": s(note, 500)})


def next_ref(month):
    st = get_settings()
    n = int(st.get("seq", 1))
    st["seq"] = n + 1
    save_settings(st)
    return f"CLM-{(month or today()[:7]).replace('-', '')}-{n:03d}"


def state_for(u):
    users = load_users()
    st = get_settings()
    return {
        "ok": True,
        "user": public_user(u),
        "settings": {k: st[k] for k in ("company", "rate", "departments", "notify", "demo")},
        "claims": [c for c in load_claims() if can_see(u, c)],
        "users": [public_user(x) for x in users] if u["role"] == "admin" else [directory_entry(x) for x in users],
    }


# ---------------------------------------------------------------- routes: page & session

@app.get("/")
def index():
    return send_file(PAGE, mimetype="text/html", max_age=0)


@app.get("/healthz")
def healthz():
    q("SELECT 1")
    return jsonify(ok=True)


def needs_setup(users):
    # setup reopens only while there is no active Administrator (e.g. first run, or after removing the demo accounts)
    return not any(x["role"] == "admin" and x.get("active", True) for x in users)


def setup_allowed(d):
    if not needs_setup(load_users()):
        return "Setup has already been done."
    needed = SETUP_KEY or ON_RAILWAY
    if needed and not SETUP_KEY:
        return "Set a SETUP_KEY variable in Railway before setting up EcoClaim."
    if SETUP_KEY and not secrets.compare_digest(s(d.get("setupKey"), 200), SETUP_KEY):
        return "Setup key is incorrect."
    return None


@app.get("/api/bootstrap")
def bootstrap():
    st = get_settings()
    users = load_users()
    u = current_user()
    out = {"ok": True, "needsSetup": needs_setup(users), "setupKeyRequired": bool(SETUP_KEY or ON_RAILWAY),
           "settings": {"company": st["company"], "departments": st["departments"], "demo": st["demo"]}}
    if st["demo"]:
        out["demoUsers"] = [directory_entry(x) for x in users if x.get("demo")]
        out["demoPassword"] = DEMO_PW
    if u:
        out.update(state_for(u))
    return jsonify(out)


@app.post("/api/setup")
def setup():
    d = body()
    problem = setup_allowed(d)
    if problem:
        return err(403, problem)
    name, un, email = s(d.get("name"), 80), s(d.get("username"), 30).lower(), s(d.get("email"), 120).lower()
    dept, pw = s(d.get("department"), 60), str(d.get("password") or "")
    if not name:
        return err(400, "Enter your full name.")
    if not USERNAME.match(un):
        return err(400, "Username: 3-30 letters, numbers, dot, dash or underscore.")
    if not EMAIL.match(email):
        return err(400, "Enter a valid email address.")
    if not pw_ok(pw):
        return err(400, "Password: at least 8 characters, with letters and numbers.")
    st = get_settings()
    if dept not in st["departments"]:
        return err(400, "Pick a department.")
    if any(x["username"] == un or x.get("email") in (un, email) for x in load_users()):
        return err(400, "That username or email is already used by another user.")
    u = {"id": new_id(), "name": name, "username": un, "email": email, "department": dept, "role": "admin",
         "approveDepts": [], "active": True, "mustChange": False, "createdAt": now_iso(), "lastLogin": now_iso()}
    set_pw(u, pw)
    save_user(u)
    save_settings(st)
    g.user = u
    return start_session(jsonify(state_for(u)), u)


@app.post("/api/login")
def login():
    d = body()
    ident, pw = s(d.get("login"), 120).lower(), str(d.get("password") or "")
    dept, role = s(d.get("department"), 60), s(d.get("role"), 20)
    if not ident or not pw or not dept or not role:
        return err(400, "Enter your username or email, password, department and role.")
    users = load_users()
    u = next((x for x in users if x["username"] == ident or (x.get("email") and x["email"] == ident)), None)
    key = u["username"] if u else ident
    lock = q("SELECT n, until FROM locks WHERE k = ?", (key,), one=True) or {"n": 0, "until": 0}
    if lock["until"] > time.time():
        mins = int((lock["until"] - time.time()) // 60) + 1
        return err(429, f"Too many failed attempts. Try again in {mins} minute(s).")
    if not (u and check_pw(u, pw) and u["department"] == dept and u["role"] == role):
        n, until = lock["n"] + 1, 0
        if n >= 5:
            n, until = 0, time.time() + 5 * 60
        q("INSERT INTO locks (k, n, until) VALUES (?, ?, ?) ON CONFLICT (k) DO UPDATE SET n = excluded.n, until = excluded.until",
          (key, n, until))
        return err(401, "Sign-in failed. Check your username or email, password, department and role.")
    if not u.get("active", True):
        return err(403, "This account is disabled. Contact your Administrator.")
    q("DELETE FROM locks WHERE k = ?", (key,))
    u["lastLogin"] = now_iso()
    save_user(u)
    g.user = u
    return start_session(jsonify(state_for(u)), u)


@app.post("/api/logout")
def logout():
    return end_session(jsonify(ok=True))


@app.get("/api/state")
@login_required
def state():
    return jsonify(state_for(current_user()))


@app.post("/api/password")
@login_required
def change_password():
    u, d = current_user(), body()
    new = str(d.get("new") or "")
    if not u.get("mustChange") and not check_pw(u, str(d.get("current") or "")):
        return err(400, "Current password is incorrect.")
    if not pw_ok(new):
        return err(400, "Password: at least 8 characters, with letters and numbers.")
    if check_pw(u, new):
        return err(400, "Choose a password different from the current one.")
    set_pw(u, new)
    u["mustChange"] = False
    save_user(u)
    return jsonify(state_for(u))


# ---------------------------------------------------------------- routes: claims

@app.post("/api/claims")
@login_required
def create_claim():
    u, d = current_user(), body()
    c = {"id": new_id(), "ownerId": u["id"], "claimant": u["name"], "email": u.get("email", ""),
         "department": u["department"], "status": "draft", "hod": None, "history": [], "createdAt": now_iso()}
    apply_fields(c, d.get("claim") or {})
    if d.get("submit"):
        problem = submit_problem(c)
        if problem:
            return err(400, problem)
    c["ref"] = next_ref(c["month"])
    add_history(c, "created", u["name"])
    if d.get("submit"):
        c["status"] = "pending"
        add_history(c, "submitted", u["name"])
    save_claim(c)
    return jsonify(ok=True, claim=c, **{k: v for k, v in state_for(u).items() if k != "ok"})


@app.put("/api/claims/<cid>")
@login_required
def update_claim(cid):
    u, d = current_user(), body()
    c = get_claim(cid)
    if not c or not can_see(u, c):
        return err(404, "Claim not found.")
    if not can_edit(u, c):
        return err(403, "This claim can no longer be edited.")
    apply_fields(c, d.get("claim") or {})
    if d.get("submit"):
        problem = submit_problem(c)
        if problem:
            return err(400, problem)
    add_history(c, "edited", u["name"])
    if d.get("submit"):
        c["status"] = "pending"
        add_history(c, "submitted", u["name"])
    save_claim(c)
    return jsonify(ok=True, claim=c, **{k: v for k, v in state_for(u).items() if k != "ok"})


@app.post("/api/claims/<cid>/action")
@login_required
def claim_action(cid):
    u, d = current_user(), body()
    c = get_claim(cid)
    if not c or not can_see(u, c):
        return err(404, "Claim not found.")
    action = s(d.get("action"), 20)
    if action == "submit":
        if not can_edit(u, c):
            return err(403, "Only the claimant can submit a draft or returned claim.")
        problem = submit_problem(c)
        if problem:
            return err(400, problem)
        c["status"] = "pending"
        add_history(c, "submitted", u["name"])
    elif action == "withdraw":
        if not (owns(u, c) and c["status"] == "pending"):
            return err(403, "Only the claimant can withdraw a pending claim.")
        c["status"] = "draft"
        add_history(c, "withdrawn", u["name"])
    elif action in ("approve", "reject"):
        if not can_approve(u, c):
            return err(403, f"Only the HOD or Approver of {c.get('department')} can approve this claim.")
        remarks = s(d.get("remarks"), 500)
        if action == "reject" and not remarks:
            return err(400, "Add remarks so the claimant knows what to fix.")
        c["status"] = "approved" if action == "approve" else "rejected"
        c["hod"] = {"name": u["name"], "userId": u["id"], "role": u["role"], "email": u.get("email", ""),
                    "date": iso_date(d.get("date")) or today(), "remarks": remarks}
        add_history(c, c["status"], u["name"], remarks)
    elif action == "revoke":
        if not can_revoke(u, c):
            return err(403, "Only the HOD or Approver of this department can revoke the approval.")
        c["status"] = "pending"
        c["hod"] = None
        add_history(c, "reopened", u["name"])
    elif action == "emailed":
        add_history(c, "emailed", u["name"], d.get("note"))
    else:
        return err(400, "Unknown action.")
    save_claim(c)
    return jsonify(ok=True, claim=c, **{k: v for k, v in state_for(u).items() if k != "ok"})


@app.delete("/api/claims/<cid>")
@login_required
def delete_claim(cid):
    u = current_user()
    c = get_claim(cid)
    if not c or not can_see(u, c):
        return err(404, "Claim not found.")
    if not can_delete(u, c):
        return err(403, "You can only delete your own draft or returned claims.")
    q("DELETE FROM claims WHERE id = ?", (cid,))
    return jsonify(state_for(u))


# ---------------------------------------------------------------- routes: users & settings (admin)

def active_admins(users):
    return sum(1 for x in users if x["role"] == "admin" and x.get("active", True))


def user_fields(d, users, existing=None):
    st = get_settings()
    name, un = s(d.get("name"), 80), s(d.get("username"), 30).lower()
    email, dept, role = s(d.get("email"), 120).lower(), s(d.get("department"), 60), s(d.get("role"), 20)
    depts = [x for x in (d.get("approveDepts") or []) if isinstance(x, str) and x in st["departments"]] if role == "approver" else []
    if not name:
        return None, "Enter the full name."
    if not USERNAME.match(un):
        return None, "Username: 3-30 letters, numbers, dot, dash or underscore."
    if not EMAIL.match(email):
        return None, "Enter a valid email address."
    if dept not in st["departments"]:
        return None, "Pick a department."
    if role not in ROLES:
        return None, "Pick a role."
    others = [x for x in users if not existing or x["id"] != existing["id"]]
    if any(x["username"] == un for x in others):
        return None, "That username is already taken."
    if any(x.get("email") == email or x["username"] == email for x in others):
        return None, "That email is already used by another user."
    if role == "approver" and not depts:
        return None, "Tick at least one department this Approver can approve."
    if existing and existing["role"] == "admin" and role != "admin" and existing.get("active", True) and active_admins(users) <= 1:
        return None, "Keep at least one active Administrator."
    return {"name": name, "username": un, "email": email, "department": dept, "role": role, "approveDepts": depts}, None


@app.post("/api/users")
@admin_required
def create_user():
    d, users = body(), load_users()
    fields, problem = user_fields(d, users)
    if problem:
        return err(400, problem)
    pw = str(d.get("password") or "")
    if not pw_ok(pw):
        return err(400, "Temporary password: at least 8 characters, with letters and numbers.")
    u = dict(fields, id=new_id(), active=True, mustChange=True, createdAt=now_iso())
    set_pw(u, pw)
    save_user(u)
    return jsonify(state_for(current_user()))


@app.put("/api/users/<uid>")
@admin_required
def update_user(uid):
    d, users = body(), load_users()
    u = next((x for x in users if x["id"] == uid), None)
    if not u:
        return err(404, "User not found.")
    fields, problem = user_fields(d, users, u)
    if problem:
        return err(400, problem)
    old_name = u["name"]
    u.update(fields)
    save_user(u)
    for c in load_claims():
        if c.get("ownerId") == uid:
            if c.get("claimant") == old_name:
                c["claimant"] = u["name"]
            if c["status"] != "approved":
                c["email"] = u["email"]
            save_claim(c)
    g.pop("user", None)
    return jsonify(state_for(current_user()))


@app.post("/api/users/<uid>/password")
@admin_required
def reset_password(uid):
    me, pw = current_user(), str(body().get("password") or "")
    u = next((x for x in load_users() if x["id"] == uid), None)
    if not u:
        return err(404, "User not found.")
    if not pw_ok(pw):
        return err(400, "Password: at least 8 characters, with letters and numbers.")
    set_pw(u, pw)
    u["mustChange"] = u["id"] != me["id"]
    save_user(u)
    q("DELETE FROM locks WHERE k = ?", (u["username"],))
    if u["id"] != me["id"]:
        q("DELETE FROM sessions WHERE user_id = ?", (u["id"],))
    return jsonify(state_for(me))


@app.post("/api/users/<uid>/toggle")
@admin_required
def toggle_user(uid):
    me, users = current_user(), load_users()
    u = next((x for x in users if x["id"] == uid), None)
    if not u:
        return err(404, "User not found.")
    if u["id"] == me["id"]:
        return err(400, "You can't disable your own account.")
    if u.get("active", True) and u["role"] == "admin" and active_admins(users) <= 1:
        return err(400, "Keep at least one active Administrator.")
    u["active"] = not u.get("active", True)
    save_user(u)
    if not u["active"]:
        q("DELETE FROM sessions WHERE user_id = ?", (u["id"],))
    return jsonify(state_for(me))


@app.put("/api/settings")
@admin_required
def update_settings():
    d, st, users = body(), get_settings(), load_users()
    depts = []
    for x in d.get("departments") or []:
        x = s(x, 60)
        if x and x not in depts:
            depts.append(x)
    depts = depts or list(DEFAULT_SETTINGS["departments"])
    in_use = sorted({x["department"] for x in users} - set(depts))
    if in_use:
        return err(400, f"Can't remove {', '.join(in_use)} - users are still assigned to it.")
    st.update(company=s(d.get("company"), 120) or DEFAULT_SETTINGS["company"], rate=max(0.0, num(d.get("rate"))),
              departments=depts, notify=bool(d.get("notify", True)))
    save_settings(st)
    for u in users:
        if u.get("approveDepts") and any(x not in depts for x in u["approveDepts"]):
            u["approveDepts"] = [x for x in u["approveDepts"] if x in depts]
            save_user(u)
    return jsonify(state_for(current_user()))


@app.get("/api/backup")
@admin_required
def backup():
    resp = jsonify(settings=get_settings(), users=load_users(), claims=load_claims(), exportedAt=now_iso())
    resp.headers["Content-Disposition"] = f"attachment; filename=EcoClaim backup {today()}.json"
    return resp


@app.post("/api/restore")
@admin_required
def restore():
    d = body()
    users, claims = d.get("users"), d.get("claims")
    if not isinstance(claims, list) or not all(isinstance(c, dict) and c.get("id") for c in claims):
        return err(400, "That file is not a valid EcoClaim backup.")
    keep_users = not (isinstance(users, list) and any(isinstance(x, dict) and x.get("role") == "admin" and x.get("active", True) for x in users))
    q("DELETE FROM claims")
    for c in claims:
        c.setdefault("status", "draft")
        c.setdefault("history", [])
        save_claim(c)
    if not keep_users:
        q("DELETE FROM users")
        q("DELETE FROM sessions")
        for x in users:
            if isinstance(x, dict) and x.get("id") and x.get("username"):
                save_user(x)
    if isinstance(d.get("settings"), dict):
        st = get_settings()
        st.update({k: v for k, v in d["settings"].items() if k in DEFAULT_SETTINGS})
        save_settings(st)
    g.pop("user", None)
    u = current_user()
    if not u:
        return end_session(jsonify(ok=True, signedOut=True))
    return jsonify(state_for(u))


# ---------------------------------------------------------------- demo mode

DEMO_USERS = [("System Admin", "admin", "Admin", "admin", []), ("TEY KOK LEONG", "tey", "Sales", "hod", []),
              ("Timothy Lim", "timothy", "Sales", "staff", []), ("Lee Mei", "leemei", "Logistics", "hod", []),
              ("Ahmad Faiz", "ahmad", "Logistics", "staff", []), ("Nora Hassan", "nora", "Finance", "approver", ["Sales", "Logistics"])]


def demo_item(d, frm="", to="", km="", desc="", **extra):
    it = {"id": new_id(), "date": d, "from": frm, "to": to, "km": str(km), "toll": "", "parking": "", "other": "", "desc": desc, "receipt": ""}
    it.update({k: str(v) for k, v in extra.items()})
    return it


def demo_claims(tim, tey):
    H, D, N = "Gaya Resort Home", "DHL Supply Chain PKFZ", "New Asia"
    sept = [demo_item("2026-09-04", H, "VTEB Baker Hugh", 10, "Collection of goods"), demo_item("", "VTEB Baker Hugh", N, 51, "Deliver and meeting with Suresh"),
            demo_item("", N, D, 3.5, "Meeting with Syaliny"), demo_item("", D, H, 58),
            demo_item("2026-09-07", H, "Mectech", 10, "Collect goods"), demo_item("", "Mectech", N, 53, "Deliver goods"),
            demo_item("", N, D, 3.5, "Meeting with Syaliny"), demo_item("", D, H, 38),
            demo_item("2026-09-09", H, "DHL ILC1", 11, "Meeting with Anujashini"), demo_item("", "DHL ILC1", H, 11),
            demo_item("2026-09-10", desc="232 2486299995 - return flight KL-JB site visit (Syaliny - DHL)", other=752.6),
            demo_item("2026-09-10", desc="232 2486299996 - return flight KL-JB site visit (Timothy - LVC)", other=752.6),
            demo_item("2026-09-10", desc="A-9QKE6LEGXXSVAV - Grab ride to KLIA (Timothy - LVC)", other=64.73),
            demo_item("2026-09-10", desc="A-9QHW224GXDGNAV - Grab ride to KLIA (Syaliny - DHL)", other=75.71),
            demo_item("2026-09-11", desc="A-9QRKE5WWXFLKAV - Grab ride from KLIA (Timothy - LVC)", other=75.73),
            demo_item("2026-09-11", desc="A-9QRKDB4WX89SAV - Grab ride from KLIA (Syaliny - DHL)", other=74.71),
            demo_item("2026-09-14", H, "Petikemas", 38, "Meeting and checking printer machine"), demo_item("", "Petikemas", D, 3.5, "Meeting with Syaliny"), demo_item("", D, H, 58),
            demo_item("2026-09-15", H, "PSE", 19, "Collect sample"), demo_item("", "PSE", D, 34, "Meeting with Syaliny"), demo_item("", D, H, 58),
            demo_item("2026-09-21", H, "Kweng Hong", 59, "Collect sample"), demo_item("", "Kweng Hong", D, 84, "Meeting with Syaliny"),
            demo_item("", D, "Petikemas", 3.5, "Meeting with Calvin"), demo_item("", "Petikemas", H, 38),
            demo_item("2026-09-24", H, "DHL ILC1", 11, "Meeting with Anujashini"), demo_item("", "DHL ILC1", H, 11),
            demo_item("2026-09-25", H, N, 38, "Meeting with Suresh & Bala"), demo_item("", N, D, 3.5, "Meeting with Liyana"), demo_item("", D, H, 58),
            demo_item("2026-09-26", H, N, 38, "Meeting with Elya & Suresh"), demo_item("", N, H, 38)]
    base = {"ownerId": tim["id"], "claimant": tim["name"], "email": tim["email"], "department": "Sales", "rate": 0.5, "demo": True}
    c1 = dict(base, id=new_id(), ref=next_ref("2026-09"), claimName="Customer visits & deliveries - September 2026", month="2026-09",
              purpose="Collection & delivery of goods, sample collection, customer meetings (DHL, New Asia, Petikemas) and KL-JB site visit.",
              dateClaimed="2026-09-28", periodFrom="2026-09-01", periodTo="2026-09-30", items=sept, status="approved",
              hod={"name": tey["name"], "userId": tey["id"], "role": "hod", "email": tey["email"], "date": "2026-10-09", "remarks": ""},
              history=[], createdAt=now_iso())
    add_history(c1, "submitted", tim["name"])
    add_history(c1, "approved", tey["name"])
    octo = [demo_item("2026-10-02", H, N, 38, "Meeting with Suresh"), demo_item("", N, D, 3.5, "Meeting with Syaliny", toll="4.20", parking="3.00"),
            demo_item("", D, H, 58), demo_item("2026-10-06", H, "DHL ILC1", 11, "Meeting with Anujashini"), demo_item("", "DHL ILC1", H, 11),
            demo_item("2026-10-06", desc="Lunch meeting with DHL team", other="86.50", receipt="INV-20145")]
    c2 = dict(base, id=new_id(), ref=next_ref("2026-10"), claimName="Customer visits - October 2026", month="2026-10",
              purpose="Customer meetings and sample collection (DHL, New Asia).", dateClaimed=today(),
              periodFrom="2026-10-01", periodTo="2026-10-31", items=octo, status="pending", hod=None, history=[], createdAt=now_iso())
    add_history(c2, "created", tim["name"])
    add_history(c2, "submitted", tim["name"])
    return [c1, c2]


@app.post("/api/demo")
def load_demo():
    problem = setup_allowed(body())
    if problem:
        return err(403, problem)
    taken = {x["username"] for x in load_users()} & {d[1] for d in DEMO_USERS}
    if taken:
        return err(400, f"Can't load demo accounts - these usernames already exist: {', '.join(sorted(taken))}.")
    st = get_settings()
    made = {}
    for name, un, dept, role, depts in DEMO_USERS:
        if dept not in st["departments"]:
            st["departments"].append(dept)
        u = {"id": new_id(), "name": name, "username": un, "email": f"{un}@example.com", "department": dept, "role": role,
             "approveDepts": depts, "active": True, "mustChange": False, "demo": True, "createdAt": now_iso()}
        set_pw(u, DEMO_PW)
        save_user(u)
        made[un] = u
    st["demo"] = True
    save_settings(st)
    for c in demo_claims(made["timothy"], made["tey"]):
        save_claim(c)
    return jsonify(ok=True)


@app.post("/api/demo/end")
@admin_required
def end_demo():
    me = current_user()
    demo_ids = {x["id"] for x in load_users() if x.get("demo")}
    for uid in demo_ids:
        q("DELETE FROM users WHERE id = ?", (uid,))
        q("DELETE FROM sessions WHERE user_id = ?", (uid,))
    for c in load_claims():
        if c.get("demo"):
            q("DELETE FROM claims WHERE id = ?", (c["id"],))
    q("DELETE FROM locks")
    st = get_settings()
    st["demo"] = False
    save_settings(st)
    if me["id"] in demo_ids:
        return end_session(jsonify(ok=True, signedOut=True))
    g.pop("user", None)
    return jsonify(state_for(current_user()))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 8000)), debug=False)
