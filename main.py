# ===============================
# RentinBerlin – AUTH FOUNDATION
# ===============================
# Run: streamlit run main.py

import os
import re
import uuid
import sqlite3
import hashlib
from datetime import datetime, timedelta

import streamlit as st

# ===============================
# CONFIG
# ===============================
APP_NAME = "RentinBerlin"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "rentinberlin.db")
ASSETS_DIR = os.path.join(BASE_DIR, "assets")
GOOGLE_LOGO = os.path.join(ASSETS_DIR, "google_logo.png")

SESSION_DAYS = 30

st.set_page_config(
    page_title=APP_NAME,
    page_icon="🏠",
    layout="centered",
)

# ===============================
# UTIL
# ===============================
def now_iso():
    return datetime.utcnow().replace(microsecond=0).isoformat()

def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

def valid_email(e: str) -> bool:
    return bool(re.match(r"[^@]+@[^@]+\.[^@]+", e or ""))

# ===============================
# DATABASE
# ===============================
def db():
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    c = db()
    cur = c.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        expires_at TEXT NOT NULL
    )
    """)

    c.commit()
    c.close()

init_db()

# ===============================
# AUTH CORE
# ===============================
def create_user(email, password):
    if not valid_email(email):
        return False, "Invalid email"
    if len(password) < 6:
        return False, "Password must be at least 6 characters"

    try:
        c = db()
        c.execute(
            "INSERT INTO users (email, password_hash, created_at) VALUES (?,?,?)",
            (email.lower(), sha256(password), now_iso())
        )
        c.commit()
        c.close()
        return True, "Account created"
    except sqlite3.IntegrityError:
        return False, "Email already exists"

def authenticate(email, password):
    c = db()
    row = c.execute(
        "SELECT id, password_hash FROM users WHERE email=?",
        (email.lower(),)
    ).fetchone()
    c.close()

    if not row:
        return None
    if row["password_hash"] != sha256(password):
        return None
    return row["id"]

def create_session(user_id):
    token = uuid.uuid4().hex + uuid.uuid4().hex
    expires = (datetime.utcnow() + timedelta(days=SESSION_DAYS)).isoformat()
    c = db()
    c.execute(
        "INSERT INTO sessions (token, user_id, expires_at) VALUES (?,?,?)",
        (token, user_id, expires)
    )
    c.commit()
    c.close()
    return token

def get_user_from_token(token):
    if not token:
        return None
    c = db()
    row = c.execute(
        "SELECT user_id, expires_at FROM sessions WHERE token=?",
        (token,)
    ).fetchone()
    c.close()

    if not row:
        return None
    if datetime.fromisoformat(row["expires_at"]) < datetime.utcnow():
        return None
    return row["user_id"]

def logout():
    st.session_state.clear()
    st.experimental_set_query_params()
    st.rerun()

# ===============================
# STYLE
# ===============================
st.markdown("""
<style>
body {
    background: radial-gradient(circle at top, #fff7ed, #f8fafc);
}
.auth-card {
    max-width: 420px;
    margin: auto;
    padding: 24px;
    border-radius: 22px;
    background: white;
    box-shadow: 0 25px 60px rgba(0,0,0,.08);
}
.title {
    text-align: center;
    font-size: 26px;
    font-weight: 900;
}
.sub {
    text-align: center;
    color: #64748b;
    font-size: 13px;
    margin-bottom: 16px;
}
.divider {
    text-align: center;
    color: #94a3b8;
    font-size: 12px;
    margin: 14px 0;
}
.divider:before,
.divider:after {
    content: "";
    display: inline-block;
    width: 40%;
    height: 1px;
    background: #e5e7eb;
    vertical-align: middle;
}
.divider:before { margin-right: 8px; }
.divider:after { margin-left: 8px; }
.google-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 10px;
    border: 1px solid #e5e7eb;
    border-radius: 14px;
    padding: 10px;
    font-weight: 800;
    cursor: pointer;
    background: #fff;
}
.google-btn:hover {
    background: #f8fafc;
}
</style>
""", unsafe_allow_html=True)

# ===============================
# ROUTING
# ===============================
if "page" not in st.session_state:
    st.session_state.page = "login"

token = st.query_params.get("t", "")
user_id = get_user_from_token(token)

# ===============================
# LOGGED IN
# ===============================
if user_id:
    st.success("✅ Logged in successfully")
    st.write("Welcome to RentinBerlin")
    if st.button("Logout"):
        logout()
    st.stop()

# ===============================
# AUTH UI
# ===============================
st.markdown("<div class='auth-card'>", unsafe_allow_html=True)

st.markdown(f"<div class='title'>{APP_NAME}</div>", unsafe_allow_html=True)
st.markdown("<div class='sub'>Find apartments in Berlin</div>", unsafe_allow_html=True)

# -------- LOGIN --------
if st.session_state.page == "login":
    st.subheader("Sign in")

    email = st.text_input("Email")
    password = st.text_input("Password", type="password")

    if st.button("Sign in", use_container_width=True):
        uid = authenticate(email, password)
        if not uid:
            st.error("Invalid credentials")
        else:
            token = create_session(uid)
            st.experimental_set_query_params(t=token)
            st.rerun()

    st.markdown("<div class='divider'>or</div>", unsafe_allow_html=True)

    if os.path.exists(GOOGLE_LOGO):
        st.image(GOOGLE_LOGO, width=22)
    st.button("Continue with Google", use_container_width=True)

    st.markdown(
        "New here? **Create account**",
        unsafe_allow_html=True
    )
    if st.button("Create account"):
        st.session_state.page = "signup"
        st.rerun()

# -------- SIGNUP --------
if st.session_state.page == "signup":
    st.subheader("Create account")

    email = st.text_input("Email")
    password = st.text_input("Password", type="password")

    if st.button("Create account", use_container_width=True):
        ok, msg = create_user(email, password)
        if ok:
            st.success(msg)
            st.session_state.page = "login"
            st.rerun()
        else:
            st.error(msg)

    if st.button("Back to login"):
        st.session_state.page = "login"
        st.rerun()

st.markdown("</div>", unsafe_allow_html=True)
