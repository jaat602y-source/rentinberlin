# ============================================================
# RentinBerlin – PRO AUTH (ONE FILE) + ANIMATIONS + LIGHT THEME
# ============================================================
# Run: streamlit run main.py
#
# Files (optional):
#   assets/google_logo.png
#   assets/logo.png
#
# requirements.txt:
#   streamlit
#   authlib   (only needed if you wire real Google OAuth later)

import os
import re
import uuid
import sqlite3
import hashlib
import base64
from datetime import datetime, timedelta

import streamlit as st

# ===============================
# CONFIG
# ===============================
APP_NAME = "RentinBerlin"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "rentinberlin.db")
ASSETS_DIR = os.path.join(BASE_DIR, "assets")
GOOGLE_LOGO_PATH = os.path.join(ASSETS_DIR, "google_logo.png")
APP_LOGO_PATH = os.path.join(ASSETS_DIR, "logo.png")

SESSION_DAYS = 30

st.set_page_config(
    page_title=APP_NAME,
    page_icon="🏠",
    layout="centered",
    initial_sidebar_state="collapsed",
)

# ===============================
# HELPERS
# ===============================
def now_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat()

def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def valid_email(e: str) -> bool:
    return bool(re.match(r"^[^@]+@[^@]+\.[^@]+$", (e or "").strip()))

def b64_file(path: str) -> str:
    with open(path, "rb") as f:
        return base64.b64encode(f.read()).decode("utf-8")

def safe_exists(path: str) -> bool:
    try:
        return os.path.exists(path)
    except Exception:
        return False

# ===============================
# DB
# ===============================
def db():
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL;")
    c.execute("PRAGMA synchronous=NORMAL;")
    c.execute("PRAGMA busy_timeout=8000;")
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
        created_at TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        expires_at TEXT NOT NULL
    )
    """)
    c.commit()
    c.close()

init_db()

# ===============================
# AUTH
# ===============================
def create_user(email: str, password: str):
    email = (email or "").strip().lower()
    password = (password or "").strip()

    if not valid_email(email):
        return False, "Please enter a valid email."
    if len(password) < 6:
        return False, "Password must be at least 6 characters."

    try:
        c = db()
        c.execute(
            "INSERT INTO users (email, password_hash, created_at) VALUES (?,?,?)",
            (email, sha256(password), now_iso())
        )
        c.commit()
        c.close()
        return True, "Account created. Please sign in."
    except sqlite3.IntegrityError:
        return False, "This email is already registered."

def authenticate(email: str, password: str):
    email = (email or "").strip().lower()
    password = (password or "").strip()

    if not email or not password:
        return None

    c = db()
    row = c.execute("SELECT id, password_hash FROM users WHERE email=?", (email,)).fetchone()
    c.close()

    if not row:
        return None
    if row["password_hash"] != sha256(password):
        return None
    return int(row["id"])

def reset_password(email: str, new_password: str):
    email = (email or "").strip().lower()
    new_password = (new_password or "").strip()

    if not valid_email(email):
        return False, "Please enter a valid email."
    if len(new_password) < 6:
        return False, "New password must be at least 6 characters."

    c = db()
    cur = c.cursor()
    cur.execute("UPDATE users SET password_hash=? WHERE email=?", (sha256(new_password), email))
    changed = cur.rowcount
    c.commit()
    c.close()

    if changed:
        return True, "Password reset successfully. Please sign in."
    return False, "Email not found."

# ===============================
# SESSION TOKENS (?t=...)
# ===============================
def create_session(user_id: int) -> str:
    token = uuid.uuid4().hex + uuid.uuid4().hex
    expires_at = (datetime.utcnow() + timedelta(days=SESSION_DAYS)).replace(microsecond=0).isoformat()

    c = db()
    c.execute("""
        INSERT INTO sessions (token, user_id, created_at, last_seen, expires_at)
        VALUES (?,?,?,?,?)
    """, (token, user_id, now_iso(), now_iso(), expires_at))
    c.commit()
    c.close()
    return token

def get_user_from_token(token: str):
    token = (token or "").strip()
    if not token:
        return None

    c = db()
    row = c.execute("SELECT user_id, expires_at FROM sessions WHERE token=?", (token,)).fetchone()
    if not row:
        c.close()
        return None

    exp = datetime.fromisoformat(row["expires_at"])
    if exp < datetime.utcnow():
        c.execute("DELETE FROM sessions WHERE token=?", (token,))
        c.commit()
        c.close()
        return None

    c.execute("UPDATE sessions SET last_seen=? WHERE token=?", (now_iso(), token))
    c.commit()
    c.close()
    return int(row["user_id"])

def delete_session(token: str):
    token = (token or "").strip()
    if not token:
        return
    c = db()
    c.execute("DELETE FROM sessions WHERE token=?", (token,))
    c.commit()
    c.close()

def set_token_in_url(token: str):
    st.query_params["t"] = token

def clear_url():
    try:
        st.query_params.clear()
    except Exception:
        st.experimental_set_query_params()

def do_logout():
    tok = st.query_params.get("t", "")
    if tok:
        delete_session(tok)
    clear_url()
    st.session_state.clear()
    st.rerun()

# ===============================
# UI / STYLE (FORCED LIGHT + ANIMATIONS)
# ===============================
def inject_style():
    # Force light theme even if user/system is dark
    st.markdown("""
    <style>
      /* Force light background and base text */
      .stApp {
        background:
          radial-gradient(900px 650px at 10% 5%, rgba(255,122,26,0.14), transparent 55%),
          radial-gradient(850px 600px at 90% 15%, rgba(99,102,241,0.12), transparent 60%),
          radial-gradient(900px 650px at 50% 110%, rgba(16,185,129,0.12), transparent 58%),
          #f6f8fb !important;
        color: #0f172a !important;
      }

      /* Hide Streamlit chrome */
      #MainMenu {visibility:hidden;}
      header {visibility:hidden;}
      footer {visibility:hidden;}

      /* Center container */
      section.main > div.block-container {
        max-width: 520px;
        padding-top: 2.2rem;
        padding-bottom: 2.5rem;
      }

      /* Animated floating blobs */
      .rb-blob {
        position: fixed;
        z-index: 0;
        width: 520px;
        height: 520px;
        border-radius: 999px;
        filter: blur(40px);
        opacity: 0.22;
        animation: rbFloat 10s ease-in-out infinite;
      }
      .rb-blob.one { left: -180px; top: -180px; background: rgba(255,122,26,1); }
      .rb-blob.two { right: -220px; top: -220px; background: rgba(99,102,241,1); animation-delay: 1.7s; }
      .rb-blob.three { left: 10%; bottom: -260px; background: rgba(16,185,129,1); animation-delay: 3.2s; }

      @keyframes rbFloat {
        0%,100% { transform: translate(0,0) scale(1); }
        50% { transform: translate(20px, 28px) scale(1.03); }
      }

      /* Card */
      .rb-shell { position: relative; z-index: 2; }
      .rb-card {
        background: rgba(255,255,255,0.82);
        border: 1px solid rgba(226,232,240,0.85);
        border-radius: 24px;
        box-shadow: 0 28px 70px rgba(16,24,40,0.12);
        padding: 20px 18px 16px 18px;
        backdrop-filter: blur(10px);
        animation: rbEnter 600ms ease-out;
      }

      @keyframes rbEnter {
        from { opacity: 0; transform: translateY(10px); }
        to   { opacity: 1; transform: translateY(0); }
      }

      /* Header area */
      .rb-top {
        display:flex;
        flex-direction:column;
        align-items:center;
        text-align:center;
        margin-bottom: 14px;
      }
      .rb-logo {
        width: 72px;
        height: 72px;
        border-radius: 20px;
        background: #ffffff;
        border: 1px solid rgba(226,232,240,0.9);
        box-shadow: 0 18px 48px rgba(16,24,40,0.12);
        overflow:hidden;
        display:flex;
        align-items:center;
        justify-content:center;
      }
      .rb-logo img { width:100%; height:100%; object-fit:cover; display:block; }
      .rb-appname {
        margin-top: 10px;
        font-weight: 950;
        font-size: 24px;
        letter-spacing: 0.2px;
        color:#0f172a;
      }
      .rb-tagline {
        margin-top: 6px;
        font-size: 13px;
        color:#64748b;
      }

      /* Titles */
      .rb-h1 { font-weight: 950; font-size: 28px; margin: 0; color:#0f172a; }
      .rb-sub { margin-top: 6px; color:#64748b; font-size: 13px; }

      /* Inputs - force light */
      .stTextInput input, .stPassword input {
        border-radius: 14px !important;
        height: 46px !important;
        border: 1px solid rgba(226,232,240,1) !important;
        background: #ffffff !important;
        color: #0f172a !important;
      }
      .stTextInput label, .stPassword label {
        color: #0f172a !important;
        font-weight: 800 !important;
      }

      /* Buttons */
      .stButton>button {
        border-radius: 14px !important;
        border: 1px solid rgba(226,232,240,1) !important;
        background: #ffffff !important;
        color: #0f172a !important;
        padding: 0.62rem 0.95rem !important;
        font-weight: 950 !important;
        transition: transform 140ms ease, box-shadow 140ms ease, border-color 140ms ease;
      }
      .stButton>button:hover {
        transform: translateY(-1px);
        box-shadow: 0 14px 30px rgba(16,24,40,0.10);
        border-color: rgba(203,213,225,1) !important;
      }
      .stButton>button[kind="primary"] {
        background: #ff7a1a !important;
        border-color: #ff7a1a !important;
        color: #ffffff !important;
        box-shadow: 0 16px 40px rgba(255, 122, 26, 0.22) !important;
      }

      /* Divider */
      .rb-divider {
        display:flex; align-items:center; gap:10px;
        margin: 14px 0;
        color:#94a3b8;
        font-size: 12px;
        font-weight: 900;
      }
      .rb-divider:before, .rb-divider:after {
        content:""; height:1px; flex:1; background:#e5e7eb;
      }

      /* Social button */
      .rb-social {
        display:flex;
        align-items:center;
        justify-content:center;
        gap: 10px;
        padding: 10px 12px;
        border-radius: 14px;
        border: 1px solid rgba(226,232,240,1);
        background: #ffffff;
        font-weight: 950;
        cursor: pointer;
        user-select: none;
        transition: transform 140ms ease, box-shadow 140ms ease;
      }
      .rb-social:hover {
        transform: translateY(-1px);
        box-shadow: 0 14px 30px rgba(16,24,40,0.10);
      }
      .rb-social img { width: 18px; height: 18px; display:block; }

      .rb-foot {
        margin-top: 12px;
        text-align:center;
        font-size: 12px;
        color:#64748b;
      }
      .rb-link {
        color:#0f172a;
        font-weight: 950;
        text-decoration: none;
      }
      .rb-link:hover { text-decoration: underline; }

      /* Small helper row */
      .rb-row {
        display:flex;
        justify-content:space-between;
        align-items:center;
        margin-top: -6px;
        margin-bottom: 10px;
      }

      @media (max-width: 520px){
        section.main > div.block-container { padding-left: 0.9rem; padding-right: 0.9rem; }
        .rb-card { padding: 18px 14px 14px 14px; }
      }
    </style>

    <div class="rb-blob one"></div>
    <div class="rb-blob two"></div>
    <div class="rb-blob three"></div>
    """, unsafe_allow_html=True)

inject_style()

# ===============================
# ROUTING
# ===============================
if "route" not in st.session_state:
    st.session_state.route = "login"

token = st.query_params.get("t", "")
uid = get_user_from_token(token)

# ===============================
# HEADER (Logo)
# ===============================
def render_top():
    logo_html = "🏠"
    if safe_exists(APP_LOGO_PATH):
        b64 = b64_file(APP_LOGO_PATH)
        logo_html = f"<img src='data:image/png;base64,{b64}' />"

    st.markdown(f"""
    <div class="rb-shell">
      <div class="rb-top">
        <div class="rb-logo">{logo_html}</div>
        <div class="rb-appname">{APP_NAME}</div>
        <div class="rb-tagline">Apartments in Berlin • Fast messaging • Clean experience</div>
      </div>
    """, unsafe_allow_html=True)

def close_shell():
    st.markdown("</div>", unsafe_allow_html=True)

def google_button():
    # This is UI only. Wiring real Google OAuth is separate.
    if safe_exists(GOOGLE_LOGO_PATH):
        b64 = b64_file(GOOGLE_LOGO_PATH)
        st.markdown(f"""
        <div class="rb-social">
          <img src="data:image/png;base64,{b64}" />
          <span>Continue with Google</span>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class="rb-social">
          <span style="font-size:18px;">G</span>
          <span>Continue with Google</span>
        </div>
        """, unsafe_allow_html=True)

    # Put a real Streamlit button below (so it actually clicks)
    if st.button("Continue with Google", use_container_width=True, key="google_real_btn"):
        st.info("Google OAuth wiring comes next (you already added secrets/requirements). Tell me your redirect URL and I’ll connect it.")

# ===============================
# LOGGED IN VIEW
# ===============================
if uid:
    render_top()
    st.markdown("<div class='rb-card'>", unsafe_allow_html=True)
    st.markdown("<div class='rb-h1'>You’re signed in ✅</div>", unsafe_allow_html=True)
    st.markdown("<div class='rb-sub'>This is your dashboard placeholder (we’ll add listings next).</div>", unsafe_allow_html=True)
    st.write("")
    st.success("Login persistence is working (token in URL).")
    st.write("Next: we build your real website pages (Home, Listings, Post, Messages, Profile).")
    st.write("")
    if st.button("Logout", use_container_width=True):
        do_logout()
    st.markdown("</div>", unsafe_allow_html=True)
    close_shell()
    st.stop()

# ===============================
# AUTH PAGES
# ===============================
def page_login():
    render_top()
    st.markdown("<div class='rb-card'>", unsafe_allow_html=True)

    st.markdown("<div class='rb-h1'>Sign in</div>", unsafe_allow_html=True)
    st.markdown("<div class='rb-sub'>Welcome back. Please enter your details.</div>", unsafe_allow_html=True)
    st.write("")

    with st.form("login_form", clear_on_submit=False):
        email = st.text_input("Email", placeholder="name@email.com")
        password = st.text_input("Password", type="password", placeholder="Minimum 6 characters")
        submit = st.form_submit_button("Sign in", type="primary", use_container_width=True)

    st.markdown("<div class='rb-row'>", unsafe_allow_html=True)
    colA, colB = st.columns([1,1])
    with colA:
        if st.button("Create account", use_container_width=True):
            st.session_state.route = "signup"
            st.rerun()
    with colB:
        if st.button("Forgot password", use_container_width=True):
            st.session_state.route = "reset"
            st.rerun()
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<div class='rb-divider'>OR</div>", unsafe_allow_html=True)
    google_button()

    if submit:
        user_id = authenticate(email, password)
        if not user_id:
            st.error("Wrong email or password.")
        else:
            tok = create_session(user_id)
            set_token_in_url(tok)
            st.rerun()

    st.markdown("<div class='rb-foot'>By continuing you agree to basic community rules.</div>", unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)
    close_shell()

def page_signup():
    render_top()
    st.markdown("<div class='rb-card'>", unsafe_allow_html=True)

    st.markdown("<div class='rb-h1'>Create account</div>", unsafe_allow_html=True)
    st.markdown("<div class='rb-sub'>Start posting & finding apartments in minutes.</div>", unsafe_allow_html=True)
    st.write("")

    with st.form("signup_form", clear_on_submit=False):
        email = st.text_input("Email", placeholder="name@email.com")
        password = st.text_input("Password", type="password", placeholder="Minimum 6 characters")
        submit = st.form_submit_button("Create account", type="primary", use_container_width=True)

    if submit:
        ok, msg = create_user(email, password)
        if ok:
            st.success(msg)
            st.session_state.route = "login"
            st.rerun()
        else:
            st.error(msg)

    st.write("")
    if st.button("Back to sign in", use_container_width=True):
        st.session_state.route = "login"
        st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)
    close_shell()

def page_reset():
    render_top()
    st.markdown("<div class='rb-card'>", unsafe_allow_html=True)

    st.markdown("<div class='rb-h1'>Reset password</div>", unsafe_allow_html=True)
    st.markdown("<div class='rb-sub'>Set a new password for your account.</div>", unsafe_allow_html=True)
    st.write("")

    with st.form("reset_form", clear_on_submit=False):
        email = st.text_input("Email", placeholder="name@email.com")
        new_password = st.text_input("New password", type="password", placeholder="Minimum 6 characters")
        submit = st.form_submit_button("Reset password", type="primary", use_container_width=True)

    if submit:
        ok, msg = reset_password(email, new_password)
        if ok:
            st.success(msg)
            st.session_state.route = "login"
            st.rerun()
        else:
            st.error(msg)

    st.write("")
    if st.button("Back to sign in", use_container_width=True):
        st.session_state.route = "login"
        st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)
    close_shell()

# ===============================
# RUN ROUTE
# ===============================
route = st.session_state.route
if route == "signup":
    page_signup()
elif route == "reset":
    page_reset()
else:
    page_login()
