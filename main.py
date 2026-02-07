# ==============================
# ADVANCED AUTH UI (Login/Signup/Reset)
# Uses: assets/bg1.png, assets/bg2.png, assets/bg3.png
# Optional: assets/logo.png, assets/google_logo.png (white/colored)
# ==============================

import os
import re
import uuid
import base64
import sqlite3
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

import streamlit as st

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ASSETS_DIR = os.path.join(BASE_DIR, "assets")
DB_PATH = os.path.join(BASE_DIR, "rentinberlin.db")

SESSION_DAYS = 30
APP_NAME = "RentinBerlin"

# ------------------------------
# Helpers
# ------------------------------
def _b64(path: str) -> str:
    if not os.path.exists(path):
        return ""
    return base64.b64encode(open(path, "rb").read()).decode()

def _data_url(path: str) -> str:
    if not os.path.exists(path):
        return ""
    ext = os.path.splitext(path)[1].lower().replace(".", "")
    if ext == "jpg":
        ext = "jpeg"
    return f"data:image/{ext};base64,{_b64(path)}"

def now_iso() -> str:
    return datetime.now().replace(microsecond=0).isoformat()

def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def normalize_email(e: str) -> str:
    return (e or "").strip().lower()

# ------------------------------
# DB + Auth (simple, working)
# ------------------------------
def conn() -> sqlite3.Connection:
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    if st.session_state.get("_db_init"):
        return
    c = conn()
    cur = c.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS sessions(
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
    """)
    c.commit()
    c.close()
    st.session_state["_db_init"] = True

def create_user(email: str, password: str):
    email = normalize_email(email)
    password = (password or "").strip()
    if not email or "@" not in email:
        return False, "Enter a valid email."
    if len(password) < 6:
        return False, "Password must be at least 6 characters."
    c = conn()
    cur = c.cursor()
    try:
        cur.execute("INSERT INTO users(created_at,email,password_hash) VALUES(?,?,?)",
                    (now_iso(), email, sha256(password)))
        c.commit()
        c.close()
        return True, "Account created. Please sign in."
    except sqlite3.IntegrityError:
        c.close()
        return False, "Email already exists."

def authenticate(email: str, password: str) -> Optional[int]:
    email = normalize_email(email)
    password = (password or "").strip()
    c = conn()
    row = c.execute("SELECT id,password_hash FROM users WHERE email=?", (email,)).fetchone()
    c.close()
    if not row:
        return None
    if row["password_hash"] != sha256(password):
        return None
    return int(row["id"])

def reset_password(email: str, new_password: str):
    email = normalize_email(email)
    new_password = (new_password or "").strip()
    if not email or "@" not in email:
        return False, "Enter a valid email."
    if len(new_password) < 6:
        return False, "Password must be at least 6 characters."
    c = conn()
    cur = c.cursor()
    cur.execute("UPDATE users SET password_hash=? WHERE email=?",
                (sha256(new_password), email))
    changed = cur.rowcount
    c.commit()
    c.close()
    return (True, "Password updated. Please sign in.") if changed else (False, "Email not found.")

# ------------------------------
# Session token in URL (?t=...)
# ------------------------------
def get_query_token() -> str:
    try:
        return (st.query_params.get("t") or "")
    except Exception:
        qp = st.experimental_get_query_params()
        return qp.get("t", [""])[0] if qp else ""

def set_query_token(token: str):
    try:
        st.query_params["t"] = token
    except Exception:
        st.experimental_set_query_params(t=token)

def clear_query_token():
    try:
        st.query_params.clear()
    except Exception:
        st.experimental_set_query_params()

def create_session(user_id: int) -> str:
    token = uuid.uuid4().hex + uuid.uuid4().hex
    exp = (datetime.now() + timedelta(days=SESSION_DAYS)).replace(microsecond=0).isoformat()
    c = conn()
    c.execute("INSERT INTO sessions(token,user_id,created_at,expires_at) VALUES(?,?,?,?)",
              (token, user_id, now_iso(), exp))
    c.commit()
    c.close()
    return token

def load_session(token: str) -> Optional[int]:
    token = (token or "").strip()
    if not token:
        return None
    c = conn()
    row = c.execute("SELECT user_id, expires_at FROM sessions WHERE token=?", (token,)).fetchone()
    c.close()
    if not row:
        return None
    if datetime.fromisoformat(row["expires_at"]) < datetime.now().replace(microsecond=0):
        return None
    return int(row["user_id"])

def logout():
    clear_query_token()
    for k in ["user_id", "route", "session_token"]:
        st.session_state.pop(k, None)

# ------------------------------
# Autorefresh every 15s (for BG rotate)
# ------------------------------
def _autorefresh_15s() -> int:
    if hasattr(st, "autorefresh"):
        return st.autorefresh(interval=15000, key="auth_bg_refresh")
    try:
        from streamlit_autorefresh import st_autorefresh
        return st_autorefresh(interval=15000, key="auth_bg_refresh")
    except Exception:
        import time
        return int(time.time() // 15)

# ------------------------------
# GLOBAL SUPER UI CSS (auth-only)
# ------------------------------
def inject_auth_ui():
    # rotate bg
    count = _autorefresh_15s()
    bg_paths = [
        os.path.join(ASSETS_DIR, "bg1.png"),
        os.path.join(ASSETS_DIR, "bg2.png"),
        os.path.join(ASSETS_DIR, "bg3.png"),
    ]
    bg_paths = [p for p in bg_paths if os.path.exists(p)]
    bg = _data_url(bg_paths[count % len(bg_paths)]) if bg_paths else ""

    # optional logo + google logo
    logo = _data_url(os.path.join(ASSETS_DIR, "logo.png"))
    g_logo = _data_url(os.path.join(ASSETS_DIR, "google_logo.png"))

    st.markdown(
        f"""
        <style>
          /* Hide Streamlit chrome */
          #MainMenu {{visibility:hidden;}}
          header {{visibility:hidden;}}
          footer {{visibility:hidden;}}

          /* Fade animation */
          @keyframes rbFade {{
            0% {{ opacity: 0; transform: scale(1.01); }}
            100% {{ opacity: 1; transform: scale(1.0); }}
          }}

          /* Full background */
          .stApp {{
            background:
              radial-gradient(1200px 900px at 10% 0%, rgba(255,122,26,0.16), transparent 55%),
              radial-gradient(900px 700px at 90% 10%, rgba(99,102,241,0.14), transparent 55%),
              linear-gradient(180deg, rgba(15,23,42,0.10), rgba(15,23,42,0.02)),
              url("{bg}");
            background-size: cover;
            background-position: center;
            background-repeat: no-repeat;
            background-attachment: fixed;
            animation: rbFade 0.55s ease-out;
          }}

          section.main > div.block-container {{
            padding-top: 4vh;
            padding-bottom: 6vh;
            max-width: 1100px;
          }}

          /* Auth Layout */
          .rb-shell {{
            max-width: 440px;
            margin: 0 auto;
          }}

          .rb-top {{
            display:flex;
            align-items:center;
            justify-content:center;
            flex-direction:column;
            text-align:center;
            margin-bottom: 14px;
          }}

          .rb-logo {{
            width: 64px;
            height: 64px;
            border-radius: 18px;
            overflow:hidden;
            border: 1px solid rgba(226,232,240,0.9);
            background: rgba(255,255,255,0.7);
            box-shadow: 0 20px 60px rgba(2,6,23,0.18);
            backdrop-filter: blur(10px);
            display:flex;
            align-items:center;
            justify-content:center;
          }}
          .rb-logo img {{
            width:100%; height:100%; object-fit:cover;
          }}

          .rb-brand {{
            margin-top: 10px;
            font-weight: 950;
            letter-spacing: 0.2px;
            font-size: 22px;
            color: #0f172a;
            text-shadow: 0 2px 20px rgba(255,255,255,0.4);
          }}

          .rb-tag {{
            margin-top: 5px;
            font-size: 13px;
            color: rgba(15,23,42,0.72);
          }}

          /* Glass card */
          .rb-card {{
            border-radius: 24px;
            border: 1px solid rgba(226,232,240,0.85);
            background: rgba(255,255,255,0.72);
            box-shadow: 0 28px 90px rgba(2,6,23,0.22);
            backdrop-filter: blur(14px);
            -webkit-backdrop-filter: blur(14px);
            padding: 18px 18px 12px 18px;
          }}

          .rb-h1 {{
            font-size: 28px;
            font-weight: 950;
            color:#0f172a;
            margin: 0;
          }}
          .rb-sub {{
            margin-top: 6px;
            font-size: 13px;
            color: rgba(15,23,42,0.70);
          }}

          /* Inputs */
          .stTextInput input {{
            height: 46px !important;
            border-radius: 14px !important;
            border: 1px solid rgba(203,213,225,0.9) !important;
            background: rgba(255,255,255,0.85) !important;
          }}

          /* Buttons */
          .stButton>button {{
            border-radius: 14px !important;
            padding: 0.65rem 0.95rem !important;
            font-weight: 900 !important;
            border: 1px solid rgba(203,213,225,0.95) !important;
            background: rgba(255,255,255,0.95) !important;
            color:#0f172a !important;
          }}
          .stButton>button:hover {{
            background: rgba(248,250,252,1) !important;
            border-color: rgba(148,163,184,1) !important;
          }}
          .stButton>button[kind="primary"] {{
            background: linear-gradient(135deg, #ff7a1a, #ff4d4d) !important;
            border: 0 !important;
            color: white !important;
            box-shadow: 0 18px 50px rgba(255, 122, 26, 0.26) !important;
          }}

          /* Divider OR */
          .rb-or {{
            display:flex; align-items:center; gap:10px;
            margin: 14px 0 10px 0;
            color: rgba(15,23,42,0.50);
            font-size: 12px; font-weight: 900;
          }}
          .rb-or::before, .rb-or::after {{
            content:""; height:1px; flex:1;
            background: rgba(203,213,225,0.9);
          }}

          /* Google button (HTML) */
          .rb-google {{
            width:100%;
            display:flex;
            align-items:center;
            justify-content:center;
            gap:10px;
            border-radius: 14px;
            border: 1px solid rgba(203,213,225,0.95);
            background: rgba(255,255,255,0.95);
            padding: 10px 12px;
            font-weight: 950;
            cursor:pointer;
            user-select:none;
          }}
          .rb-google:hover {{
            background: rgba(248,250,252,1);
            border-color: rgba(148,163,184,1);
          }}
          .rb-google img {{
            width: 18px; height: 18px;
          }}

          /* Footer links */
          .rb-foot {{
            text-align:center;
            margin-top: 10px;
            font-size: 12px;
            color: rgba(15,23,42,0.62);
          }}
          .rb-link {{
            font-weight: 950;
            color:#0f172a;
            text-decoration:none;
          }}
          .rb-link:hover {{ text-decoration:underline; }}

          @media (max-width: 520px){{
            section.main > div.block-container {{ padding-top: 2.5vh; }}
            .rb-card {{ padding: 16px 14px 10px 14px; }}
          }}
        </style>

        <script>
          // provide logos to JS if needed in future
          window.RB_LOGO = "{logo}";
          window.RB_GOOGLE_LOGO = "{g_logo}";
        </script>
        """,
        unsafe_allow_html=True
    )

    # top header
    st.markdown("<div class='rb-shell'>", unsafe_allow_html=True)
    if logo:
        st.markdown(
            f"""
            <div class="rb-top">
              <div class="rb-logo"><img src="{logo}"/></div>
              <div class="rb-brand">{APP_NAME}</div>
              <div class="rb-tag">Find homes in Berlin • message instantly • save favorites</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    else:
        st.markdown(
            f"""
            <div class="rb-top">
              <div class="rb-logo" style="font-size:26px;">🏠</div>
              <div class="rb-brand">{APP_NAME}</div>
              <div class="rb-tag">Find homes in Berlin • message instantly • save favorites</div>
            </div>
            """,
            unsafe_allow_html=True
        )

def auth_wrap_open(title: str, subtitle: str):
    st.markdown("<div class='rb-card'>", unsafe_allow_html=True)
    st.markdown(f"<div class='rb-h1'>{title}</div>", unsafe_allow_html=True)
    st.markdown(f"<div class='rb-sub'>{subtitle}</div>", unsafe_allow_html=True)
    st.write("")

def auth_wrap_close():
    st.markdown("</div>", unsafe_allow_html=True)  # rb-card
    st.markdown("</div>", unsafe_allow_html=True)  # rb-shell

# ------------------------------
# Google button (UI) -> call your google handler when clicked
# ------------------------------
def google_button_ui() -> bool:
    g_logo_path = os.path.join(ASSETS_DIR, "google_logo.png")
    g = _data_url(g_logo_path)
    # Using normal st.button for reliable clicks, but styled with html above would need components.
    # This is still professional.
    cols = st.columns([1])
    with cols[0]:
        return st.button("Continue with Google", use_container_width=True, key="rb_google_btn")

# ------------------------------
# PAGES
# ------------------------------
def page_login():
    inject_auth_ui()
    auth_wrap_open("Sign in", "Use your email & password to continue.")

    with st.form("login_form"):
        email = st.text_input("Email", placeholder="name@email.com")
        password = st.text_input("Password", type="password", placeholder="Minimum 6 characters")
        ok = st.form_submit_button("Sign in", type="primary", use_container_width=True)

    c1, c2 = st.columns([1, 1])
    with c1:
        if st.button("Create account", use_container_width=True):
            st.session_state["route"] = "signup"
            st.rerun()
    with c2:
        if st.button("Forgot password", use_container_width=True):
            st.session_state["route"] = "reset"
            st.rerun()

    st.markdown("<div class='rb-or'>OR</div>", unsafe_allow_html=True)

    # If you already have real Google OAuth code, call it here instead.
    # Example: if google_button_ui(): start_google_oauth()
    if google_button_ui():
        st.info("✅ Google button clicked. Call your Google OAuth function here.")

    if ok:
        uid = authenticate(email, password)
        if not uid:
            st.error("Wrong email or password.")
        else:
            token = create_session(uid)
            st.session_state["user_id"] = uid
            st.session_state["session_token"] = token
            set_query_token(token)
            st.session_state["route"] = "app"
            st.rerun()

    st.markdown(
        "<div class='rb-foot'>By continuing you agree to our <a class='rb-link' href='#'>Terms</a> and <a class='rb-link' href='#'>Privacy</a>.</div>",
        unsafe_allow_html=True
    )
    auth_wrap_close()

def page_signup():
    inject_auth_ui()
    auth_wrap_open("Create account", "Create an account in seconds. No spam.")

    with st.form("signup_form"):
        email = st.text_input("Email", placeholder="name@email.com")
        password = st.text_input("Password", type="password", placeholder="At least 6 characters")
        ok = st.form_submit_button("Create account", type="primary", use_container_width=True)

    if st.button("Back to Sign in", use_container_width=True):
        st.session_state["route"] = "login"
        st.rerun()

    st.markdown("<div class='rb-or'>OR</div>", unsafe_allow_html=True)
    if google_button_ui():
        st.info("✅ Google button clicked. Call your Google OAuth function here.")

    if ok:
        ok2, msg = create_user(email, password)
        if ok2:
            st.success(msg)
            st.session_state["route"] = "login"
            st.rerun()
        else:
            st.error(msg)

    auth_wrap_close()

def page_reset():
    inject_auth_ui()
    auth_wrap_open("Reset password", "Set a new password for your account.")

    with st.form("reset_form"):
        email = st.text_input("Email", placeholder="name@email.com")
        new_password = st.text_input("New password", type="password", placeholder="At least 6 characters")
        ok = st.form_submit_button("Update password", type="primary", use_container_width=True)

    if st.button("Back to Sign in", use_container_width=True):
        st.session_state["route"] = "login"
        st.rerun()

    if ok:
        ok2, msg = reset_password(email, new_password)
        if ok2:
            st.success(msg)
            st.session_state["route"] = "login"
            st.rerun()
        else:
            st.error(msg)

    auth_wrap_close()

# ------------------------------
# Router (minimal)
# ------------------------------
def run_auth_app():
    init_db()

    # auto-login from token
    tok = get_query_token()
    if tok and not st.session_state.get("user_id"):
        uid = load_session(tok)
        if uid:
            st.session_state["user_id"] = uid
            st.session_state["session_token"] = tok
            st.session_state["route"] = "app"

    route = st.session_state.get("route") or ("app" if st.session_state.get("user_id") else "login")

    if route == "signup":
        page_signup()
    elif route == "reset":
        page_reset()
    elif route == "app":
        st.success("✅ Logged in! (Replace this with your real app pages)")
        if st.button("Logout"):
            logout()
            st.session_state["route"] = "login"
            st.rerun()
    else:
        page_login()

# CALL THIS at bottom of your file:
# run_auth_app()
