# main.py
# Run: streamlit run main.py
#
# ONE-FILE Streamlit app:
# - Professional centered Login / Signup / Reset
# - Email+Password auth (SQLite)
# - Persistent login via URL token (?t=...)
# - Optional REAL Google OAuth (Authlib + secrets)
# - Apple button UI (real Apple OAuth needs Apple Developer keys)
#
# Folder (optional):
#   assets/logo.png

import os
import re
import uuid
import time
import base64
import sqlite3
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

import streamlit as st

# Optional: REAL Google OAuth
try:
    from authlib.integrations.requests_client import OAuth2Session
    AUTHLIB_OK = True
except Exception:
    AUTHLIB_OK = False


# =============================
# CONFIG
# =============================
APP_NAME = "RentinBerlin"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "rentinberlin.db")
ASSETS_DIR = os.path.join(BASE_DIR, "assets")
os.makedirs(ASSETS_DIR, exist_ok=True)

SESSION_DAYS = 30
REGISTRATION_ENABLED = True


# =============================
# HELPERS
# =============================
def now_iso() -> str:
    return datetime.now().replace(microsecond=0).isoformat()


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def normalize_email(e: str) -> str:
    return (e or "").strip().lower()


def normalize_phone(p: str) -> str:
    p = (p or "").strip()
    p = re.sub(r"[^\d+]", "", p)
    return p[:25]


def sanitize_username(u: str) -> str:
    u = (u or "").strip().lower()
    u = re.sub(r"[^a-z0-9._]", "", u)
    return u[:30]


def asset_path(name: str) -> str:
    p = os.path.join(ASSETS_DIR, name)
    return p if os.path.exists(p) else ""


def _img_to_b64(path: str) -> str:
    with open(path, "rb") as f:
        return base64.b64encode(f.read()).decode("utf-8")


# =============================
# QUERY TOKEN
# =============================
def get_query_token() -> str:
    try:
        return (st.query_params.get("t") or "")
    except Exception:
        pass
    try:
        qp = st.experimental_get_query_params()
        return (qp.get("t", [""])[0]) if qp else ""
    except Exception:
        return ""


def set_query_token(token: str):
    try:
        st.query_params["t"] = token
        return
    except Exception:
        pass
    try:
        st.experimental_set_query_params(t=token)
    except Exception:
        pass


def clear_query_token():
    try:
        st.query_params.clear()
        return
    except Exception:
        pass
    try:
        st.experimental_set_query_params()
    except Exception:
        pass


# =============================
# DB
# =============================
def conn() -> sqlite3.Connection:
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL;")
    c.execute("PRAGMA synchronous=NORMAL;")
    c.execute("PRAGMA busy_timeout=8000;")
    return c


def init_db():
    if st.session_state.get("_db_inited"):
        return

    c = conn()
    cur = c.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        phone TEXT,
        password_hash TEXT NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS profiles (
        user_id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        display_name TEXT,
        updated_at TEXT NOT NULL
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
    st.session_state["_db_inited"] = True


def ensure_profile_for_user(user_id: int, email: str):
    email = normalize_email(email)
    base_username = sanitize_username(email.split("@")[0]) or "user"
    c = conn()
    cur = c.cursor()
    row = cur.execute("SELECT user_id FROM profiles WHERE user_id=?", (user_id,)).fetchone()
    if row:
        c.close()
        return

    suffix = 0
    while True:
        try_u = base_username if suffix == 0 else f"{base_username}{suffix}"
        try:
            cur.execute(
                "INSERT INTO profiles (user_id, username, display_name, updated_at) VALUES (?,?,?,?)",
                (user_id, try_u, "", now_iso())
            )
            c.commit()
            c.close()
            return
        except sqlite3.IntegrityError:
            suffix += 1
            if suffix > 9999:
                c.close()
                return


# =============================
# AUTH (EMAIL/PASSWORD)
# =============================
def create_user(email: str, phone: str, password: str):
    email = normalize_email(email)
    phone = normalize_phone(phone)
    password = (password or "").strip()

    if not email or "@" not in email:
        return False, "Enter a valid email."
    if len(password) < 6:
        return False, "Password must be at least 6 characters."

    c = conn()
    cur = c.cursor()
    try:
        cur.execute(
            "INSERT INTO users (created_at, email, phone, password_hash) VALUES (?,?,?,?)",
            (now_iso(), email, phone, sha256(password))
        )
        c.commit()
        user_id = int(cur.lastrowid)
        c.close()
        ensure_profile_for_user(user_id, email)
        return True, "Account created. You can sign in now."
    except sqlite3.IntegrityError:
        c.close()
        return False, "Email already exists."


def authenticate(email: str, password: str) -> Optional[int]:
    email = normalize_email(email)
    password = (password or "").strip()
    if not email or not password:
        return None

    c = conn()
    row = c.execute("SELECT id, email, password_hash FROM users WHERE email=?", (email,)).fetchone()
    c.close()
    if not row:
        return None
    if row["password_hash"] != sha256(password):
        return None

    uid = int(row["id"])
    ensure_profile_for_user(uid, row["email"])
    return uid


def reset_password(email: str, new_password: str):
    email = normalize_email(email)
    new_password = (new_password or "").strip()

    if not email or "@" not in email:
        return False, "Enter a valid email."
    if len(new_password) < 6:
        return False, "New password must be at least 6 characters."

    c = conn()
    cur = c.cursor()
    cur.execute("UPDATE users SET password_hash=? WHERE email=?", (sha256(new_password), email))
    changed = cur.rowcount
    c.commit()
    c.close()

    return (True, "Password reset. Please sign in.") if changed else (False, "Email not found.")


def get_user(uid: int) -> Dict[str, Any]:
    c = conn()
    row = c.execute("""
        SELECT u.id, u.email, u.phone,
               COALESCE(p.username,'') AS username,
               COALESCE(p.display_name,'') AS display_name
        FROM users u
        LEFT JOIN profiles p ON p.user_id=u.id
        WHERE u.id=?
    """, (uid,)).fetchone()
    c.close()
    return dict(row) if row else {}


# =============================
# SESSIONS (PERSISTENT LOGIN)
# =============================
def create_session(user_id: int) -> str:
    token = uuid.uuid4().hex + uuid.uuid4().hex
    expires_at = (datetime.now() + timedelta(days=SESSION_DAYS)).replace(microsecond=0).isoformat()

    c = conn()
    cur = c.cursor()
    cur.execute("""
        INSERT INTO sessions (token, user_id, created_at, last_seen, expires_at)
        VALUES (?,?,?,?,?)
    """, (token, user_id, now_iso(), now_iso(), expires_at))
    c.commit()
    c.close()
    return token


def load_session_from_token(token: str) -> Optional[int]:
    token = (token or "").strip()
    if not token:
        return None

    c = conn()
    row = c.execute("SELECT user_id, expires_at FROM sessions WHERE token=?", (token,)).fetchone()
    if not row:
        c.close()
        return None

    exp = datetime.fromisoformat(row["expires_at"])
    if exp < datetime.now().replace(microsecond=0):
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
    c = conn()
    c.execute("DELETE FROM sessions WHERE token=?", (token,))
    c.commit()
    c.close()


def logout():
    tok = st.session_state.get("session_token") or get_query_token()
    if tok:
        delete_session(tok)
    clear_query_token()
    for k in list(st.session_state.keys()):
        if k in ["user_id", "route", "session_token"]:
            st.session_state.pop(k, None)


# =============================
# OPTIONAL: REAL GOOGLE OAUTH
# =============================
def google_oauth_is_configured() -> bool:
    if not AUTHLIB_OK:
        return False
    try:
        _ = st.secrets["GOOGLE_CLIENT_ID"]
        _ = st.secrets["GOOGLE_CLIENT_SECRET"]
        _ = st.secrets["GOOGLE_REDIRECT_URI"]
        return True
    except Exception:
        return False


def google_oauth_login_button(label: str = "Continue with Google"):
    # If not configured, show a button but explain
    if not google_oauth_is_configured():
        if st.button(label, use_container_width=True, key="google_btn_not_ready"):
            st.info("Google login is not configured yet. Add Authlib + Google secrets in Streamlit.")
        return

    client_id = st.secrets["GOOGLE_CLIENT_ID"]
    client_secret = st.secrets["GOOGLE_CLIENT_SECRET"]
    redirect_uri = st.secrets["GOOGLE_REDIRECT_URI"]

    oauth = OAuth2Session(
        client_id=client_id,
        scope="openid email profile",
        redirect_uri=redirect_uri,
    )

    # Callback handler
    qp = {}
    try:
        qp = dict(st.query_params)
    except Exception:
        qp = st.experimental_get_query_params() or {}

    code = qp.get("code", "")
    if isinstance(code, list):
        code = code[0] if code else ""

    if code:
        try:
            oauth.fetch_token(
                "https://oauth2.googleapis.com/token",
                code=code,
                client_secret=client_secret,
            )
            userinfo = oauth.get("https://openidconnect.googleapis.com/v1/userinfo").json()
            email = normalize_email(userinfo.get("email", ""))

            if not email:
                st.error("Google login failed: no email returned.")
                return

            # Get or create local user
            c = conn()
            row = c.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
            if row:
                uid = int(row["id"])
                c.close()
            else:
                # Create with random password (user can reset later)
                pw = uuid.uuid4().hex[:10] + "A!"
                cur = c.cursor()
                cur.execute(
                    "INSERT INTO users (created_at, email, phone, password_hash) VALUES (?,?,?,?)",
                    (now_iso(), email, "", sha256(pw))
                )
                c.commit()
                uid = int(cur.lastrowid)
                c.close()
                ensure_profile_for_user(uid, email)

            # Clean params
            clear_query_token()  # removes all; then we set our session token again below

            # Login
            token = create_session(uid)
            st.session_state["user_id"] = uid
            st.session_state["session_token"] = token
            set_query_token(token)
            st.session_state["route"] = "app"
            st.rerun()
        except Exception as e:
            st.error(f"Google login failed: {e}")
        return

    # Start OAuth
    auth_url, _state = oauth.create_authorization_url(
        "https://accounts.google.com/o/oauth2/v2/auth",
        access_type="offline",
        prompt="select_account",
    )
    if st.button(label, use_container_width=True, key="google_btn_start"):
        st.markdown(f"<meta http-equiv='refresh' content='0; url={auth_url}'>", unsafe_allow_html=True)


# =============================
# UI STYLE (GLOBAL)
# =============================
def inject_style():
    st.markdown(
        """
        <style>
          .stApp { background: #f6f8fb; }
          section.main > div.block-container { padding-top: 0.7rem; padding-bottom: 4.5rem; max-width: 1280px; }

          #MainMenu {visibility: hidden;}
          footer {visibility: hidden;}
          header {visibility: hidden;}

          @media (max-width: 768px) {
            section.main > div.block-container { padding-left: 0.75rem; padding-right: 0.75rem; }
            .stButton>button { padding: 0.5rem 0.7rem !important; font-size: 12px !important; }
          }

          .stButton>button {
            border-radius: 14px !important;
            border: 1px solid rgba(226,232,240,1) !important;
            background: #ffffff !important;
            color: #0f172a !important;
            padding: 0.60rem 0.95rem !important;
            font-weight: 900 !important;
          }
          .stButton>button:hover {
            border-color: rgba(203,213,225,1) !important;
            background: #fbfdff !important;
          }
          .stButton>button[kind="primary"] {
            background: #ff7a1a !important;
            border-color: #ff7a1a !important;
            color: white !important;
            box-shadow: 0 10px 30px rgba(255, 122, 26, 0.20) !important;
          }

          .stTextInput input {
            border-radius: 14px !important;
            height: 46px !important;
          }

          /* =============================
             AUTH UI (Professional Center)
             ============================= */
          .rb-auth-shell{
            max-width: 430px;
            margin: 0 auto;
            padding-top: 5.5vh;
            padding-bottom: 6vh;
          }
          @media (max-width: 900px){
            .rb-auth-shell{ max-width: 94vw; padding-top: 3vh; }
          }
          .rb-auth-top{
            display:flex;
            flex-direction:column;
            align-items:center;
            text-align:center;
            margin-bottom: 14px;
          }
          .rb-auth-logo{
            width: 66px;
            height: 66px;
            border-radius: 18px;
            overflow:hidden;
            background: #ffffff;
            border: 1px solid #eef2f7;
            box-shadow: 0 18px 45px rgba(16, 24, 40, 0.10);
            display:flex;
            align-items:center;
            justify-content:center;
          }
          .rb-auth-logo img{ width:100%; height:100%; object-fit:cover; display:block; border:0 !important; }
          .rb-auth-appname{
            margin-top: 10px;
            font-weight: 950;
            font-size: 22px;
            letter-spacing: 0.2px;
            color:#0f172a;
          }
          .rb-auth-tagline{
            margin-top: 6px;
            font-size: 13px;
            color:#64748b;
          }
          .rb-auth-card{
            background: rgba(255,255,255,0.92);
            border: 1px solid #eef2f7;
            border-radius: 22px;
            box-shadow: 0 26px 70px rgba(16,24,40,0.10);
            padding: 18px 18px 14px 18px;
            backdrop-filter: blur(8px);
          }
          .rb-auth-h1{
            font-weight: 950;
            font-size: 28px;
            margin: 0;
            color:#0f172a;
          }
          .rb-auth-sub{
            margin-top: 6px;
            color:#64748b;
            font-size: 13px;
          }
          .rb-auth-divider{
            display:flex;
            align-items:center;
            gap:10px;
            margin: 14px 0;
            color:#94a3b8;
            font-size: 12px;
            font-weight: 900;
          }
          .rb-auth-divider:before,
          .rb-auth-divider:after{
            content:"";
            height:1px;
            flex:1;
            background:#e5e7eb;
          }
          .rb-auth-foot{
            margin-top: 10px;
            text-align:center;
            font-size: 12px;
            color:#64748b;
          }
          .rb-link{
            color:#0f172a;
            font-weight: 950;
            text-decoration: none;
          }
          .rb-link:hover{ text-decoration: underline; }
          .rb-forgot-wrap{
            display:flex;
            justify-content:flex-end;
            margin-top: -6px;
            margin-bottom: 10px;
          }
          .rb-forgot-wrap button{
            padding: 0.2rem 0.45rem !important;
            border-radius: 10px !important;
            font-size: 12px !important;
            background: transparent !important;
            border: 1px solid transparent !important;
            color:#0f172a !important;
            box-shadow:none !important;
          }
          .rb-forgot-wrap button:hover{
            background:#f8fafc !important;
            border-color:#e5e7eb !important;
          }
        </style>
        """,
        unsafe_allow_html=True
    )


# =============================
# PAGES
# =============================
def auth_header(tagline: str):
    st.markdown(
        """
        <style>
          .stApp { background:
            radial-gradient(1200px 800px at 10% 0%, rgba(255,122,26,0.10), transparent 55%),
            radial-gradient(900px 700px at 90% 10%, rgba(99,102,241,0.10), transparent 50%),
            #f6f8fb !important; }
        </style>
        """,
        unsafe_allow_html=True
    )
    st.markdown("<div class='rb-auth-shell'>", unsafe_allow_html=True)

    logo = asset_path("logo.png")
    if logo and os.path.exists(logo):
        b64 = _img_to_b64(logo)
        st.markdown(
            f"""
            <div class="rb-auth-top">
              <div class="rb-auth-logo"><img src="data:image/png;base64,{b64}" /></div>
              <div class="rb-auth-appname">{APP_NAME}</div>
              <div class="rb-auth-tagline">{tagline}</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    else:
        st.markdown(
            f"""
            <div class="rb-auth-top">
              <div class="rb-auth-logo">🏠</div>
              <div class="rb-auth-appname">{APP_NAME}</div>
              <div class="rb-auth-tagline">{tagline}</div>
            </div>
            """,
            unsafe_allow_html=True
        )


def auth_footer_close():
    st.markdown("</div>", unsafe_allow_html=True)  # rb-auth-shell


def page_login():
    auth_header("Apartments in Berlin • fast messaging • verified community")

    st.markdown("<div class='rb-auth-card'>", unsafe_allow_html=True)
    st.markdown("<div class='rb-auth-h1'>Sign in</div>", unsafe_allow_html=True)
    st.markdown("<div class='rb-auth-sub'>Use your email & password to continue.</div>", unsafe_allow_html=True)
    st.write("")

    with st.form("login_form"):
        email = st.text_input("Email", placeholder="name@email.com")
        password = st.text_input("Password", type="password", placeholder="Minimum 6 characters")
        submitted = st.form_submit_button("Sign in", type="primary", use_container_width=True)

    st.markdown("<div class='rb-forgot-wrap'>", unsafe_allow_html=True)
    if st.button("Forgot password?", key="forgot_pw_btn"):
        st.session_state["route"] = "reset"
        st.rerun()
    st.markdown("</div>", unsafe_allow_html=True)

    if submitted:
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

    st.markdown("<div class='rb-auth-divider'>or</div>", unsafe_allow_html=True)

    google_oauth_login_button("Continue with Google")

    if st.button("Continue with Apple", use_container_width=True, key="apple_btn"):
        st.info("Apple login needs Apple Developer keys. The UI is ready; the integration requires setup.")

    st.write("")
    if REGISTRATION_ENABLED:
        st.markdown("<div class='rb-auth-foot'>New to RentinBerlin?</div>", unsafe_allow_html=True)
        if st.button("Create account", use_container_width=True, key="go_register", type="primary"):
            st.session_state["route"] = "register"
            st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)  # card
    auth_footer_close()


def page_register():
    auth_header("Create your account in under a minute.")

    st.markdown("<div class='rb-auth-card'>", unsafe_allow_html=True)
    st.markdown("<div class='rb-auth-h1'>Create account</div>", unsafe_allow_html=True)
    st.markdown("<div class='rb-auth-sub'>Email, password, and you’re in.</div>", unsafe_allow_html=True)
    st.write("")

    with st.form("register_form"):
        email = st.text_input("Email", placeholder="name@email.com")
        phone = st.text_input("Phone (optional)", placeholder="+49 …")
        password = st.text_input("Password", type="password", placeholder="Minimum 6 characters")
        st.caption("Tip: password 6+ characters. Username is generated from your email.")
        submitted = st.form_submit_button("Create account", type="primary", use_container_width=True)

    if submitted:
        ok, msg = create_user(email, phone, password)
        if ok:
            st.success(msg)
            st.session_state["route"] = "login"
            st.rerun()
        else:
            st.error(msg)

    st.markdown("<div class='rb-auth-divider'>or</div>", unsafe_allow_html=True)
    google_oauth_login_button("Continue with Google")

    if st.button("Continue with Apple", use_container_width=True, key="apple_btn_reg"):
        st.info("Apple login needs Apple Developer keys. The UI is ready; the integration requires setup.")

    st.write("")
    if st.button("Back to sign in", use_container_width=True, key="back_to_login"):
        st.session_state["route"] = "login"
        st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)  # card
    auth_footer_close()


def page_reset():
    auth_header("Reset your password securely.")

    st.markdown("<div class='rb-auth-card'>", unsafe_allow_html=True)
    st.markdown("<div class='rb-auth-h1'>Reset password</div>", unsafe_allow_html=True)
    st.markdown("<div class='rb-auth-sub'>Enter your email and choose a new password.</div>", unsafe_allow_html=True)
    st.write("")

    with st.form("reset_form"):
        email = st.text_input("Email", placeholder="name@email.com")
        new_password = st.text_input("New password", type="password", placeholder="Minimum 6 characters")
        submitted = st.form_submit_button("Reset password", type="primary", use_container_width=True)

    if submitted:
        ok, msg = reset_password(email, new_password)
        if ok:
            st.success(msg)
            st.session_state["route"] = "login"
            st.rerun()
        else:
            st.error(msg)

    if st.button("Back to sign in", use_container_width=True, key="back_login_reset"):
        st.session_state["route"] = "login"
        st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)  # card
    auth_footer_close()


def page_app(uid: int):
    user = get_user(uid)

    st.markdown(
        f"""
        <div style="
          background:#ffffff;
          border:1px solid #eef2f7;
          border-radius:18px;
          box-shadow:0 18px 45px rgba(16,24,40,0.06);
          padding:16px;
          max-width:900px;
          margin: 0 auto;
        ">
          <div style="font-weight:950;font-size:22px;color:#0f172a;">
            Welcome, @{user.get("username","user")}
          </div>
          <div style="color:#64748b;margin-top:6px;">
            You are logged in as <b>{user.get("email","")}</b>.
          </div>
          <div style="color:#64748b;margin-top:10px;">
            This is your protected area. Add your real pages here.
          </div>
        </div>
        """,
        unsafe_allow_html=True
    )
    st.write("")
    c = st.columns([1, 1, 2])
    with c[0]:
        if st.button("Logout", use_container_width=True):
            logout()
            st.session_state["route"] = "login"
            st.rerun()
    with c[1]:
        st.caption("")
    with c[2]:
        st.caption("")


# =============================
# MAIN
# =============================
def main():
    st.set_page_config(page_title=APP_NAME, page_icon="🏠", layout="wide")
    inject_style()
    init_db()

    st.session_state.setdefault("route", "login")

    # Auto login via token
    if not st.session_state.get("user_id"):
        tok = get_query_token()
        if tok:
            uid = load_session_from_token(tok)
            if uid:
                st.session_state["user_id"] = uid
                st.session_state["session_token"] = tok
                st.session_state["route"] = "app"

    uid = st.session_state.get("user_id")
    if not uid:
        route = st.session_state.get("route", "login")
        if route == "register":
            page_register()
        elif route == "reset":
            page_reset()
        else:
            st.session_state["route"] = "login"
            page_login()
        return

    st.session_state["route"] = "app"
    page_app(int(uid))


if __name__ == "__main__":
    main()
