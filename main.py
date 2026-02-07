# main.py
# Run: streamlit run main.py
#
# ONE-FILE Streamlit app:
# - Professional centered Login / Signup / Reset (mobile friendly)
# - Email+Password auth (SQLite)
# - Persistent login via URL token (?t=...)
# - REAL Google OAuth (Authlib + secrets)
# - Apple button UI (real Apple OAuth needs Apple Developer Program keys)
#
# Optional folder:
#   assets/logo.png

import os
import re
import uuid
import base64
import sqlite3
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

import streamlit as st
import streamlit.components.v1 as components

# Optional: REAL Google OAuth
try:
    import requests
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

# Google endpoints
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"


# =============================
# PAGE CONFIG
# =============================
logo_path = os.path.join(ASSETS_DIR, "logo.png")
page_icon = "🏠"
if os.path.exists(logo_path):
    page_icon = logo_path

st.set_page_config(
    page_title=APP_NAME,
    page_icon=page_icon,
    layout="centered",
)


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


def html_escape(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def json_escape(s: str) -> str:
    s = (s or "").replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return f"\"{s}\""


def redirect_js(url: str):
    # Works on mobile + Streamlit cloud
    components.html(
        f"<script>window.location.replace({json_escape(url)});</script>",
        height=0,
    )


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


def clear_all_query_params():
    try:
        st.query_params.clear()
        return
    except Exception:
        pass
    try:
        st.experimental_set_query_params()
    except Exception:
        pass


def get_query_param(name: str) -> str:
    try:
        v = st.query_params.get(name, "")
        return v or ""
    except Exception:
        pass
    try:
        qp = st.experimental_get_query_params() or {}
        v = qp.get(name, "")
        if isinstance(v, list):
            return v[0] if v else ""
        return v or ""
    except Exception:
        return ""


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
    clear_all_query_params()
    for k in list(st.session_state.keys()):
        if k in ["user_id", "route", "session_token", "google_state"]:
            st.session_state.pop(k, None)


# =============================
# REAL GOOGLE OAUTH (Authlib)
# =============================
def google_configured() -> bool:
    if not AUTHLIB_OK:
        return False
    try:
        _ = st.secrets["GOOGLE_CLIENT_ID"]
        _ = st.secrets["GOOGLE_CLIENT_SECRET"]
        _ = st.secrets["APP_BASE_URL"]
        return True
    except Exception:
        return False


def google_redirect_uri() -> str:
    # must match your Google console redirect
    base = (st.secrets.get("APP_BASE_URL") or "").rstrip("/")
    return f"{base}/"


def google_start():
    if not google_configured():
        st.info("Google login not configured. Add authlib + secrets.")
        return

    oauth = OAuth2Session(
        client_id=st.secrets["GOOGLE_CLIENT_ID"],
        client_secret=st.secrets["GOOGLE_CLIENT_SECRET"],
        scope="openid email profile",
        redirect_uri=google_redirect_uri(),
    )

    state = uuid.uuid4().hex
    st.session_state["google_state"] = state

    auth_url, _ = oauth.create_authorization_url(
        GOOGLE_AUTH_URL,
        state=state,
        prompt="select_account",
        include_granted_scopes="true",
        access_type="online",
    )
    redirect_js(auth_url)


def google_finish_if_callback():
    """
    If URL has ?code=...&state=..., exchange token, fetch user info,
    create local user, create session, then clean URL and go to app.
    """
    if not google_configured():
        return

    code = get_query_param("code")
    state = get_query_param("state")

    if not code:
        return

    expected = st.session_state.get("google_state")
    if expected and state and state != expected:
        st.error("Google login security check failed (state mismatch). Try again.")
        return

    try:
        oauth = OAuth2Session(
            client_id=st.secrets["GOOGLE_CLIENT_ID"],
            client_secret=st.secrets["GOOGLE_CLIENT_SECRET"],
            scope="openid email profile",
            redirect_uri=google_redirect_uri(),
        )
        token = oauth.fetch_token(
            GOOGLE_TOKEN_URL,
            code=code,
            grant_type="authorization_code",
        )

        r = requests.get(
            GOOGLE_USERINFO_URL,
            headers={"Authorization": f"Bearer {token['access_token']}"},
            timeout=20,
        )
        if r.status_code != 200:
            st.error("Google login failed (userinfo).")
            return

        info = r.json()
        email = normalize_email(info.get("email", ""))
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

        # Create our session token
        sess_token = create_session(uid)
        st.session_state["user_id"] = uid
        st.session_state["session_token"] = sess_token

        # Clean URL params then set our token param
        clear_all_query_params()
        set_query_token(sess_token)

        st.session_state["route"] = "app"
        st.rerun()

    except Exception as e:
        st.error(f"Google login failed: {e}")


# =============================
# UI STYLE (GLOBAL)
# =============================
def inject_style():
    st.markdown(
        """
        <style>
          .stApp { background: #f6f8fb; }
          section.main > div.block-container { padding-top: 0.8rem; padding-bottom: 3.5rem; max-width: 980px; }
          #MainMenu {visibility: hidden;}
          footer {visibility: hidden;}
          header {visibility: hidden;}

          /* Buttons */
          .stButton>button {
            border-radius: 14px !important;
            border: 1px solid rgba(226,232,240,1) !important;
            background: #ffffff !important;
            color: #0f172a !important;
            padding: 0.62rem 0.95rem !important;
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

          /* Inputs */
          .stTextInput input {
            border-radius: 14px !important;
            height: 46px !important;
          }

          /* Auth shell */
          .rb-auth-shell{
            max-width: 430px;
            margin: 0 auto;
            padding-top: 4.5vh;
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
            font-size: 28px;
            font-weight: 950;
            color:#0f172a;
          }
          .rb-auth-logo img{ width:100%; height:100%; object-fit:cover; display:block; }
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

          .rb-note{
            font-size: 12px;
            color:#64748b;
            margin-top: 8px;
          }
        </style>
        """,
        unsafe_allow_html=True
    )


# =============================
# AUTH UI COMPONENTS
# =============================
def auth_background():
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


def auth_header(tagline: str):
    auth_background()
    st.markdown("<div class='rb-auth-shell'>", unsafe_allow_html=True)

    logo = asset_path("logo.png")
    if logo and os.path.exists(logo):
        b64 = _img_to_b64(logo)
        st.markdown(
            f"""
            <div class="rb-auth-top">
              <div class="rb-auth-logo"><img src="data:image/png;base64,{b64}" /></div>
              <div class="rb-auth-appname">{html_escape(APP_NAME)}</div>
              <div class="rb-auth-tagline">{html_escape(tagline)}</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    else:
        st.markdown(
            f"""
            <div class="rb-auth-top">
              <div class="rb-auth-logo">🏠</div>
              <div class="rb-auth-appname">{html_escape(APP_NAME)}</div>
              <div class="rb-auth-tagline">{html_escape(tagline)}</div>
            </div>
            """,
            unsafe_allow_html=True
        )


def auth_footer_close():
    st.markdown("</div>", unsafe_allow_html=True)  # rb-auth-shell


def oauth_buttons():
    # Google
    if google_configured():
        if st.button("Continue with Google", type="primary", use_container_width=True, key="google_btn"):
            google_start()
    else:
        if st.button("Continue with Google", use_container_width=True, key="google_disabled"):
            st.info("Google login not configured yet. Add secrets + requirements.txt (authlib).")

    # Apple (UI only)
    if st.button("Continue with Apple", use_container_width=True, key="apple_btn"):
        st.warning("Apple Sign-In needs Apple Developer Program (€99/year) + keys. UI is ready, integration needs setup.")


# =============================
# PAGES
# =============================
def page_login():
    auth_header("Apartments in Berlin • fast messaging • verified community")

    st.markdown("<div class='rb-auth-card'>", unsafe_allow_html=True)
    st.markdown("<div class='rb-auth-h1'>Sign in</div>", unsafe_allow_html=True)
    st.markdown("<div class='rb-auth-sub'>Use your email & password to continue.</div>", unsafe_allow_html=True)
    st.write("")

    oauth_buttons()
    st.markdown("<div class='rb-auth-divider'>or</div>", unsafe_allow_html=True)

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

    st.markdown(
        "<div class='rb-auth-foot'>Don't have an account? "
        "<a class='rb-link' href='#' onclick='return false;'> </a></div>",
        unsafe_allow_html=True
    )
    if REGISTRATION_ENABLED:
        if st.button("Create account", use_container_width=True, key="go_signup"):
            st.session_state["route"] = "signup"
            st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)  # card
    auth_footer_close()


def page_signup():
    auth_header("Create your account to start posting and messaging")

    st.markdown("<div class='rb-auth-card'>", unsafe_allow_html=True)
    st.markdown("<div class='rb-auth-h1'>Create account</div>", unsafe_allow_html=True)
    st.markdown("<div class='rb-auth-sub'>It takes less than a minute.</div>", unsafe_allow_html=True)
    st.write("")

    oauth_buttons()
    st.markdown("<div class='rb-auth-divider'>or</div>", unsafe_allow_html=True)

    with st.form("signup_form"):
        email = st.text_input("Email", placeholder="name@email.com")
        phone = st.text_input("Phone (optional)", placeholder="+49...")
        password = st.text_input("Password", type="password", placeholder="Minimum 6 characters")
        password2 = st.text_input("Confirm password", type="password", placeholder="Repeat password")
        submitted = st.form_submit_button("Create account", type="primary", use_container_width=True)

    if submitted:
        if password != password2:
            st.error("Passwords do not match.")
        else:
            ok, msg = create_user(email, phone, password)
            if ok:
                st.success(msg)
                st.session_state["route"] = "login"
                st.rerun()
            else:
                st.error(msg)

    st.markdown("<div class='rb-auth-foot'>Already have an account?</div>", unsafe_allow_html=True)
    if st.button("Back to sign in", use_container_width=True, key="back_login"):
        st.session_state["route"] = "login"
        st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)  # card
    auth_footer_close()


def page_reset():
    auth_header("Reset your password and sign in again")

    st.markdown("<div class='rb-auth-card'>", unsafe_allow_html=True)
    st.markdown("<div class='rb-auth-h1'>Reset password</div>", unsafe_allow_html=True)
    st.markdown("<div class='rb-auth-sub'>Set a new password for your account.</div>", unsafe_allow_html=True)
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

    st.markdown("<div class='rb-auth-foot'>Remembered your password?</div>", unsafe_allow_html=True)
    if st.button("Back to sign in", use_container_width=True, key="back_login2"):
        st.session_state["route"] = "login"
        st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)  # card
    auth_footer_close()


def page_app():
    # Simple base app page you can extend
    uid = st.session_state.get("user_id")
    user = get_user(uid) if uid else {}

    st.markdown(f"## Welcome, {user.get('email','')}")
    st.caption("This is your logged-in area. Add your rent listings, posts, messages here.")
    col1, col2 = st.columns([1, 1])

    with col1:
        st.markdown("### Profile")
        st.write("Username:", user.get("username", ""))
        st.write("Display name:", user.get("display_name", ""))
        st.write("Phone:", user.get("phone", ""))

    with col2:
        st.markdown("### Actions")
        if st.button("Log out", type="primary", use_container_width=True):
            logout()
            st.session_state["route"] = "login"
            st.rerun()

    st.markdown("---")
    st.info("Next step: I can add posts, listings, chat, and admin panel — but login is now real and stable.")


# =============================
# ROUTER / BOOT
# =============================
def boot_session():
    # If already in session_state, keep it
    if st.session_state.get("user_id") and st.session_state.get("session_token"):
        return

    # Try URL token
    tok = get_query_token()
    if tok:
        uid = load_session_from_token(tok)
        if uid:
            st.session_state["user_id"] = uid
            st.session_state["session_token"] = tok
            st.session_state["route"] = "app"
            return
        else:
            # invalid token
            clear_all_query_params()

    # Default route
    if not st.session_state.get("route"):
        st.session_state["route"] = "login"


def main():
    init_db()
    inject_style()

    # If user is returning from Google callback, finish it early
    google_finish_if_callback()

    boot_session()

    route = st.session_state.get("route", "login")
    if route == "signup":
        page_signup()
    elif route == "reset":
        page_reset()
    elif route == "app":
        page_app()
    else:
        page_login()


if __name__ == "__main__":
    main()
