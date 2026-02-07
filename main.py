# main.py
# Run: streamlit run main.py
#
# ONE-FILE Streamlit app (production-safe auth pages):
# - Professional centered Login / Signup / Reset (mobile + desktop)
# - Email+Password auth (SQLite)
# - Persistent login via URL token (?t=...)
# - REAL Google OAuth (Authlib) if configured in st.secrets + requirements.txt
# - Apple button UI (real Apple OAuth needs Apple Developer keys)
#
# Optional assets:
#   assets/logo.png
#   assets/google_logo.png
#   assets/apple_logo.png

import os
import re
import uuid
import base64
import sqlite3
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple

import streamlit as st

# --- Optional: REAL Google OAuth (Authlib) ---
AUTHLIB_OK = False
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
# BASIC HELPERS
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
# QUERY PARAMS
# =============================
def qp_get(key: str) -> str:
    try:
        v = st.query_params.get(key, "")
        return v if isinstance(v, str) else (v[0] if v else "")
    except Exception:
        try:
            q = st.experimental_get_query_params() or {}
            v = q.get(key, [""])
            return v[0] if isinstance(v, list) and v else ""
        except Exception:
            return ""


def qp_set(**kwargs):
    try:
        for k, v in kwargs.items():
            st.query_params[k] = str(v)
        return
    except Exception:
        try:
            st.experimental_set_query_params(**{k: str(v) for k, v in kwargs.items()})
        except Exception:
            pass


def qp_clear():
    try:
        st.query_params.clear()
        return
    except Exception:
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

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT,
            password_hash TEXT NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS profiles (
            user_id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            display_name TEXT,
            updated_at TEXT NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
        """
    )

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
                (user_id, try_u, "", now_iso()),
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
# AUTH: EMAIL/PASSWORD
# =============================
def create_user(email: str, phone: str, password: str) -> Tuple[bool, str]:
    email = normalize_email(email)
    phone = normalize_phone(phone)
    password = (password or "").strip()

    if not email or "@" not in email:
        return False, "Enter a valid email."
    if len(password) < 6:
        return False, "Password must be at least 6 characters."
    if re.match(r"^\d", sanitize_username(email.split("@")[0]) or ""):
        # suggestion only; not blocking by default
        pass

    c = conn()
    cur = c.cursor()
    try:
        cur.execute(
            "INSERT INTO users (created_at, email, phone, password_hash) VALUES (?,?,?,?)",
            (now_iso(), email, phone, sha256(password)),
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


def reset_password(email: str, new_password: str) -> Tuple[bool, str]:
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
    row = c.execute(
        """
        SELECT u.id, u.email, u.phone,
               COALESCE(p.username,'') AS username,
               COALESCE(p.display_name,'') AS display_name
        FROM users u
        LEFT JOIN profiles p ON p.user_id=u.id
        WHERE u.id=?
        """,
        (uid,),
    ).fetchone()
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
    cur.execute(
        """
        INSERT INTO sessions (token, user_id, created_at, last_seen, expires_at)
        VALUES (?,?,?,?,?)
        """,
        (token, user_id, now_iso(), now_iso(), expires_at),
    )
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


def do_login(uid: int):
    token = create_session(uid)
    st.session_state["user_id"] = uid
    st.session_state["session_token"] = token
    qp_clear()
    qp_set(t=token)
    st.session_state["route"] = "app"
    st.rerun()


def logout():
    tok = st.session_state.get("session_token") or qp_get("t")
    if tok:
        delete_session(tok)
    qp_clear()
    for k in list(st.session_state.keys()):
        if k in ["user_id", "route", "session_token", "google_oauth_state"]:
            st.session_state.pop(k, None)


# =============================
# GOOGLE OAUTH (REAL)
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


def google_oauth_client() -> OAuth2Session:
    return OAuth2Session(
        client_id=st.secrets["GOOGLE_CLIENT_ID"],
        scope="openid email profile",
        redirect_uri=st.secrets["GOOGLE_REDIRECT_URI"],
    )


def google_auth_url() -> str:
    oauth = google_oauth_client()
    url, state = oauth.create_authorization_url(
        "https://accounts.google.com/o/oauth2/v2/auth",
        access_type="offline",
        prompt="select_account",
    )
    st.session_state["google_oauth_state"] = state
    return url


def google_callback_try_login():
    # Called on every run. If user returned from Google with code, we finish login.
    if not google_oauth_is_configured():
        return

    code = qp_get("code")
    state = qp_get("state")
    if not code:
        return

    expected = st.session_state.get("google_oauth_state", "")
    if expected and state and state != expected:
        st.error("Google login failed: invalid state.")
        qp_clear()
        return

    oauth = google_oauth_client()
    try:
        oauth.fetch_token(
            "https://oauth2.googleapis.com/token",
            code=code,
            client_secret=st.secrets["GOOGLE_CLIENT_SECRET"],
        )
        userinfo = oauth.get("https://openidconnect.googleapis.com/v1/userinfo").json()
        email = normalize_email(userinfo.get("email", ""))

        if not email:
            st.error("Google login failed: Google did not return an email.")
            qp_clear()
            return

        # Get or create local user
        c = conn()
        row = c.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if row:
            uid = int(row["id"])
            c.close()
        else:
            # Create with random password (user can reset later)
            pw = uuid.uuid4().hex[:12] + "A!"
            cur = c.cursor()
            cur.execute(
                "INSERT INTO users (created_at, email, phone, password_hash) VALUES (?,?,?,?)",
                (now_iso(), email, "", sha256(pw)),
            )
            c.commit()
            uid = int(cur.lastrowid)
            c.close()
            ensure_profile_for_user(uid, email)

        do_login(uid)
    except Exception as e:
        st.error(f"Google login failed: {e}")
        qp_clear()


# =============================
# UI STYLE
# =============================
def inject_style():
    st.markdown(
        """
        <style>
          .stApp {
            background:
              radial-gradient(1200px 800px at 10% 0%, rgba(255,122,26,0.10), transparent 55%),
              radial-gradient(900px 700px at 90% 10%, rgba(99,102,241,0.10), transparent 50%),
              #f6f8fb !important;
          }

          #MainMenu {visibility: hidden;}
          footer {visibility: hidden;}
          header {visibility: hidden;}

          section.main > div.block-container {
            padding-top: 0.8rem;
            padding-bottom: 3.8rem;
            max-width: 1280px;
          }

          @media (max-width: 768px) {
            section.main > div.block-container { padding-left: 0.75rem; padding-right: 0.75rem; }
            .stButton>button { padding: 0.52rem 0.75rem !important; font-size: 12px !important; }
          }

          /* global buttons */
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

          /* inputs */
          .stTextInput input {
            border-radius: 14px !important;
            height: 46px !important;
          }

          /* AUTH LAYOUT */
          .rb-auth-shell{
            max-width: 440px;
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
            width: 68px;
            height: 68px;
            border-radius: 18px;
            overflow:hidden;
            background: #ffffff;
            border: 1px solid #eef2f7;
            box-shadow: 0 18px 45px rgba(16, 24, 40, 0.10);
            display:flex;
            align-items:center;
            justify-content:center;
          }
          .rb-auth-logo img{
            width:100%;
            height:100%;
            object-fit:cover;
            display:block;
            border:0 !important;
            outline:0 !important;
          }

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
            text-align:left;
          }
          .rb-auth-sub{
            margin-top: 6px;
            color:#64748b;
            font-size: 13px;
            text-align:left;
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

          /* HTML OAuth buttons */
          .rb-oauth-btn{
            display:flex;
            align-items:center;
            justify-content:center;
            gap:12px;
            padding:12px;
            border-radius:14px;
            border:1px solid #e5e7eb;
            background:white;
            font-weight:900;
            color:#0f172a;
            cursor:pointer;
            box-shadow:0 8px 24px rgba(0,0,0,0.06);
            user-select:none;
          }
          .rb-oauth-btn:hover{
            background:#fbfdff;
            border-color:#dbe3ee;
          }
          .rb-oauth-icon{
            width:20px;
            height:20px;
            display:block;
          }
          .rb-oauth-a{
            text-decoration:none !important;
          }
        </style>
        """,
        unsafe_allow_html=True,
    )


# =============================
# UI COMPONENTS
# =============================
def auth_shell_open(tagline: str):
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
            unsafe_allow_html=True,
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
            unsafe_allow_html=True,
        )


def auth_shell_close():
    st.markdown("</div>", unsafe_allow_html=True)


def oauth_html_button(label: str, href: str, icon_asset_name: str):
    icon_path = asset_path(icon_asset_name)
    icon_html = ""
    if icon_path and os.path.exists(icon_path):
        b64 = _img_to_b64(icon_path)
        icon_html = f"<img class='rb-oauth-icon'ogout():
    tok = st.session_state.get("session_token") or qp_get("t")
    if tok:
        delete_session(tok)
    qp_clear_all()
    for k in ["user_id", "session_token", "route"]:
        st.session_state.pop(k, None)


# =============================
# GOOGLE OAUTH (REAL)
# =============================
def google_oauth_is_configured() -> bool:
    if not AUTHLIB_OK:
        return False
    cid = safe_get_secret("GOOGLE_CLIENT_ID")
    cs = safe_get_secret("GOOGLE_CLIENT_SECRET")
    base = safe_get_secret("APP_BASE_URL")  # e.g. https://xxx.streamlit.app
    if not cid or not cs or not base:
        return False
    return True


def google_redirect_uri() -> str:
    base = safe_get_secret("APP_BASE_URL").rstrip("/")
    # This app handles callback on the same page (query param `code`)
    return f"{base}/"


def google_login_flow() -> Optional[int]:
    """
    Returns uid if login completes via callback, otherwise None.
    """
    if not google_oauth_is_configured():
        return None

    client_id = safe_get_secret("GOOGLE_CLIENT_ID")
    client_secret = safe_get_secret("GOOGLE_CLIENT_SECRET")
    redirect_uri = google_redirect_uri()

    oauth = OAuth2Session(
        client_id=client_id,
        scope="openid email profile",
        redirect_uri=redirect_uri,
    )

    code = qp_get("code")
    err = qp_get("error")

    if err:
        # Clean oauth params (keep nothing)
        qp_clear_all()
        st.error(f"Google login cancelled: {err}")
        return None

    if not code:
        return None

    try:
        oauth.fetch_token(
            "https://oauth2.googleapis.com/token",
            code=code,
            client_secret=client_secret,
        )
        userinfo = oauth.get("https://openidconnect.googleapis.com/v1/userinfo").json()
        email = normalize_email(userinfo.get("email", ""))

        if not email:
            qp_clear_all()
            st.error("Google login failed: no email returned.")
            return None

        # Get or create local user
        c = conn()
        row = c.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if row:
            uid = int(row["id"])
            c.close()
        else:
            # create user with random password (user can reset later)
            random_pw = uuid.uuid4().hex[:10] + "A!"
            cur = c.cursor()
            cur.execute(
                "INSERT INTO users (created_at, email, phone, password_hash) VALUES (?,?,?,?)",
                (now_iso(), email, "", sha256(random_pw)),
            )
            uid = int(cur.lastrowid)
            c.commit()
            c.close()
            ensure_profile_for_user(uid, email)

        # Remove oauth params, then set our session token param
        qp_clear_all()
        return uid
    except Exception as e:
        qp_clear_all()
        st.error(f"Google login failed: {e}")
        return None


def google_auth_url() -> str:
    client_id = safe_get_secret("GOOGLE_CLIENT_ID")
    redirect_uri = google_redirect_uri()

    oauth = OAuth2Session(
        client_id=client_id,
        scope="openid email profile",
        redirect_uri=redirect_uri,
    )

    url, _state = oauth.create_authorization_url(
        "https://accounts.google.com/o/oauth2/v2/auth",
        access_type="offline",
        prompt="select_account",
    )
    return url


# =============================
# UI STYLE
# =============================
def inject_style():
    st.markdown(
        """
        <style>
          #MainMenu {visibility: hidden;}
          footer {visibility: hidden;}
          header {visibility: hidden;}

          .stApp {
            background:
              radial-gradient(1200px 800px at 10% 0%, rgba(255,122,26,0.10), transparent 55%),
              radial-gradient(900px 700px at 90% 10%, rgba(99,102,241,0.10), transparent 50%),
              #f6f8fb !important;
          }

          section.main > div.block-container {
            padding-top: 0.9rem;
            padding-bottom: 3.6rem;
            max-width: 1280px;
          }

          .stTextInput input {
            border-radius: 14px !important;
            height: 46px !important;
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

          @media (max-width: 768px) {
            section.main > div.block-container { padding-left: 0.75rem; padding-right: 0.75rem; }
            .stButton>button { padding: 0.55rem 0.75rem !important; font-size: 12px !important; }
          }

          /* AUTH LAYOUT */
          .rb-auth-shell{
            max-width: 440px;
            margin: 0 auto;
            padding-top: 5vh;
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
            width: 72px;
            height: 72px;
            border-radius: 20px;
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
            text-align:center;
          }
          .rb-auth-sub{
            margin-top: 6px;
            color:#64748b;
            font-size: 13px;
            text-align:center;
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

          .rb-secondary-btn button{
            background: #ffffff !important;
          }

          .rb-home-card{
            background:#ffffff;
            border:1px solid #eef2f7;
            border-radius:18px;
            box-shadow: 0 18px 45px rgba(16, 24, 40, 0.06);
            padding: 18px;
          }
        </style>
        """,
        unsafe_allow_html=True,
    )


def auth_header(tagline: str):
    st.markdown("<div class='rb-auth-shell'>", unsafe_allow_html=True)

    logo = asset_path("logo.png")
    if logo and os.path.exists(logo):
        b64 = _img_to_b64(logo)
        st.markdown(
            f"""
            <div class="rb-auth-top">
              <div class="rb-auth-logo"><img src="data:image/png;base64,{b64}" alt="logo"/></div>
              <div class="rb-auth-appname">{APP_NAME}</div>
              <div class="rb-auth-tagline">{tagline}</div>
            </div>
            """,
            unsafe_allow_html=True,
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
            unsafe_allow_html=True,
        )


def auth_footer_close():
    st.markdown("</div>", unsafe_allow_html=True)


# =============================
# AUTH PAGES
# =============================
def page_login():
    # Handle Google callback if user returned with ?code=
    google_uid = google_login_flow()
    if google_uid:
        token = create_session(google_uid)
        st.session_state["user_id"] = google_uid
        st.session_state["session_token"] = token
        qp_set(t=token)
        st.session_state["route"] = "app"
        st.rerun()

    auth_header("Apartments in Berlin • fast messaging • verified community")

    st.markdown("<div class='rb-auth-card'>", unsafe_allow_html=True)
    st.markdown("<div class='rb-auth-h1'>Sign in</div>", unsafe_allow_html=True)
    st.markdown("<div class='rb-auth-sub'>Use email & password, or continue with Google/Apple.</div>", unsafe_allow_html=True)
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
            qp_set(t=token)
            st.session_state["route"] = "app"
            st.rerun()

    st.markdown("<div class='rb-auth-divider'>OR</div>", unsafe_allow_html=True)

    # Google button (REAL if configured)
    if google_oauth_is_configured():
        url = google_auth_url()
        # link_button exists in modern Streamlit; fallback to markdown link if not
        if hasattr(st, "link_button"):
            st.link_button("Continue with Google", url, use_container_width=True)
        else:
            st.markdown(f"<a class='rb-link' href='{url}'>Continue with Google</a>", unsafe_allow_html=True)
            st.caption("If link does not open, update Streamlit.")
    else:
        # Show exact reason
        if not AUTHLIB_OK:
            st.button("Continue with Google", use_container_width=True, disabled=True)
            st.caption("Google login disabled: authlib not installed. Add authlib to requirements.txt.")
        else:
            st.button("Continue with Google", use_container_width=True, disabled=True)
            st.caption("Google login disabled: missing secrets. Add GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, APP_BASE_URL.")

    # Apple UI (real Apple needs Apple Developer keys)
    st.button("Continue with Apple", use_container_width=True, disabled=True)
    st.caption("Apple login requires Apple Developer keys (not included here).")

    st.markdown("<div class='rb-auth-foot'>New to RentinBerlin? <a class='rb-link' href='#'>Create account</a></div>", unsafe_allow_html=True)
    if st.button("Create account", use_container_width=True, key="go_register", type="primary"):
        st.session_state["route"] = "register"
        st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)  # rb-auth-card
    auth_footer_close()


def page_register():
    auth_header("Create your account • username rules apply")

    st.markdown("<div class='rb-auth-card'>", unsafe_allow_html=True)
    st.markdown("<div class='rb-auth-h1'>Create account</div>", unsafe_allow_html=True)
    st.markdown(
        "<div class='rb-auth-sub'>Password ≥ 6 characters • Username can not begin with numbers.</div>",
        unsafe_allow_html=True,
    )
    st.write("")

    with st.form("register_form"):
        email = st.text_input("Email", placeholder="name@email.com")
        username = st.text_input("Username", placeholder="e.g. rentinberlin_user")
        phone = st.text_input("Phone (optional)", placeholder="+49 …")
        password = st.text_input("Password", type="password", placeholder="At least 6 characters")
        submitted = st.form_submit_button("Create account", type="primary", use_container_width=True)

    if submitted:
        ok, msg = create_user(email, phone, password, username)
        if ok:
            st.success(msg)
            st.session_state["route"] = "login"
            st.rerun()
        else:
            st.error(msg)

    st.markdown("<div class='rb-auth-divider'>OR</div>", unsafe_allow_html=True)

    if google_oauth_is_configured():
        url = google_auth_url()
        if hasattr(st, "link_button"):
            st.link_button("Sign up with Google", url, use_container_width=True)
        else:
            st.markdown(f"<a class='rb-link' href='{url}'>Sign up with Google</a>", unsafe_allow_html=True)
    else:
        st.button("Sign up with Google", use_container_width=True, disabled=True)

    st.button("Sign up with Apple", use_container_width=True, disabled=True)
    st.caption("Apple signup needs Apple Developer setup.")

    if st.button("Back to sign in", use_container_width=True, key="back_login"):
        st.session_state["route"] = "login"
        st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)
    auth_footer_close()


def page_reset():
    auth_header("Reset password • secure access")

    st.markdown("<div class='rb-auth-card'>", unsafe_allow_html=True)
    st.markdown("<div class='rb-auth-h1'>Reset password</div>", unsafe_allow_html=True)
    st.markdown("<div class='rb-auth-sub'>Enter your email and set a new password.</div>", unsafe_allow_html=True)
    st.write("")

    with st.form("reset_form"):
        email = st.text_input("Email", placeholder="name@email.com")
        new_password = st.text_input("New password", type="password", placeholder="At least 6 characters")
        submitted = st.form_submit_button("Reset", type="primary", use_container_width=True)

    if submitted:
        ok, msg = reset_password(email, new_password)
        if ok:
            st.success(msg)
            st.session_state["route"] = "login"
            st.rerun()
        else:
            st.error(msg)

    if st.button("Back to sign in", use_container_width=True, key="back_login_from_reset"):
        st.session_state["route"] = "login"
        st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)
    auth_footer_close()


# =============================
# APP (AFTER LOGIN)
# =============================
def page_app(uid: int):
    u = get_user(uid)
    st.markdown("<div class='rb-home-card'>", unsafe_allow_html=True)
    st.markdown(f"## Welcome, @{u.get('username','user')}")
    st.caption(f"Signed in as: {u.get('email','')}")
    st.write("")
    st.write("This is the logged-in area. Replace this section with your real app pages.")
    st.write("")
    if st.button("Logout", type="primary"):
        logout()
        st.session_state["route"] = "login"
        st.rerun()
    st.markdown("</div>", unsafe_allow_html=True)


# =============================
# MAIN
# =============================
def main():
    inject_style()
    init_db()

    st.session_state.setdefault("route", "login")

    # Auto-login from token
    if not st.session_state.get("user_id"):
        tok = qp_get("t")
        if tok:
            uid = load_session_from_token(tok)
            if uid:
                st.session_state["user_id"] = uid
                st.session_state["session_token"] = tok
                st.session_state["route"] = "app"

    uid = st.session_state.get("user_id")
    if uid:
        st.session_state["route"] = "app"
        page_app(int(uid))
        return

    # Auth routes
    route = st.session_state.get("route", "login")
    if route == "register":
        page_register()
    elif route == "reset":
        page_reset()
    else:
        st.session_state["route"] = "login"
        page_login()


if __name__ == "__main__":
    main()
