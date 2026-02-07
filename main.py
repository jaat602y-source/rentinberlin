# main.py
# Run: streamlit run main.py
#
# RentinBerlin — One-file Streamlit website with:
# - Beautiful Login / Signup / Reset (mobile-friendly)
# - Background slideshow (assets/bg1.jpg bg2.jpg bg3.jpg) changes every 15 seconds
# - Email+Password auth (SQLite, PBKDF2)
# - Persistent login via URL token (?t=...)
# - REAL Google OAuth (Authlib + st.secrets)
# - Apple button UI (real Apple OAuth requires Apple Developer keys)
#
# Optional assets:
#   assets/logo.png
#   assets/google_logo.png
#   assets/bg1.jpg
#   assets/bg2.jpg
#   assets/bg3.jpg
#
# Required secrets for Google OAuth (Streamlit secrets):
#   GOOGLE_CLIENT_ID
#   GOOGLE_CLIENT_SECRET
#   GOOGLE_REDIRECT_URI   (must match Google Cloud OAuth redirect URI exactly)

import os
import re
import uuid
import base64
import sqlite3
import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple

import streamlit as st
import streamlit.components.v1 as components

# Optional: REAL Google OAuth
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

# Background images for auth pages (slideshow)
AUTH_BG_FILES = ["bg1.jpg", "bg2.jpg", "bg3.jpg"]  # in assets/
BG_ROTATE_SECONDS = 15


# =============================
# STREAMLIT PAGE CONFIG
# =============================
def _favicon():
    # if you have assets/logo.png it will show as favicon
    p = os.path.join(ASSETS_DIR, "logo.png")
    if os.path.exists(p):
        return p
    return "🏠"


st.set_page_config(
    page_title=APP_NAME,
    page_icon=_favicon(),
    layout="wide",
)


# =============================
# HELPERS
# =============================
def now_iso() -> str:
    return datetime.now().replace(microsecond=0).isoformat()


def asset_path(name: str) -> str:
    p = os.path.join(ASSETS_DIR, name)
    return p if os.path.exists(p) else ""


def read_file_b64(path: str) -> str:
    with open(path, "rb") as f:
        return base64.b64encode(f.read()).decode("utf-8")


def normalize_email(e: str) -> str:
    return (e or "").strip().lower()


def normalize_phone(p: str) -> str:
    p = (p or "").strip()
    p = re.sub(r"[^\d+]", "", p)
    return p[:25]


def sanitize_username(u: str) -> str:
    u = (u or "").strip().lower()
    u = re.sub(r"[^a-z0-9._-]", "", u)
    return u[:30]


def is_valid_email(email: str) -> bool:
    email = normalize_email(email)
    if not email or "@" not in email:
        return False
    if len(email) > 200:
        return False
    return True


# =============================
# PASSWORD HASHING (PBKDF2)
# =============================
def _pbkdf2_hash_password(password: str, salt: bytes) -> str:
    # PBKDF2-HMAC-SHA256
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 180_000)
    return base64.b64encode(dk).decode("utf-8")


def make_password_hash(password: str) -> str:
    # stored format: pbkdf2$<salt_b64>$<hash_b64>
    salt = os.urandom(16)
    salt_b64 = base64.b64encode(salt).decode("utf-8")
    hash_b64 = _pbkdf2_hash_password(password, salt)
    return f"pbkdf2${salt_b64}${hash_b64}"


def verify_password(password: str, stored: str) -> bool:
    try:
        parts = (stored or "").split("$")
        if len(parts) != 3:
            return False
        algo, salt_b64, hash_b64 = parts
        if algo != "pbkdf2":
            return False
        salt = base64.b64decode(salt_b64.encode("utf-8"))
        calc = _pbkdf2_hash_password(password, salt)
        # constant-time compare
        return hmac.compare_digest(calc, hash_b64)
    except Exception:
        return False


# =============================
# QUERY TOKEN (persistent session via URL)
# =============================
def get_query_token() -> str:
    # new streamlit query_params API
    try:
        return (st.query_params.get("t") or "")
    except Exception:
        pass
    # old API fallback
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


def clear_query_params():
    # clear everything
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
        password_hash TEXT NOT NULL,
        provider TEXT NOT NULL DEFAULT 'local'  -- local/google/apple
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
        candidate = base_username if suffix == 0 else f"{base_username}{suffix}"
        try:
            cur.execute(
                "INSERT INTO profiles (user_id, username, display_name, updated_at) VALUES (?,?,?,?)",
                (user_id, candidate, "", now_iso())
            )
            c.commit()
            c.close()
            return
        except sqlite3.IntegrityError:
            suffix += 1
            if suffix > 9999:
                c.close()
                return


def get_user(uid: int) -> Dict[str, Any]:
    c = conn()
    row = c.execute("""
        SELECT u.id, u.email, u.phone, u.provider,
               COALESCE(p.username,'') AS username,
               COALESCE(p.display_name,'') AS display_name
        FROM users u
        LEFT JOIN profiles p ON p.user_id=u.id
        WHERE u.id=?
    """, (uid,)).fetchone()
    c.close()
    return dict(row) if row else {}


# =============================
# AUTH: local email/password
# =============================
def create_user(email: str, phone: str, password: str) -> Tuple[bool, str]:
    email = normalize_email(email)
    phone = normalize_phone(phone)
    password = (password or "").strip()

    if not is_valid_email(email):
        return False, "Please enter a valid email."
    if len(password) < 6:
        return False, "Password must be at least 6 characters."

    c = conn()
    cur = c.cursor()
    try:
        cur.execute(
            "INSERT INTO users (created_at, email, phone, password_hash, provider) VALUES (?,?,?,?,?)",
            (now_iso(), email, phone, make_password_hash(password), "local")
        )
        c.commit()
        uid = int(cur.lastrowid)
        c.close()
        ensure_profile_for_user(uid, email)
        return True, "Account created. Please sign in."
    except sqlite3.IntegrityError:
        c.close()
        return False, "This email is already registered."


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
    if not verify_password(password, row["password_hash"]):
        return None

    uid = int(row["id"])
    ensure_profile_for_user(uid, row["email"])
    return uid


def reset_password(email: str, new_password: str) -> Tuple[bool, str]:
    email = normalize_email(email)
    new_password = (new_password or "").strip()

    if not is_valid_email(email):
        return False, "Please enter a valid email."
    if len(new_password) < 6:
        return False, "New password must be at least 6 characters."

    c = conn()
    cur = c.cursor()
    cur.execute("UPDATE users SET password_hash=?, provider='local' WHERE email=?", (make_password_hash(new_password), email))
    changed = cur.rowcount
    c.commit()
    c.close()

    if changed:
        return True, "Password reset. Please sign in."
    return False, "Email not found."


# =============================
# SESSIONS (persistent login)
# =============================
def create_session(user_id: int) -> str:
    token = uuid.uuid4().hex + uuid.uuid4().hex
    expires_at = (datetime.now() + timedelta(days=SESSION_DAYS)).replace(microsecond=0).isoformat()

    c = conn()
    c.execute("""
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
    clear_query_params()
    for k in list(st.session_state.keys()):
        if k in ["user_id", "route", "session_token"]:
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


def _query_param_value(name: str) -> str:
    # works for both new and old APIs
    try:
        v = st.query_params.get(name, "")
        if isinstance(v, list):
            return v[0] if v else ""
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


def google_oauth_handle_callback_if_present():
    """
    If URL contains ?code=... from Google OAuth, finish login.
    """
    if not google_oauth_is_configured():
        return

    code = _query_param_value("code")
    if not code:
        return

    client_id = st.secrets["GOOGLE_CLIENT_ID"]
    client_secret = st.secrets["GOOGLE_CLIENT_SECRET"]
    redirect_uri = st.secrets["GOOGLE_REDIRECT_URI"]

    oauth = OAuth2Session(
        client_id=client_id,
        scope="openid email profile",
        redirect_uri=redirect_uri,
    )

    try:
        oauth.fetch_token(
            "https://oauth2.googleapis.com/token",
            code=code,
            client_secret=client_secret,
        )
        userinfo = oauth.get("https://openidconnect.googleapis.com/v1/userinfo").json()
        email = normalize_email(userinfo.get("email", ""))

        if not email:
            st.error("Google login failed: email not returned.")
            return

        # Create or load local user
        c = conn()
        row = c.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if row:
            uid = int(row["id"])
            c.close()
        else:
            # create user with random password (can reset later)
            pw = uuid.uuid4().hex[:12] + "A!"
            cur = c.cursor()
            cur.execute(
                "INSERT INTO users (created_at, email, phone, password_hash, provider) VALUES (?,?,?,?,?)",
                (now_iso(), email, "", make_password_hash(pw), "google")
            )
            c.commit()
            uid = int(cur.lastrowid)
            c.close()
            ensure_profile_for_user(uid, email)

        # IMPORTANT: clear OAuth params (code, scope, etc.)
        clear_query_params()

        # login session
        token = create_session(uid)
        st.session_state["user_id"] = uid
        st.session_state["session_token"] = token
        set_query_token(token)
        st.session_state["route"] = "app"
        st.rerun()

    except Exception as e:
        st.error(f"Google login failed: {e}")


def build_google_auth_url() -> str:
    client_id = st.secrets["GOOGLE_CLIENT_ID"]
    redirect_uri = st.secrets["GOOGLE_REDIRECT_URI"]

    oauth = OAuth2Session(
        client_id=client_id,
        scope="openid email profile",
        redirect_uri=redirect_uri,
    )
    auth_url, _state = oauth.create_authorization_url(
        "https://accounts.google.com/o/oauth2/v2/auth",
        access_type="offline",
        prompt="select_account",
    )
    return auth_url


# =============================
# UI: GLOBAL STYLE
# =============================
def inject_global_css():
    st.markdown(
        """
        <style>
          #MainMenu {visibility: hidden;}
          footer {visibility: hidden;}
          header {visibility: hidden;}
          .stApp { background: #f6f8fb; }

          /* better spacing on mobile */
          @media (max-width: 768px) {
            section.main > div.block-container {
              padding-left: 0.85rem;
              padding-right: 0.85rem;
            }
          }

          section.main > div.block-container {
            padding-top: 0.65rem;
            padding-bottom: 4.2rem;
            max-width: 1200px;
          }

          /* button styling */
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
        </style>
        """,
        unsafe_allow_html=True
    )


# =============================
# AUTH BACKGROUND SLIDESHOW (15s rotate, no rerun)
# =============================
def inject_auth_background_slideshow():
    """
    Creates a fixed fullscreen background slideshow using JS setInterval.
    It uses your assets/bg1.jpg bg2.jpg bg3.jpg if present.
    """
    bgs = []
    for fn in AUTH_BG_FILES:
        p = asset_path(fn)
        if p:
            # jpg/png accepted
            ext = os.path.splitext(fn)[1].lower().replace(".", "")
            if ext not in ["jpg", "jpeg", "png", "webp"]:
                continue
            b64 = read_file_b64(p)
            mime = "image/jpeg" if ext in ["jpg", "jpeg"] else f"image/{ext}"
            bgs.append(f"data:{mime};base64,{b64}")

    # If none exist, fallback to gradient
    if not bgs:
        st.markdown(
            """
            <style>
              .rb-bg {
                position: fixed;
                inset: 0;
                z-index: 0;
                background:
                  radial-gradient(1200px 800px at 10% 0%, rgba(255,122,26,0.18), transparent 55%),
                  radial-gradient(900px 700px at 90% 10%, rgba(99,102,241,0.14), transparent 55%),
                  radial-gradient(1000px 900px at 40% 90%, rgba(16,185,129,0.12), transparent 55%),
                  #f6f8fb;
              }
            </style>
            <div class="rb-bg"></div>
            """,
            unsafe_allow_html=True
        )
        return

    # Use slideshow div + overlay for readability
    # No Streamlit rerun needed: pure JS changes background every 15 seconds
    js_array = "[" + ",".join([f"'{u}'" for u in bgs]) + "]"
    components.html(
        f"""
        <style>
          .rb-bg {{
            position: fixed;
            inset: 0;
            z-index: 0;
            background-image: url("{bgs[0]}");
            background-size: cover;
            background-position: center;
            background-repeat: no-repeat;
            transform: scale(1.02);
            filter: saturate(1.05) contrast(1.02);
            transition: background-image 0.6s ease-in-out;
          }}
          .rb-bg::after {{
            content: "";
            position: absolute;
            inset: 0;
            background:
              linear-gradient(180deg, rgba(2,6,23,0.35) 0%, rgba(2,6,23,0.25) 40%, rgba(2,6,23,0.45) 100%);
          }}
        </style>
        <div class="rb-bg" id="rbBg"></div>
        <script>
          const imgs = {js_array};
          let idx = 0;
          const el = document.getElementById("rbBg");
          function nextBg() {{
            idx = (idx + 1) % imgs.length;
            el.style.backgroundImage = `url("${{imgs[idx]}}")`;
          }}
          setInterval(nextBg, {int(BG_ROTATE_SECONDS*1000)});
        </script>
        """,
        height=0
    )


# =============================
# AUTH UI CSS (professional centered card)
# =============================
def inject_auth_css():
    st.markdown(
        """
        <style>
          /* auth shell centered */
          .rb-auth-shell{
            position: relative;
            z-index: 3;
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
            text-align:cent
