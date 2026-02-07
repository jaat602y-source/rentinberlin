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
            text-align:center;
            margin-bottom: 14px;
          }
          .rb-auth-logo{
            width: 68px;
            height: 68px;
            border-radius: 18px;
            overflow:hidden;
            background: rgba(255,255,255,0.92);
            border: 1px solid rgba(255,255,255,0.35);
            box-shadow: 0 28px 80px rgba(2,6,23,0.28);
            display:flex;
            align-items:center;
            justify-content:center;
            backdrop-filter: blur(10px);
          }
          .rb-auth-logo img{ width:100%; height:100%; object-fit:cover; display:block; border:0 !important; }

          .rb-auth-appname{
            margin-top: 10px;
            font-weight: 950;
            font-size: 24px;
            letter-spacing: 0.2px;
            color: rgba(255,255,255,0.95);
            text-shadow: 0 12px 40px rgba(2,6,23,0.45);
          }
          .rb-auth-tagline{
            margin-top: 6px;
            font-size: 13px;
            color: rgba(226,232,240,0.95);
            text-shadow: 0 12px 40px rgba(2,6,23,0.35);
          }

          .rb-auth-card{
            background: rgba(255,255,255,0.92);
            border: 1px solid rgba(255,255,255,0.55);
            border-radius: 24px;
            box-shadow: 0 30px 90px rgba(2,6,23,0.35);
            padding: 18px 18px 14px 18px;
            backdrop-filter: blur(12px);
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

          .rb-divider{
            display:flex;
            align-items:center;
            gap:10px;
            margin: 14px 0;
            color:#94a3b8;
            font-size: 12px;
            font-weight: 900;
          }
          .rb-divider:before,
          .rb-divider:after{
            content:"";
            height:1px;
            flex:1;
            background:#e5e7eb;
          }

          .rb-foot{
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
            margin-bottom: 8px;
          }
          .rb-mini-link button{
            padding: 0.15rem 0.45rem !important;
            border-radius: 10px !important;
            font-size: 12px !important;
            background: transparent !important;
            border: 1px solid transparent !important;
            color:#0f172a !important;
            box-shadow:none !important;
          }
          .rb-mini-link button:hover{
            background:#f8fafc !important;
            border-color:#e5e7eb !important;
          }

          /* social buttons (HTML) */
          .rb-social-btn{
            width: 100%;
            display:flex;
            align-items:center;
            justify-content:center;
            gap: 10px;
            padding: 12px 14px;
            border-radius: 14px;
            border: 1px solid rgba(226,232,240,1);
            background: #ffffff;
            color: #0f172a;
            font-weight: 950;
            text-decoration: none !important;
            box-shadow: 0 10px 25px rgba(16,24,40,0.06);
            transition: transform .08s ease, box-shadow .12s ease, border-color .12s ease;
          }
          .rb-social-btn:hover{
            border-color: rgba(203,213,225,1);
            box-shadow: 0 14px 35px rgba(16,24,40,0.08);
            transform: translateY(-1px);
          }
          .rb-social-ico{
            width: 18px;
            height: 18px;
            display:inline-block;
          }
          .rb-apple{
            background: #0b1220;
            border-color: #0b1220;
            color: #ffffff;
          }
          .rb-apple:hover{
            background: #0a0f1a;
            border-color: #0a0f1a;
          }
        </style>
        """,
        unsafe_allow_html=True
    )


def auth_shell_open(tagline: str):
    inject_auth_background_slideshow()
    inject_auth_css()

    st.markdown("<div class='rb-auth-shell'>", unsafe_allow_html=True)

    logo = asset_path("logo.png")
    if logo:
        b64 = read_file_b64(logo)
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


def auth_shell_close():
    st.markdown("</div>", unsafe_allow_html=True)


def google_button_html() -> str:
    """
    Returns HTML for a nice Google button.
    If assets/google_logo.png exists, uses it. Otherwise uses a simple 'G'.
    """
    ico = asset_path("google_logo.png")
    if ico:
        b64 = read_file_b64(ico)
        icon_html = f"<img class='rb-social-ico' src='data:image/png;base64,{b64}' />"
    else:
        # fallback: simple circle G
        icon_html = """
        <span class="rb-social-ico" style="
          width:18px;height:18px;border-radius:999px;
          display:inline-flex;align-items:center;justify-content:center;
          border:1px solid #e5e7eb;font-size:12px;font-weight:950;
        ">G</span>
        """
    return icon_html


def render_google_oauth_button():
    if not google_oauth_is_configured():
        # still show button, but info
        icon_html = google_button_html()
        st.markdown(
            f"""
            <a class="rb-social-btn" href="#" onclick="return false;">
              {icon_html}
              Continue with Google
            </a>
            <div style="margin-top:8px; font-size:12px; color:#64748b;">
              Google OAuth not configured. Add <b>Authlib</b> and Streamlit secrets.
            </div>
            """,
            unsafe_allow_html=True
        )
        return

    auth_url = build_google_auth_url()
    icon_html = google_button_html()
    st.markdown(
        f"""
        <a class="rb-social-btn" href="{auth_url}">
          {icon_html}
          Continue with Google
        </a>
        """,
        unsafe_allow_html=True
    )


def render_apple_button_ui():
    # UI only (real Apple OAuth requires Apple Developer keys + JWT)
    st.markdown(
        """
        <a class="rb-social-btn rb-apple" href="#" onclick="return false;">
          <span class="rb-social-ico" style="font-size:16px; line-height:0;"></span>
          Continue with Apple
        </a>
        <div style="margin-top:8px; font-size:12px; color:#64748b;">
          Apple login UI is ready. Real Apple OAuth needs Apple Developer keys.
        </div>
        """,
        unsafe_allow_html=True
    )


# =============================
# ROUTES: AUTH PAGES
# =============================
def page_login():
    auth_shell_open("Find rentals in Berlin • message fast • build your profile")

    st.markdown("<div class='rb-auth-card'>", unsafe_allow_html=True)
    st.markdown("<div class='rb-auth-h1'>Sign in</div>", unsafe_allow_html=True)
    st.markdown("<div class='rb-auth-sub'>Use your email & password or continue with Google.</div>", unsafe_allow_html=True)
    st.write("")

    # Handle OAuth callback if present
    google_oauth_handle_callback_if_present()

    # Social buttons
    render_google_oauth_button()
    st.write("")
    render_apple_button_ui()

    st.markdown("<div class='rb-divider'>OR</div>", unsafe_allow_html=True)

    with st.form("login_form"):
        email = st.text_input("Email", placeholder="name@email.com")
        password = st.text_input("Password", type="password", placeholder="Minimum 6 characters")
        submitted = st.form_submit_button("Sign in", type="primary", use_container_width=True)

    st.markdown("<div class='rb-forgot-wrap'>", unsafe_allow_html=True)
    cols = st.columns([1, 1])
    with cols[0]:
        if st.button("Create account", key="go_signup", use_container_width=True):
            st.session_state["route"] = "signup"
            st.rerun()
    with cols[1]:
        st.markdown("<div class='rb-mini-link'>", unsafe_allow_html=True)
        if st.button("Forgot password?", key="go_reset", use_container_width=True):
            st.session_state["route"] = "reset"
            st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)
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

    st.markdown("<div class='rb-foot'>By continuing, you agree to basic community rules and privacy.</div>", unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)  # card
    auth_shell_close()


def page_signup():
    auth_shell_open("Create an account • build trust • post & message")

    st.markdown("<div class='rb-auth-card'>", unsafe_allow_html=True)
    st.markdown("<div class='rb-auth-h1'>Create account</div>", unsafe_allow_html=True)
    st.markdown("<div class='rb-auth-sub'>Fast signup — then sign in.</div>", unsafe_allow_html=True)
    st.write("")

    if not REGISTRATION_ENABLED:
        st.warning("Registration is currently disabled.")
        st.markdown("</div>", unsafe_allow_html=True)
        auth_shell_close()
        return

    with st.form("signup_form"):
        email = st.text_input("Email", placeholder="name@email.com")
        phone = st.text_input("Phone (optional)", placeholder="+49...")
        password = st.text_input("Password", type="password", placeholder="Minimum 6 characters")
        submitted = st.form_submit_button("Create account", type="primary", use_container_width=True)

    if submitted:
        ok, msg = create_user(email, phone, password)
        if ok:
            st.success(msg)
            st.session_state["route"] = "login"
            st.info("Now sign in.")
        else:
            st.error(msg)

    st.markdown("<div class='rb-foot'>Already have an account? <a class='rb-link' href='#'>Sign in</a></div>", unsafe_allow_html=True)
    if st.button("Back to Sign in", use_container_width=True):
        st.session_state["route"] = "login"
        st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)
    auth_shell_close()


def page_reset():
    auth_shell_open("Reset your password • sign in again")

    st.markdown("<div class='rb-auth-card'>", unsafe_allow_html=True)
    st.markdown("<div class='rb-auth-h1'>Reset password</div>", unsafe_allow_html=True)
    st.markdown("<div class='rb-auth-sub'>Set a new password for your email.</div>", unsafe_allow_html=True)
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
            st.info("Please sign in now.")
        else:
            st.error(msg)

    if st.button("Back to Sign in", use_container_width=True):
        st.session_state["route"] = "login"
        st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)
    auth_shell_close()


# =============================
# APP PAGE (after login)
# =============================
def inject_app_css():
    st.markdown(
        """
        <style>
          .rb-topbar{
            position: sticky;
            top: 0;
            z-index: 5;
            background: rgba(246,248,251,0.86);
            backdrop-filter: blur(10px);
            padding: 10px 0 8px 0;
            border-bottom: 1px solid rgba(226,232,240,0.9);
          }
          .rb-topbar-inner{
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 8px;
            display:flex;
            align-items:center;
            justify-content:space-between;
            gap: 12px;
          }
          .rb-brand{
            display:flex;
            align-items:center;
            gap: 10px;
            font-weight: 950;
            color:#0f172a;
          }
          .rb-brand-badge{
            width: 40px;
            height: 40px;
            border-radius: 14px;
            background: #ffffff;
            border: 1px solid #eef2f7;
            box-shadow: 0 18px 45px rgba(16,24,40,0.06);
            display:flex;
            align-items:center;
            justify-content:center;
            overflow:hidden;
          }
          .rb-brand-badge img{ width:100%; height:100%; object-fit:cover; }
          .rb-card{
            background:#ffffff;
            border: 1px solid #eef2f7;
            border-radius: 18px;
            box-shadow: 0 18px 45px rgba(16, 24, 40, 0.06);
            padding: 14px;
          }
          .rb-muted{ color:#64748b; font-size: 12px; }
          .rb-h1{ font-weight:950; font-size: 28px; margin:0; color:#0f172a; }
        </style>
        """,
        unsafe_allow_html=True
    )


def page_app():
    inject_app_css()

    user = get_user(st.session_state["user_id"])
    logo = asset_path("logo.png")

    st.markdown("<div class='rb-topbar'><div class='rb-topbar-inner'>", unsafe_allow_html=True)

    if logo:
        b64 = read_file_b64(logo)
        st.markdown(
            f"""
            <div class="rb-brand">
              <div class="rb-brand-badge"><img src="data:image/png;base64,{b64}"/></div>
              <div>{APP_NAME}</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    else:
        st.markdown(
            f"""
            <div class="rb-brand">
              <div class="rb-brand-badge">🏠</div>
              <div>{APP_NAME}</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    if st.button("Logout", key="logout_btn"):
        logout()
        st.rerun()

    st.markdown("</div></div>", unsafe_allow_html=True)

    st.write("")
    col1, col2 = st.columns([1.2, 1])

    with col1:
        st.markdown("<div class='rb-card'>", unsafe_allow_html=True)
        st.markdown(f"<div class='rb-h1'>Welcome 👋</div>", unsafe_allow_html=True)
        st.markdown("<div class='rb-muted'>Your session stays active even on refresh (URL token).</div>", unsafe_allow_html=True)
        st.write("")
        st.write("**Email:**", user.get("email", ""))
        st.write("**Username:**", user.get("username", ""))
        st.write("**Provider:**", user.get("provider", "local"))
        st.write("")
        st.info("This is the base working website shell. Next you can add: posts, listings, chat, saved, etc.")
        st.markdown("</div>", unsafe_allow_html=True)

    with col2:
        st.markdown("<div class='rb-card'>", unsafe_allow_html=True)
        st.write("### Quick Actions")
        if st.button("Go to Profile (demo)", use_container_width=True):
            st.session_state["app_tab"] = "profile"
        if st.button("Settings (demo)", use_container_width=True):
            st.session_state["app_tab"] = "settings"
        st.write("")
        st.write("### Your Domain")
        st.write("When your domain is active, you can point it to Streamlit or to a real hosting later.")
        st.markdown("</div>", unsafe_allow_html=True)

    st.write("")
    tab = st.session_state.get("app_tab", "profile")

    if tab == "profile":
        st.markdown("<div class='rb-card'>", unsafe_allow_html=True)
        st.write("## Profile (demo)")
        st.write("Add profile editing, avatar upload, posts, followers, etc.")
        st.markdown("</div>", unsafe_allow_html=True)
    elif tab == "settings":
        st.markdown("<div class='rb-card'>", unsafe_allow_html=True)
        st.write("## Settings (demo)")
        st.write("Add email verification, notifications, privacy, etc.")
        st.markdown("</div>", unsafe_allow_html=True)


# =============================
# BOOT / ROUTER
# =============================
def boot_load_session():
    # If already loaded in state, keep it
    if st.session_state.get("user_id"):
        return

    tok = get_query_token()
    if tok:
        uid = load_session_from_token(tok)
        if uid:
            st.session_state["user_id"] = uid
            st.session_state["session_token"] = tok
            st.session_state["route"] = "app"
            return

    # default route
    if not st.session_state.get("route"):
        st.session_state["route"] = "login"


def main():
    init_db()
    inject_global_css()
    boot_load_session()

    # If logged in -> app
    if st.session_state.get("user_id"):
        st.session_state["route"] = "app"

    route = st.session_state.get("route", "login")

    if route == "login":
        page_login()
    elif route == "signup":
        page_signup()
    elif route == "reset":
        page_reset()
    elif route == "app":
        page_app()
    else:
        st.session_state["route"] = "login"
        st.rerun()


if __name__ == "__main__":
    main()
