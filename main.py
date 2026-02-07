# main.py
# Run: streamlit run main.py

import os
import re
import uuid
import base64
import sqlite3
import hashlib
import hmac
import secrets
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

AUTH_BG_FILES = ["bg1.jpg", "bg2.jpg", "bg3.jpg"]  # in assets/
BG_ROTATE_SECONDS = 15

# Password hashing
PBKDF2_ITERATIONS = 240_000  # stronger than 180k (still fine on Streamlit)
PEPPER = str(st.secrets.get("PEPPER", "")).encode("utf-8")  # optional secret

# Password reset
RESET_TOKEN_MINUTES = 30
RESET_LINK_BASE = st.secrets.get("RESET_LINK_BASE", "")  # e.g. https://yourapp.streamlit.app


# =============================
# STREAMLIT PAGE CONFIG
# =============================
def _favicon():
    p = os.path.join(ASSETS_DIR, "logo.png")
    return p if os.path.exists(p) else "🏠"


st.set_page_config(
    page_title=APP_NAME,
    page_icon=_favicon(),
    layout="wide",
)


# =============================
# HELPERS
# =============================
def now() -> datetime:
    return datetime.now().replace(microsecond=0)


def now_iso() -> str:
    return now().isoformat()


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
    # light sanity
    if email.count("@") != 1:
        return False
    return True


def asset_path(name: str) -> str:
    p = os.path.join(ASSETS_DIR, name)
    return p if os.path.exists(p) else ""


@st.cache_data(show_spinner=False)
def read_file_b64_cached(path: str) -> str:
    with open(path, "rb") as f:
        return base64.b64encode(f.read()).decode("utf-8")


def read_file_b64(path: str) -> str:
    # wrapper so the rest of your code stays clean
    return read_file_b64_cached(path)


# =============================
# PASSWORD HASHING (PBKDF2)
# Format: pbkdf2_sha256$<iterations>$<salt_b64>$<hash_b64>
# Uses optional PEPPER in addition to salt.
# =============================
def _pbkdf2_hash_password(password: str, salt: bytes, iterations: int) -> str:
    msg = (password or "").encode("utf-8") + (PEPPER or b"")
    dk = hashlib.pbkdf2_hmac("sha256", msg, salt, iterations)
    return base64.b64encode(dk).decode("utf-8")


def make_password_hash(password: str) -> str:
    salt = os.urandom(16)
    salt_b64 = base64.b64encode(salt).decode("utf-8")
    hash_b64 = _pbkdf2_hash_password(password, salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt_b64}${hash_b64}"


def verify_password(password: str, stored: str) -> bool:
    try:
        parts = (stored or "").split("$")
        if len(parts) != 4:
            return False
        algo, iters_s, salt_b64, hash_b64 = parts
        if algo != "pbkdf2_sha256":
            return False
        iterations = int(iters_s)
        salt = base64.b64decode(salt_b64.encode("utf-8"))
        calc = _pbkdf2_hash_password(password, salt, iterations)
        return hmac.compare_digest(calc, hash_b64)
    except Exception:
        return False


# =============================
# QUERY TOKEN (persistent session via URL)
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


def clear_query_params():
    try:
        st.query_params.clear()
        return
    except Exception:
        pass
    try:
        st.experimental_set_query_params()
    except Exception:
        pass


def _query_param_value(name: str) -> str:
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


# =============================
# DB
# =============================
def conn() -> sqlite3.Connection:
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL;")
    c.execute("PRAGMA synchronous=NORMAL;")
    c.execute("PRAGMA busy_timeout=8000;")
    c.execute("PRAGMA foreign_keys=ON;")
    return c


def init_db():
    if st.session_state.get("_db_inited"):
        return

    with conn() as c:
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
            updated_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """)

        # Selector/validator pattern for reset:
        # - store selector in DB (lookup)
        # - store hash(validator) in DB (verification)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            selector TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            validator_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """)

        # Helpful indexes
        cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_reset_user_id ON password_reset_tokens(user_id);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_reset_expires_at ON password_reset_tokens(expires_at);")

        c.commit()

    st.session_state["_db_inited"] = True


def cleanup_expired():
    """Clean expired sessions + expired reset tokens."""
    ts = now_iso()
    with conn() as c:
        c.execute("DELETE FROM sessions WHERE expires_at < ?", (ts,))
        c.execute("""
            DELETE FROM password_reset_tokens
            WHERE expires_at < ? OR (used_at IS NOT NULL)
        """, (ts,))
        c.commit()


def ensure_profile_for_user(user_id: int, email: str):
    email = normalize_email(email)
    base_username = sanitize_username(email.split("@")[0]) or "user"

    with conn() as c:
        cur = c.cursor()
        row = cur.execute("SELECT user_id FROM profiles WHERE user_id=?", (user_id,)).fetchone()
        if row:
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
                return
            except sqlite3.IntegrityError:
                suffix += 1
                if suffix > 9999:
                    return


def get_user(uid: int) -> Dict[str, Any]:
    with conn() as c:
        row = c.execute("""
            SELECT u.id, u.email, u.phone, u.provider,
                   COALESCE(p.username,'') AS username,
                   COALESCE(p.display_name,'') AS display_name
            FROM users u
            LEFT JOIN profiles p ON p.user_id=u.id
            WHERE u.id=?
        """, (uid,)).fetchone()
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
    if len(password) < 8:
        return False, "Password must be at least 8 characters."

    with conn() as c:
        cur = c.cursor()
        try:
            cur.execute(
                "INSERT INTO users (created_at, email, phone, password_hash, provider) VALUES (?,?,?,?,?)",
                (now_iso(), email, phone, make_password_hash(password), "local")
            )
            c.commit()
            uid = int(cur.lastrowid)
        except sqlite3.IntegrityError:
            return False, "This email is already registered."

    ensure_profile_for_user(uid, email)
    return True, "Account created. Please sign in."


def authenticate(email: str, password: str) -> Optional[int]:
    email = normalize_email(email)
    password = (password or "").strip()
    if not email or not password:
        return None

    with conn() as c:
        row = c.execute(
            "SELECT id, email, password_hash FROM users WHERE email=?",
            (email,)
        ).fetchone()

    if not row:
        return None
    if not verify_password(password, row["password_hash"]):
        return None

    uid = int(row["id"])
    ensure_profile_for_user(uid, row["email"])
    return uid


def set_user_password(user_id: int, new_password: str) -> Tuple[bool, str]:
    new_password = (new_password or "").strip()
    if len(new_password) < 8:
        return False, "Password must be at least 8 characters."

    with conn() as c:
        c.execute(
            "UPDATE users SET password_hash=?, provider='local' WHERE id=?",
            (make_password_hash(new_password), user_id)
        )
        c.commit()
    return True, "Password updated."


# =============================
# PASSWORD RESET (token-based)
# =============================
def _hash_validator(validator: str) -> str:
    # HMAC-style hashing with PEPPER to avoid DB leak -> reset token use
    key = PEPPER or b""
    return hmac.new(key, validator.encode("utf-8"), hashlib.sha256).hexdigest()


def create_password_reset(email: str) -> Tuple[bool, str]:
    """Creates a reset token if the email exists. Returns a message (never reveals existence)."""
    email = normalize_email(email)
    if not is_valid_email(email):
        return False, "Please enter a valid email."

    with conn() as c:
        row = c.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()

    # Do not reveal whether it exists
    if not row:
        return True, "If that email exists, a reset link can be generated."

    user_id = int(row["id"])
    selector = secrets.token_urlsafe(10)
    validator = secrets.token_urlsafe(32)
    vhash = _hash_validator(validator)
    exp = (now() + timedelta(minutes=RESET_TOKEN_MINUTES)).isoformat()

    with conn() as c:
        c.execute("""
            INSERT INTO password_reset_tokens (selector, user_id, validator_hash, created_at, expires_at, used_at)
            VALUES (?,?,?,?,?,NULL)
        """, (selector, user_id, vhash, now_iso(), exp))
        c.commit()

    # Build link (best effort)
    base = (RESET_LINK_BASE or "").rstrip("/")
    if base:
        link = f"{base}/?reset=1&selector={selector}&validator={validator}"
    else:
        # fallback: relative link (works locally)
        link = f"/?reset=1&selector={selector}&validator={validator}"

    return True, f"Reset link (demo — send by email in production): {link}"


def consume_password_reset(selector: str, validator: str) -> Optional[int]:
    selector = (selector or "").strip()
    validator = (validator or "").strip()
    if not selector or not validator:
        return None

    with conn() as c:
        row = c.execute("""
            SELECT selector, user_id, validator_hash, expires_at, used_at
            FROM password_reset_tokens
            WHERE selector=?
        """, (selector,)).fetchone()

        if not row:
            return None
        if row["used_at"] is not None:
            return None
        if datetime.fromisoformat(row["expires_at"]) < now():
            return None

        if not hmac.compare_digest(row["validator_hash"], _hash_validator(validator)):
            return None

        # mark used
        c.execute("UPDATE password_reset_tokens SET used_at=? WHERE selector=?", (now_iso(), selector))
        c.commit()

    return int(row["user_id"])


# =============================
# SESSIONS (persistent login)
# =============================
def create_session(user_id: int) -> str:
    token = uuid.uuid4().hex + uuid.uuid4().hex
    expires_at = (now() + timedelta(days=SESSION_DAYS)).isoformat()

    with conn() as c:
        c.execute("""
            INSERT INTO sessions (token, user_id, created_at, last_seen, expires_at)
            VALUES (?,?,?,?,?)
        """, (token, user_id, now_iso(), now_iso(), expires_at))
        c.commit()
    return token


def load_session_from_token(token: str) -> Optional[int]:
    token = (token or "").strip()
    if not token:
        return None

    with conn() as c:
        row = c.execute("SELECT user_id, expires_at FROM sessions WHERE token=?", (token,)).fetchone()
        if not row:
            return None

        exp = datetime.fromisoformat(row["expires_at"])
        if exp < now():
            c.execute("DELETE FROM sessions WHERE token=?", (token,))
            c.commit()
            return None

        c.execute("UPDATE sessions SET last_seen=? WHERE token=?", (now_iso(), token))
        c.commit()
        return int(row["user_id"])


def delete_session(token: str):
    token = (token or "").strip()
    if not token:
        return
    with conn() as c:
        c.execute("DELETE FROM sessions WHERE token=?", (token,))
        c.commit()


def logout():
    tok = st.session_state.get("session_token") or get_query_token()
    if tok:
        delete_session(tok)
    clear_query_params()
    for k in list(st.session_state.keys()):
        if k in ["user_id", "route", "session_token", "oauth_state", "app_tab"]:
            st.session_state.pop(k, None)


# =============================
# GOOGLE OAUTH (REAL, with state validation)
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


def build_google_auth_url() -> str:
    client_id = st.secrets["GOOGLE_CLIENT_ID"]
    redirect_uri = st.secrets["GOOGLE_REDIRECT_URI"]

    oauth = OAuth2Session(
        client_id=client_id,
        scope="openid email profile",
        redirect_uri=redirect_uri,
    )
    auth_url, state = oauth.create_authorization_url(
        "https://accounts.google.com/o/oauth2/v2/auth",
        access_type="offline",
        prompt="select_account",
    )
    st.session_state["oauth_state"] = state
    return auth_url


def google_oauth_handle_callback_if_present():
    if not google_oauth_is_configured():
        return

    code = _query_param_value("code")
    if not code:
        return

    returned_state = _query_param_value("state")
    expected_state = st.session_state.get("oauth_state", "")

    if not expected_state or not returned_state or returned_state != expected_state:
        st.error("Google login failed: invalid state (CSRF protection). Please try again.")
        clear_query_params()
        st.session_state.pop("oauth_state", None)
        return

    client_id = st.secrets["GOOGLE_CLIENT_ID"]
    client_secret = st.secrets["GOOGLE_CLIENT_SECRET"]
    redirect_uri = st.secrets["GOOGLE_REDIRECT_URI"]

    oauth = OAuth2Session(
        client_id=client_id,
        scope="openid email profile",
        redirect_uri=redirect_uri,
        state=expected_state,
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

        with conn() as c:
            row = c.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
            if row:
                uid = int(row["id"])
            else:
                # create user with random password (can reset later)
                pw = uuid.uuid4().hex[:18] + "A!"
                cur = c.cursor()
                cur.execute(
                    "INSERT INTO users (created_at, email, phone, password_hash, provider) VALUES (?,?,?,?,?)",
                    (now_iso(), email, "", make_password_hash(pw), "google")
                )
                c.commit()
                uid = int(cur.lastrowid)

        ensure_profile_for_user(uid, email)

        # clear OAuth params
        clear_query_params()
        st.session_state.pop("oauth_state", None)

        token = create_session(uid)
        st.session_state["user_id"] = uid
        st.session_state["session_token"] = token
        set_query_token(token)
        st.session_state["route"] = "app"
        st.rerun()

    except Exception as e:
        st.error(f"Google login failed: {e}")
        clear_query_params()
        st.session_state.pop("oauth_state", None)


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

          .stTextInput input {
            border-radius: 14px !important;
            height: 46px !important;
          }
        </style>
        """,
        unsafe_allow_html=True
    )


# =============================
# AUTH BACKGROUND SLIDESHOW
# =============================
def inject_auth_background_slideshow():
    bgs = []
    for fn in AUTH_BG_FILES:
        p = asset_path(fn)
        if p:
            ext = os.path.splitext(fn)[1].lower().replace(".", "")
            if ext not in ["jpg", "jpeg", "png", "webp"]:
                continue
            b64 = read_file_b64(p)
            mime = "image/jpeg" if ext in ["jpg", "jpeg"] else f"image/{ext}"
            bgs.append(f"data:{mime};base64,{b64}")

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


def inject_auth_css():
    st.markdown(
        """
        <style>
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
            justify-content:space-between;
            gap: 10px;
            margin-top: 8px;
          }

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
    ico = asset_path("google_logo.png")
    if ico:
        b64 = read_file_b64(ico)
        icon_html = f"<img class='rb-social-ico' src='data:image/png;base64,{b64}' />"
    else:
        icon_html = """
        <span class="rb-social-ico" style="
          width:18px;height:18px;border-radius:999px;
          display:inline-flex;align-items:center;justify-content:center;
          border:1px solid #e5e7eb;font-size:12px;font-weight:950;
        ">G</span>
        """
    return icon_html


def render_google_oauth_button():
    icon_html = google_button_html()
    if not google_oauth_is_configured():
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
# ROUTES
# =============================
def page_login():
    auth_shell_open("Find rentals in Berlin • message fast • build your profile")

    st.markdown("<div class='rb-auth-card'>", unsafe_allow_html=True)
    st.markdown("<div class='rb-auth-h1'>Sign in</div>", unsafe_allow_html=True)
    st.markdown("<div class='rb-auth-sub'>Use email & password or continue with Google.</div>", unsafe_allow_html=True)
    st.write("")

    # Handle Google callback
    google_oauth_handle_callback_if_present()

    render_google_oauth_button()
    st.write("")
    render_apple_button_ui()
    st.markdown("<div class='rb-divider'>OR</div>", unsafe_allow_html=True)

    with st.form("login_form"):
        email = st.text_input("Email", placeholder="name@email.com")
        password = st.text_input("Password", type="password", placeholder="Minimum 8 characters")
        submitted = st.form_submit_button("Sign in", type="primary", use_container_width=True)

    st.markdown("<div class='rb-forgot-wrap'>", unsafe_allow_html=True)
    c1, c2 = st.columns(2)
    with c1:
        if st.button("Create account", use_container_width=True):
            st.session_state["route"] = "signup"
            st.rerun()
    with c2:
        if st.button("Forgot password?", use_container_width=True):
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

    st.markdown("<div class='rb-foot'>By continuing, you agree to basic community rules and privacy.</div>", unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)
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
        password = st.text_input("Password", type="password", placeholder="Minimum 8 characters")
        submitted = st.form_submit_button("Create account", type="primary", use_container_width=True)

    if submitted:
        ok, msg = create_user(email, phone, password)
        if ok:
            st.success(msg)
            st.session_state["route"] = "login"
            st.info("Now sign in.")
        else:
            st.error(msg)

    if st.button("Back to Sign in", use_container_width=True):
        st.session_state["route"] = "login"
        st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)
    auth_shell_close()


def page_reset():
    # Two modes:
    # 1) Request reset link (email -> link)
    # 2) Use reset link (selector+validator) to set new password
    is_from_link = _query_param_value("reset") == "1"
    selector = _query_param_value("selector")
    validator = _query_param_value("validator")

    auth_shell_open("Reset your password • sign in again")
    st.markdown("<div class='rb-auth-card'>", unsafe_allow_html=True)

    if is_from_link and selector and validator:
        st.markdown("<div class='rb-auth-h1'>Set new password</div>", unsafe_allow_html=True)
        st.markdown("<div class='rb-auth-sub'>This link expires soon.</div>", unsafe_allow_html=True)
        st.write("")

        with st.form("reset_set_form"):
            new_password = st.text_input("New password", type="password", placeholder="Minimum 8 characters")
            submitted = st.form_submit_button("Update password", type="primary", use_container_width=True)

        if submitted:
            uid = consume_password_reset(selector, validator)
            if not uid:
                st.error("Invalid or expired reset link. Request a new one.")
            else:
                ok, msg = set_user_password(uid, new_password)
                if ok:
                    st.success(msg)
                    clear_query_params()
                    st.session_state["route"] = "login"
                    st.info("Please sign in now.")
                else:
                    st.error(msg)

    else:
        st.markdown("<div class='rb-auth-h1'>Reset password</div>", unsafe_allow_html=True)
        st.markdown("<div class='rb-auth-sub'>Request a reset link for your email.</div>", unsafe_allow_html=True)
        st.write("")

        with st.form("reset_request_form"):
            email = st.text_input("Email", placeholder="name@email.com")
            submitted = st.form_submit_button("Generate reset link", type="primary", use_container_width=True)

        if submitted:
            ok, msg = create_password_reset(email)
            if ok:
                st.success("If that email exists, a reset link can be generated.")
                st.info(msg)  # demo display; replace with email sending
            else:
                st.error(msg)

    if st.button("Back to Sign in", use_container_width=True):
        clear_query_params()
        st.session_state["route"] = "login"
        st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)
    auth_shell_close()


# =============================
# APP PAGE
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
        st.markdown("<div class='rb-muted'>Your session stays active on refresh (URL token).</div>", unsafe_allow_html=True)
        st.write("")
        st.write("**Email:**", user.get("email", ""))
        st.write("**Username:**", user.get("username", ""))
        st.write("**Provider:**", user.get("provider", "local"))
        st.write("")
        st.info("Base website shell is ready. Next: listings, chat, saved, verification, moderation.")
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
        st.write("When your domain is active, you can point it to Streamlit or migrate to a real backend later.")
        st.markdown("</div>", unsafe_allow_html=True)

    st.write("")
    tab = st.session_state.get("app_tab", "profile")

    if tab == "profile":
        st.markdown("<div class='rb-card'>", unsafe_allow_html=True)
        st.write("## Profile (demo)")
        st.write("Add profile editing, avatar upload, listings, trust badges, etc.")
        st.markdown("</div>", unsafe_allow_html=True)
    elif tab == "settings":
        st.markdown("<div class='rb-card'>", unsafe_allow_html=True)
        st.write("## Settings (demo)")
        st.write("Add email verification, notifications, privacy, and active sessions management.")
        st.markdown("</div>", unsafe_allow_html=True)


# =============================
# BOOT / ROUTER
# =============================
def boot_load_session():
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

    if not st.session_state.get("route"):
        st.session_state["route"] = "login"


def main():
    init_db()
    cleanup_expired()
    inject_global_css()
    boot_load_session()

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
