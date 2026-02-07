# main.py
# Run: streamlit run main.py
#
# RentinBerlin — Robust single-file Streamlit app:
# ✅ Beautiful Auth (Login / Signup / Reset) + Background slideshow
# ✅ Secure password hashing (PBKDF2 + iterations + optional PEPPER)
# ✅ Token sessions (DB) + optional URL token (?t=...)
# ✅ Google OAuth (Authlib) with state validation (CSRF protection)
# ✅ Full app shell: Dashboard, Listings (CRUD-lite), Messages (demo), Saved, Profile, Settings
# ✅ Rate limiting + brute-force friction
# ✅ DB cleanup, indexes, foreign keys
#
# Optional assets (in ./assets):
#   logo.png
#   google_logo.png
#   bg1.jpg bg2.jpg bg3.jpg
#
# Secrets (Streamlit secrets):
#   PEPPER
#   GOOGLE_CLIENT_ID
#   GOOGLE_CLIENT_SECRET
#   GOOGLE_REDIRECT_URI
#   RESET_LINK_BASE (optional; for reset link display)
#
# Notes:
# - "Reset password" is token-based (demo displays link; plug in email later).
# - URL token persistence is kept because you asked; it has inherent privacy tradeoffs.

import os
import re
import uuid
import base64
import sqlite3
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple, List

import streamlit as st
import streamlit.components.v1 as components

AUTHLIB_OK = False
try:
    from authlib.integrations.requests_client import OAuth2Session
    AUTHLIB_OK = True
except Exception:
    AUTHLIB_OK = False


# =============================
# APP CONFIG
# =============================
APP_NAME = "RentinBerlin"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "rentinberlin.db")
ASSETS_DIR = os.path.join(BASE_DIR, "assets")
os.makedirs(ASSETS_DIR, exist_ok=True)

SESSION_DAYS = 30
REGISTRATION_ENABLED = True

AUTH_BG_FILES = ["bg1.jpg", "bg2.jpg", "bg3.jpg"]
BG_ROTATE_SECONDS = 15

PBKDF2_ITERATIONS = 240_000
PEPPER = str(st.secrets.get("PEPPER", "")).encode("utf-8")  # optional secret

RESET_TOKEN_MINUTES = 30
RESET_LINK_BASE = st.secrets.get("RESET_LINK_BASE", "")

RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_MAX_ATTEMPTS = 8

# Demo seed listings on first run
SEED_DEMO_DATA = True


def _favicon():
    p = os.path.join(ASSETS_DIR, "logo.png")
    return p if os.path.exists(p) else "🏠"


st.set_page_config(page_title=APP_NAME, page_icon=_favicon(), layout="wide")


# =============================
# UTIL
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
    return read_file_b64_cached(path)


def _safe_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default


# =============================
# QUERY PARAMS (URL TOKEN)
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
            provider TEXT NOT NULL DEFAULT 'local',
            is_verified INTEGER NOT NULL DEFAULT 0
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS profiles (
            user_id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            display_name TEXT,
            bio TEXT,
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

        cur.execute("""
        CREATE TABLE IF NOT EXISTS auth_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            email TEXT NOT NULL,
            ok INTEGER NOT NULL
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS listings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            district TEXT,
            rent_eur INTEGER,
            rooms REAL,
            move_in TEXT,
            description TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS saved_listings (
            user_id INTEGER NOT NULL,
            listing_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY(user_id, listing_id),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(listing_id) REFERENCES listings(id) ON DELETE CASCADE
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            body TEXT NOT NULL,
            FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(receiver_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """)

        # indexes
        cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_reset_user_id ON password_reset_tokens(user_id);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_reset_expires_at ON password_reset_tokens(expires_at);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_listings_user_id ON listings(user_id);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_listings_active ON listings(is_active);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_auth_attempts_email_time ON auth_attempts(email, created_at);")
        c.commit()

    st.session_state["_db_inited"] = True


def cleanup_expired():
    ts = now_iso()
    with conn() as c:
        c.execute("DELETE FROM sessions WHERE expires_at < ?", (ts,))
        c.execute("DELETE FROM password_reset_tokens WHERE expires_at < ? OR used_at IS NOT NULL", (ts,))
        # keep auth attempts only 24h
        cutoff = (now() - timedelta(hours=24)).isoformat()
        c.execute("DELETE FROM auth_attempts WHERE created_at < ?", (cutoff,))
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
                    "INSERT INTO profiles (user_id, username, display_name, bio, updated_at) VALUES (?,?,?,?,?)",
                    (user_id, candidate, "", "", now_iso()),
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
            SELECT u.id, u.email, u.phone, u.provider, u.is_verified,
                   COALESCE(p.username,'') AS username,
                   COALESCE(p.display_name,'') AS display_name,
                   COALESCE(p.bio,'') AS bio
            FROM users u
            LEFT JOIN profiles p ON p.user_id=u.id
            WHERE u.id=?
        """, (uid,)).fetchone()
    return dict(row) if row else {}


def find_user_by_email(email: str) -> Optional[int]:
    email = normalize_email(email)
    with conn() as c:
        row = c.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    return int(row["id"]) if row else None


# =============================
# PASSWORD HASHING (PBKDF2)
# Format: pbkdf2_sha256$<iters>$<salt_b64>$<hash_b64>
# =============================
def _pbkdf2(password: str, salt: bytes, iterations: int) -> str:
    msg = (password or "").encode("utf-8") + (PEPPER or b"")
    dk = hashlib.pbkdf2_hmac("sha256", msg, salt, iterations)
    return base64.b64encode(dk).decode("utf-8")


def make_password_hash(password: str) -> str:
    salt = os.urandom(16)
    salt_b64 = base64.b64encode(salt).decode("utf-8")
    h = _pbkdf2(password, salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt_b64}${h}"


def verify_password(password: str, stored: str) -> bool:
    try:
        parts = (stored or "").split("$")
        if len(parts) != 4:
            return False
        algo, iters_s, salt_b64, hash_b64 = parts
        if algo != "pbkdf2_sha256":
            return False
        iters = int(iters_s)
        salt = base64.b64decode(salt_b64.encode("utf-8"))
        calc = _pbkdf2(password, salt, iters)
        return hmac.compare_digest(calc, hash_b64)
    except Exception:
        return False


# =============================
# RATE LIMITING
# =============================
def _record_auth_attempt(email: str, ok: bool):
    email = normalize_email(email)
    with conn() as c:
        c.execute(
            "INSERT INTO auth_attempts (created_at, email, ok) VALUES (?,?,?)",
            (now_iso(), email, 1 if ok else 0),
        )
        c.commit()


def is_rate_limited(email: str) -> bool:
    email = normalize_email(email)
    cutoff = (now() - timedelta(seconds=RATE_LIMIT_WINDOW_SECONDS)).isoformat()
    with conn() as c:
        row = c.execute(
            "SELECT COUNT(*) AS n FROM auth_attempts WHERE email=? AND created_at>=?",
            (email, cutoff),
        ).fetchone()
    return int(row["n"]) >= RATE_LIMIT_MAX_ATTEMPTS


# =============================
# AUTH: LOCAL
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
                "INSERT INTO users (created_at, email, phone, password_hash, provider, is_verified) VALUES (?,?,?,?,?,?)",
                (now_iso(), email, phone, make_password_hash(password), "local", 0),
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

    if is_rate_limited(email):
        return None

    with conn() as c:
        row = c.execute(
            "SELECT id, email, password_hash FROM users WHERE email=?",
            (email,),
        ).fetchone()

    if not row:
        _record_auth_attempt(email, False)
        return None

    ok = verify_password(password, row["password_hash"])
    _record_auth_attempt(email, ok)

    if not ok:
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
            (make_password_hash(new_password), user_id),
        )
        c.commit()

    return True, "Password updated."


# =============================
# PASSWORD RESET (TOKEN BASED)
# =============================
def _hash_validator(validator: str) -> str:
    key = PEPPER or b""
    return hmac.new(key, validator.encode("utf-8"), hashlib.sha256).hexdigest()


def create_password_reset(email: str) -> Tuple[bool, str]:
    email = normalize_email(email)
    if not is_valid_email(email):
        return False, "Please enter a valid email."

    with conn() as c:
        row = c.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()

    # Never reveal existence
    if not row:
        return True, "If the email exists, a reset link can be generated."

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

    base = (RESET_LINK_BASE or "").rstrip("/")
    if base:
        link = f"{base}/?reset=1&selector={selector}&validator={validator}"
    else:
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

        c.execute("UPDATE password_reset_tokens SET used_at=? WHERE selector=?", (now_iso(), selector))
        c.commit()

    return int(row["user_id"])


# =============================
# SESSIONS
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
        if k in [
            "user_id", "route", "session_token", "oauth_state",
            "nav", "theme_mode", "listings_filter", "app_toast",
        ]:
            st.session_state.pop(k, None)


# =============================
# GOOGLE OAUTH (REAL + STATE)
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
                c.execute("UPDATE users SET provider='google', is_verified=1 WHERE id=?", (uid,))
                c.commit()
            else:
                # Create local record
                pw = uuid.uuid4().hex[:18] + "A!"
                cur = c.cursor()
                cur.execute(
                    "INSERT INTO users (created_at, email, phone, password_hash, provider, is_verified) VALUES (?,?,?,?,?,?)",
                    (now_iso(), email, "", make_password_hash(pw), "google", 1),
                )
                c.commit()
                uid = int(cur.lastrowid)

        ensure_profile_for_user(uid, email)

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
# UI / THEME
# =============================
def inject_global_css():
    # theme_mode: "dark" or "light"
    mode = st.session_state.get("theme_mode", "dark")

    # Carefully tuned spacing + "real product" vibe
    # Uses CSS variables for quick palette changes.
    if mode == "dark":
        vars_css = """
        :root{
          --rb-bg: #070A12;
          --rb-surface: rgba(255,255,255,0.06);
          --rb-surface2: rgba(255,255,255,0.09);
          --rb-stroke: rgba(255,255,255,0.10);
          --rb-text: rgba(255,255,255,0.92);
          --rb-muted: rgba(255,255,255,0.62);
          --rb-soft: rgba(255,255,255,0.14);
          --rb-accent: #ff7a1a;
          --rb-accent2: #7c3aed;
          --rb-good: #22c55e;
          --rb-warn: #fbbf24;
        }
        """
    else:
        vars_css = """
        :root{
          --rb-bg: #f6f8fb;
          --rb-surface: rgba(255,255,255,0.92);
          --rb-surface2: rgba(255,255,255,0.98);
          --rb-stroke: rgba(2,6,23,0.08);
          --rb-text: rgba(2,6,23,0.92);
          --rb-muted: rgba(2,6,23,0.55);
          --rb-soft: rgba(2,6,23,0.08);
          --rb-accent: #ff7a1a;
          --rb-accent2: #4f46e5;
          --rb-good: #16a34a;
          --rb-warn: #d97706;
        }
        """

    st.markdown(
        f"""
        <style>
          {vars_css}

          #MainMenu {{visibility: hidden;}}
          footer {{visibility: hidden;}}
          header {{visibility: hidden;}}
          .stApp {{
            background: var(--rb-bg);
            color: var(--rb-text);
          }}

          section.main > div.block-container {{
            padding-top: 0.8rem;
            padding-bottom: 4.2rem;
            max-width: 1280px;
          }}

          @media (max-width: 768px) {{
            section.main > div.block-container {{
              padding-left: 0.85rem;
              padding-right: 0.85rem;
            }}
          }}

          /* Streamlit widgets polish */
          .stTextInput input, .stTextArea textarea, .stNumberInput input, .stSelectbox select {{
            border-radius: 14px !important;
          }}
          .stTextInput input {{
            height: 46px !important;
          }}

          .stButton>button {{
            border-radius: 14px !important;
            border: 1px solid var(--rb-stroke) !important;
            background: var(--rb-surface2) !important;
            color: var(--rb-text) !important;
            padding: 0.62rem 0.95rem !important;
            font-weight: 900 !important;
            transition: transform .08s ease, box-shadow .12s ease;
          }}
          .stButton>button:hover {{
            transform: translateY(-1px);
            box-shadow: 0 16px 40px rgba(0,0,0,0.20);
            border-color: var(--rb-soft) !important;
          }}
          .stButton>button[kind="primary"] {{
            background: linear-gradient(135deg, var(--rb-accent), var(--rb-accent2)) !important;
            border-color: rgba(255,255,255,0.12) !important;
            color: white !important;
            box-shadow: 0 14px 40px rgba(255, 122, 26, 0.20) !important;
          }}

          /* app cards */
          .rb-card {{
            background: var(--rb-surface);
            border: 1px solid var(--rb-stroke);
            border-radius: 18px;
            box-shadow: 0 18px 55px rgba(0,0,0,0.22);
            padding: 14px;
            backdrop-filter: blur(14px);
          }}
          .rb-h1 {{
            font-weight: 950;
            font-size: 28px;
            margin: 0;
            color: var(--rb-text);
          }}
          .rb-muted {{
            color: var(--rb-muted);
            font-size: 12px;
          }}
          .rb-pill {{
            display:inline-flex;
            align-items:center;
            gap:8px;
            padding: 6px 10px;
            border-radius: 999px;
            border: 1px solid var(--rb-stroke);
            background: var(--rb-surface2);
            font-weight: 900;
            font-size: 12px;
            color: var(--rb-text);
          }}

          /* topbar */
          .rb-topbar {{
            position: sticky;
            top: 0;
            z-index: 50;
            background: rgba(0,0,0,0.18);
            backdrop-filter: blur(14px);
            border-bottom: 1px solid var(--rb-stroke);
            padding: 10px 0 10px 0;
          }}
          .rb-topbar-inner {{
            max-width: 1280px;
            margin: 0 auto;
            padding: 0 10px;
            display:flex;
            align-items:center;
            justify-content:space-between;
            gap: 12px;
          }}
          .rb-brand {{
            display:flex;
            align-items:center;
            gap: 10px;
            font-weight: 950;
            color: var(--rb-text);
          }}
          .rb-brand-badge {{
            width: 40px;
            height: 40px;
            border-radius: 14px;
            background: rgba(255,255,255,0.10);
            border: 1px solid var(--rb-stroke);
            box-shadow: 0 18px 45px rgba(0,0,0,0.20);
            display:flex;
            align-items:center;
            justify-content:center;
            overflow:hidden;
          }}
          .rb-brand-badge img{{ width:100%; height:100%; object-fit:cover; }}
          .rb-nav {{
            display:flex;
            align-items:center;
            gap: 8px;
            flex-wrap: wrap;
            justify-content: flex-end;
          }}
          .rb-nav button {{
            border-radius: 999px !important;
            padding: 0.45rem 0.75rem !important;
          }}

          /* social buttons (HTML) */
          .rb-social-btn{{
            width: 100%;
            display:flex;
            align-items:center;
            justify-content:center;
            gap: 10px;
            padding: 12px 14px;
            border-radius: 14px;
            border: 1px solid var(--rb-stroke);
            background: rgba(255,255,255,0.10);
            color: var(--rb-text);
            font-weight: 950;
            text-decoration: none !important;
            box-shadow: 0 12px 35px rgba(0,0,0,0.20);
            transition: transform .08s ease, box-shadow .12s ease, border-color .12s ease;
          }}
          .rb-social-btn:hover{{
            border-color: rgba(255,255,255,0.18);
            box-shadow: 0 18px 50px rgba(0,0,0,0.26);
            transform: translateY(-1px);
          }}
          .rb-social-ico{{ width: 18px; height: 18px; display:inline-block; }}
          .rb-apple{{ background: rgba(10,15,26,0.85); }}
          .rb-apple:hover{{ background: rgba(8,11,20,0.92); }}

          /* auth */
          .rb-auth-shell{{
            position: relative;
            z-index: 5;
            max-width: 460px;
            margin: 0 auto;
            padding-top: 4vh;
            padding-bottom: 8vh;
          }}
          @media (max-width: 900px) {{
            .rb-auth-shell{{ max-width: 94vw; padding-top: 2vh; }}
          }}
          .rb-auth-top{{
            display:flex;
            flex-direction:column;
            align-items:center;
            text-align:center;
            margin-bottom: 16px;
          }}
          .rb-auth-logo{{
            width: 72px;
            height: 72px;
            border-radius: 20px;
            overflow:hidden;
            background: rgba(255,255,255,0.10);
            border: 1px solid var(--rb-stroke);
            box-shadow: 0 30px 90px rgba(0,0,0,0.35);
            display:flex;
            align-items:center;
            justify-content:center;
            backdrop-filter: blur(12px);
          }}
          .rb-auth-logo img{{ width:100%; height:100%; object-fit:cover; display:block; border:0 !important; }}
          .rb-auth-appname{{
            margin-top: 10px;
            font-weight: 950;
            font-size: 26px;
            letter-spacing: 0.2px;
            color: var(--rb-text);
          }}
          .rb-auth-tagline{{
            margin-top: 6px;
            font-size: 13px;
            color: var(--rb-muted);
          }}
          .rb-auth-card{{
            background: rgba(255,255,255,0.07);
            border: 1px solid var(--rb-stroke);
            border-radius: 24px;
            box-shadow: 0 40px 120px rgba(0,0,0,0.40);
            padding: 18px 18px 14px 18px;
            backdrop-filter: blur(16px);
          }}
          .rb-auth-h1{{ font-weight: 950; font-size: 28px; margin: 0; color: var(--rb-text); }}
          .rb-auth-sub{{ margin-top: 6px; color: var(--rb-muted); font-size: 13px; }}
          .rb-divider{{
            display:flex; align-items:center; gap:10px; margin: 14px 0;
            color: var(--rb-muted); font-size: 12px; font-weight: 900;
          }}
          .rb-divider:before,.rb-divider:after{{ content:""; height:1px; flex:1; background: var(--rb-stroke); }}
          .rb-foot{{ margin-top: 10px; text-align:center; font-size: 12px; color: var(--rb-muted); }}
          .rb-row-between{{ display:flex; justify-content:space-between; gap: 10px; margin-top: 10px; }}

          /* nice table-like listing blocks */
          .rb-listing {{
            border: 1px solid var(--rb-stroke);
            background: rgba(255,255,255,0.06);
            border-radius: 18px;
            padding: 12px;
            box-shadow: 0 18px 45px rgba(0,0,0,0.18);
          }}
          .rb-listing h4 {{
            margin: 0 0 6px 0;
            font-weight: 950;
            color: var(--rb-text);
          }}
          .rb-kv {{
            display:flex;
            gap: 10px;
            flex-wrap: wrap;
          }}
          .rb-kv span {{
            font-size: 12px;
            color: var(--rb-muted);
            border: 1px solid var(--rb-stroke);
            padding: 6px 10px;
            border-radius: 999px;
            background: rgba(255,255,255,0.06);
          }}
        </style>
        """,
        unsafe_allow_html=True,
    )


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
        # fallback cinematic gradient
        st.markdown(
            """
            <style>
              .rb-bg{
                position: fixed; inset: 0; z-index: 0;
                background:
                  radial-gradient(1200px 800px at 10% 0%, rgba(255,122,26,0.20), transparent 55%),
                  radial-gradient(900px 700px at 90% 10%, rgba(124,58,237,0.22), transparent 55%),
                  radial-gradient(1000px 900px at 40% 92%, rgba(34,197,94,0.12), transparent 55%),
                  radial-gradient(700px 500px at 70% 60%, rgba(59,130,246,0.12), transparent 55%),
                  #070A12;
              }
              .rb-grid{
                position: fixed; inset: 0; z-index: 1; pointer-events:none;
                background-image: linear-gradient(rgba(255,255,255,0.04) 1px, transparent 1px),
                                  linear-gradient(90deg, rgba(255,255,255,0.04) 1px, transparent 1px);
                background-size: 42px 42px;
                mask-image: radial-gradient(400px 400px at 50% 20%, black 45%, transparent 70%);
                opacity: 0.55;
              }
            </style>
            <div class="rb-bg"></div>
            <div class="rb-grid"></div>
            """,
            unsafe_allow_html=True,
        )
        return

    js_array = "[" + ",".join([f"'{u}'" for u in bgs]) + "]"
    components.html(
        f"""
        <style>
          .rb-bg {{
            position: fixed; inset: 0; z-index: 0;
            background-image: url("{bgs[0]}");
            background-size: cover;
            background-position: center;
            background-repeat: no-repeat;
            transform: scale(1.03);
            filter: saturate(1.07) contrast(1.03);
            transition: background-image 0.8s ease-in-out;
          }}
          .rb-bg::after {{
            content:""; position:absolute; inset:0;
            background:
              radial-gradient(900px 700px at 20% 10%, rgba(255,122,26,0.20), transparent 55%),
              radial-gradient(800px 650px at 80% 10%, rgba(124,58,237,0.22), transparent 55%),
              linear-gradient(180deg, rgba(2,6,23,0.55) 0%, rgba(2,6,23,0.45) 45%, rgba(2,6,23,0.70) 100%);
          }}
          .rb-spark {{
            position: fixed; inset:0; z-index:1; pointer-events:none;
            background:
              radial-gradient(2px 2px at 10% 20%, rgba(255,255,255,0.35), transparent 60%),
              radial-gradient(2px 2px at 60% 35%, rgba(255,255,255,0.25), transparent 60%),
              radial-gradient(2px 2px at 80% 70%, rgba(255,255,255,0.30), transparent 60%),
              radial-gradient(1px 1px at 35% 80%, rgba(255,255,255,0.22), transparent 60%);
            opacity: 0.65;
          }}
        </style>
        <div class="rb-bg" id="rbBg"></div>
        <div class="rb-spark"></div>
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
        height=0,
    )


def auth_shell_open(tagline: str):
    inject_auth_background_slideshow()
    st.markdown("<div class='rb-auth-shell'>", unsafe_allow_html=True)

    logo = asset_path("logo.png")
    if logo:
        b64 = read_file_b64(logo)
        st.markdown(
            f"""
            <div class="rb-auth-top">
              <div class="rb-auth-logo"><img src="data:image/png;base64,{b64}"/></div>
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


def google_button_html() -> str:
    ico = asset_path("google_logo.png")
    if ico:
        b64 = read_file_b64(ico)
        return f"<img class='rb-social-ico' src='data:image/png;base64,{b64}' />"
    return """
      <span class="rb-social-ico" style="
        width:18px;height:18px;border-radius:999px;
        display:inline-flex;align-items:center;justify-content:center;
        border:1px solid rgba(255,255,255,0.18);
        font-size:12px;font-weight:950;
      ">G</span>
    """


def render_google_oauth_button():
    icon_html = google_button_html()
    if not google_oauth_is_configured():
        st.markdown(
            f"""
            <a class="rb-social-btn" href="#" onclick="return false;">
              {icon_html} Continue with Google
            </a>
            <div class="rb-muted" style="margin-top:8px;">
              Google OAuth not configured. Install <b>Authlib</b> and set secrets.
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    auth_url = build_google_auth_url()
    st.markdown(
        f"""
        <a class="rb-social-btn" href="{auth_url}">
          {icon_html} Continue with Google
        </a>
        """,
        unsafe_allow_html=True,
    )


def render_apple_button_ui():
    st.markdown(
        """
        <a class="rb-social-btn rb-apple" href="#" onclick="return false;">
          <span class="rb-social-ico" style="font-size:16px; line-height:0;"></span>
          Continue with Apple
        </a>
        <div class="rb-muted" style="margin-top:8px;">
          Apple login UI is ready. Real Apple OAuth needs Apple Developer keys.
        </div>
        """,
        unsafe_allow_html=True,
    )


# =============================
# DATA: LISTINGS
# =============================
def seed_demo_data_if_needed():
    if not SEED_DEMO_DATA:
        return
    if st.session_state.get("_seeded"):
        return

    with conn() as c:
        row = c.execute("SELECT COUNT(*) AS n FROM listings").fetchone()
        if int(row["n"]) > 0:
            st.session_state["_seeded"] = True
            return

    # Create demo owner if none
    demo_email = "demo@rentinberlin.app"
    uid = find_user_by_email(demo_email)
    if not uid:
        with conn() as c:
            c.execute(
                "INSERT INTO users (created_at, email, phone, password_hash, provider, is_verified) VALUES (?,?,?,?,?,?)",
                (now_iso(), demo_email, "", make_password_hash("DemoPass123!"), "local", 1),
            )
            c.commit()
            uid = int(c.execute("SELECT id FROM users WHERE email=?", (demo_email,)).fetchone()["id"])
    ensure_profile_for_user(uid, demo_email)

    demos = [
        ("Sunny Altbau near Tempelhofer Feld", "Neukölln", 1390, 2.0, "2026-03-01",
         "Bright 2-room Altbau with high ceilings, quiet courtyard, fast U-Bahn access."),
        ("Minimal studio — furnished, fast move-in", "Mitte", 1190, 1.0, "2026-02-20",
         "Furnished studio, modern kitchen, ideal for newcomers. Includes internet."),
        ("Family-friendly 3-room with balcony", "Prenzlauer Berg", 2190, 3.0, "2026-04-01",
         "Spacious 3-room, balcony, elevator, playground nearby, calm street."),
        ("Cozy WG room in creative shared flat", "Friedrichshain", 650, 1.0, "2026-02-15",
         "Room in a friendly WG. Flexible contract, great cafes and nightlife."),
    ]

    with conn() as c:
        for t, d, r, rooms, move_in, desc in demos:
            c.execute("""
                INSERT INTO listings (created_at, user_id, title, district, rent_eur, rooms, move_in, description, is_active)
                VALUES (?,?,?,?,?,?,?,?,1)
            """, (now_iso(), uid, t, d, int(r), float(rooms), move_in, desc))
        c.commit()

    st.session_state["_seeded"] = True


def create_listing(user_id: int, title: str, district: str, rent_eur: int, rooms: float, move_in: str, desc: str) -> Tuple[bool, str]:
    title = (title or "").strip()
    district = (district or "").strip()[:80]
    desc = (desc or "").strip()[:4000]
    rent_eur = _safe_int(rent_eur, 0)
    try:
        rooms = float(rooms)
    except Exception:
        rooms = 0.0
    move_in = (move_in or "").strip()[:20]

    if len(title) < 6:
        return False, "Title must be at least 6 characters."
    if rent_eur <= 0:
        return False, "Rent must be a positive number."
    if rooms <= 0:
        return False, "Rooms must be > 0."

    with conn() as c:
        c.execute("""
            INSERT INTO listings (created_at, user_id, title, district, rent_eur, rooms, move_in, description, is_active)
            VALUES (?,?,?,?,?,?,?,?,1)
        """, (now_iso(), user_id, title[:140], district, rent_eur, rooms, move_in, desc))
        c.commit()
    return True, "Listing published."


def list_listings(active_only: bool = True, q: str = "", district: str = "", max_rent: int = 0) -> List[Dict[str, Any]]:
    q = (q or "").strip().lower()
    district = (district or "").strip()

    sql = """
      SELECT l.*, p.username, COALESCE(p.display_name,'') AS display_name
      FROM listings l
      JOIN profiles p ON p.user_id = l.user_id
      WHERE 1=1
    """
    args: List[Any] = []

    if active_only:
        sql += " AND l.is_active=1 "

    if q:
        sql += " AND (LOWER(l.title) LIKE ? OR LOWER(l.description) LIKE ?) "
        args += [f"%{q}%", f"%{q}%"]

    if district:
        sql += " AND l.district=? "
        args += [district]

    if max_rent and max_rent > 0:
        sql += " AND l.rent_eur <= ? "
        args += [int(max_rent)]

    sql += " ORDER BY l.created_at DESC LIMIT 80"

    with conn() as c:
        rows = c.execute(sql, tuple(args)).fetchall()
    return [dict(r) for r in rows]


def toggle_save_listing(user_id: int, listing_id: int) -> bool:
    with conn() as c:
        row = c.execute(
            "SELECT 1 FROM saved_listings WHERE user_id=? AND listing_id=?",
            (user_id, listing_id),
        ).fetchone()
        if row:
            c.execute("DELETE FROM saved_listings WHERE user_id=? AND listing_id=?", (user_id, listing_id))
            c.commit()
            return False
        else:
            c.execute("INSERT INTO saved_listings (user_id, listing_id, created_at) VALUES (?,?,?)",
                      (user_id, listing_id, now_iso()))
            c.commit()
            return True


def is_saved(user_id: int, listing_id: int) -> bool:
    with conn() as c:
        row = c.execute(
            "SELECT 1 FROM saved_listings WHERE user_id=? AND listing_id=?",
            (user_id, listing_id),
        ).fetchone()
    return bool(row)


def my_saved_listings(user_id: int) -> List[Dict[str, Any]]:
    with conn() as c:
        rows = c.execute("""
          SELECT l.*, p.username
          FROM saved_listings s
          JOIN listings l ON l.id=s.listing_id
          JOIN profiles p ON p.user_id=l.user_id
          WHERE s.user_id=?
          ORDER BY s.created_at DESC
        """, (user_id,)).fetchall()
    return [dict(r) for r in rows]


# =============================
# MESSAGES (DEMO)
# =============================
def send_message(sender_id: int, receiver_id: int, body: str) -> Tuple[bool, str]:
    body = (body or "").strip()
    if len(body) < 1:
        return False, "Message is empty."
    if len(body) > 2000:
        return False, "Message too long."
    with conn() as c:
        c.execute(
            "INSERT INTO messages (created_at, sender_id, receiver_id, body) VALUES (?,?,?,?)",
            (now_iso(), sender_id, receiver_id, body),
        )
        c.commit()
    return True, "Sent."


def inbox_for(user_id: int) -> List[Dict[str, Any]]:
    with conn() as c:
        rows = c.execute("""
          SELECT m.*, ps.username AS sender_username, pr.username AS receiver_username
          FROM messages m
          JOIN profiles ps ON ps.user_id=m.sender_id
          JOIN profiles pr ON pr.user_id=m.receiver_id
          WHERE m.sender_id=? OR m.receiver_id=?
          ORDER BY m.created_at DESC
          LIMIT 100
        """, (user_id, user_id)).fetchall()
    return [dict(r) for r in rows]


# =============================
# ROUTES: AUTH
# =============================
def page_login():
    auth_shell_open("Find rentals in Berlin • message fast • build your profile")
    st.markdown("<div class='rb-auth-card'>", unsafe_allow_html=True)
    st.markdown("<div class='rb-auth-h1'>Sign in</div>", unsafe_allow_html=True)
    st.markdown("<div class='rb-auth-sub'>Email & password, or one-tap Google.</div>", unsafe_allow_html=True)
    st.write("")

    google_oauth_handle_callback_if_present()

    render_google_oauth_button()
    st.write("")
    render_apple_button_ui()
    st.markdown("<div class='rb-divider'>OR</div>", unsafe_allow_html=True)

    with st.form("login_form"):
        email = st.text_input("Email", placeholder="name@email.com")
        password = st.text_input("Password", type="password", placeholder="Minimum 8 characters")
        submitted = st.form_submit_button("Sign in", type="primary", use_container_width=True)

    st.markdown("<div class='rb-row-between'>", unsafe_allow_html=True)
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
            if is_rate_limited(email):
                st.error("Too many attempts. Wait a minute and try again.")
            else:
                st.error("Wrong email or password.")
        else:
            token = create_session(uid)
            st.session_state["user_id"] = uid
            st.session_state["session_token"] = token
            set_query_token(token)  # keep your URL-token persistence
            st.session_state["route"] = "app"
            st.rerun()

    st.markdown("<div class='rb-foot'>Tip: Use a strong password. Enable Google login for speed.</div>", unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)
    auth_shell_close()


def page_signup():
    auth_shell_open("Create an account • build trust • post & message")
    st.markdown("<div class='rb-auth-card'>", unsafe_allow_html=True)
    st.markdown("<div class='rb-auth-h1'>Create account</div>", unsafe_allow_html=True)
    st.markdown("<div class='rb-auth-sub'>Fast signup. Beautiful app shell included.</div>", unsafe_allow_html=True)
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
    # 2 modes: request reset link OR use reset link
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
                st.success("If the email exists, a reset link can be generated.")
                st.info(msg)  # demo display (send via email in production)
            else:
                st.error(msg)

    if st.button("Back to Sign in", use_container_width=True):
        clear_query_params()
        st.session_state["route"] = "login"
        st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)
    auth_shell_close()


# =============================
# APP SHELL
# =============================
def topbar(user: Dict[str, Any]):
    logo = asset_path("logo.png")

    st.markdown("<div class='rb-topbar'><div class='rb-topbar-inner'>", unsafe_allow_html=True)

    if logo:
        b64 = read_file_b64(logo)
        st.markdown(
            f"""
            <div class="rb-brand">
              <div class="rb-brand-badge"><img src="data:image/png;base64,{b64}"/></div>
              <div>{APP_NAME}</div>
              <span class="rb-pill">AI Rentals</span>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            f"""
            <div class="rb-brand">
              <div class="rb-brand-badge">🏠</div>
              <div>{APP_NAME}</div>
              <span class="rb-pill">AI Rentals</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # nav + actions
    st.markdown("<div class='rb-nav'>", unsafe_allow_html=True)

    nav = st.session_state.get("nav", "Dashboard")

    def nav_btn(label: str):
        is_active = (nav == label)
        if st.button(("• " if is_active else "") + label, key=f"nav_{label}"):
            st.session_state["nav"] = label
            st.rerun()

    nav_btn("Dashboard")
    nav_btn("Listings")
    nav_btn("Messages")
    nav_btn("Saved")
    nav_btn("Profile")
    nav_btn("Settings")

    # theme toggle
    mode = st.session_state.get("theme_mode", "dark")
    if st.button("🌙 Dark" if mode == "dark" else "☀️ Light", key="toggle_theme"):
        st.session_state["theme_mode"] = "light" if mode == "dark" else "dark"
        st.rerun()

    if st.button("Logout", key="logout_btn"):
        logout()
        st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)
    st.markdown("</div></div>", unsafe_allow_html=True)


def page_dashboard(user: Dict[str, Any]):
    st.markdown("<div class='rb-card'>", unsafe_allow_html=True)
    st.markdown("<div class='rb-h1'>Welcome 👋</div>", unsafe_allow_html=True)
    st.markdown(
        f"<div class='rb-muted'>Signed in as <b>{user.get('email','')}</b> • Provider: <b>{user.get('provider','local')}</b></div>",
        unsafe_allow_html=True,
    )
    st.write("")

    # metrics
    with conn() as c:
        n_listings = int(c.execute("SELECT COUNT(*) AS n FROM listings WHERE is_active=1").fetchone()["n"])
        n_users = int(c.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"])
        n_saved = int(c.execute("SELECT COUNT(*) AS n FROM saved_listings WHERE user_id=?", (user["id"],)).fetchone()["n"])

    cols = st.columns(3)
    cols[0].metric("Active Listings", n_listings)
    cols[1].metric("Users (local DB)", n_users)
    cols[2].metric("Saved", n_saved)

    st.write("")
    st.info("This is a complete system shell: listings, saved, messages, profile, settings. Next add: verification email, moderation, payments, advanced search.")
    st.markdown("</div>", unsafe_allow_html=True)

    st.write("")
    st.markdown("<div class='rb-card'>", unsafe_allow_html=True)
    st.write("### Suggested Listings")
    recs = list_listings(active_only=True, q="", district="", max_rent=0)[:4]
    if not recs:
        st.write("No listings yet.")
    else:
        for r in recs:
            render_listing_card(user["id"], r, show_actions=True)
            st.write("")
    st.markdown("</div>", unsafe_allow_html=True)


def render_listing_card(viewer_id: int, r: Dict[str, Any], show_actions: bool = True):
    title = r.get("title", "")
    district = r.get("district", "")
    rent = r.get("rent_eur", 0)
    rooms = r.get("rooms", 0)
    move_in = r.get("move_in", "") or "Flexible"
    owner = r.get("display_name") or r.get("username") or "owner"
    desc = (r.get("description") or "").strip()
    if len(desc) > 220:
        desc = desc[:220].rstrip() + "…"

    saved = is_saved(viewer_id, int(r["id"]))

    st.markdown("<div class='rb-listing'>", unsafe_allow_html=True)
    st.markdown(f"<h4>{title}</h4>", unsafe_allow_html=True)
    st.markdown(
        f"<div class='rb-kv'>"
        f"<span>📍 {district or 'Berlin'}</span>"
        f"<span>💶 {rent} €</span>"
        f"<span>🛏️ {rooms:g} rooms</span>"
        f"<span>🗓️ {move_in}</span>"
        f"<span>👤 {owner}</span>"
        f"</div>",
        unsafe_allow_html=True,
    )
    if desc:
        st.markdown(f"<div class='rb-muted' style='margin-top:10px;'>{desc}</div>", unsafe_allow_html=True)

    if show_actions:
        c1, c2, c3 = st.columns([1, 1, 2])
        with c1:
            if st.button("💾 Saved" if saved else "🤍 Save", key=f"save_{r['id']}", use_container_width=True):
                toggle_save_listing(viewer_id, int(r["id"]))
                st.rerun()
        with c2:
            if st.button("💬 Message", key=f"msg_{r['id']}", use_container_width=True):
                st.session_state["nav"] = "Messages"
                st.session_state["msg_prefill_receiver"] = int(r["user_id"])
                st.session_state["msg_prefill_context"] = f"Regarding: {title}"
                st.rerun()
        with c3:
            st.caption("Tip: Add verification + trust signals to reduce spam.")
    st.markdown("</div>", unsafe_allow_html=True)


def page_listings(user: Dict[str, Any]):
    left, right = st.columns([1.1, 0.9])

    with left:
        st.markdown("<div class='rb-card'>", unsafe_allow_html=True)
        st.write("### Search Listings")
        q = st.text_input("Search", placeholder="Try: altbau, furnished, balcony…", key="listings_q")
        districts = ["", "Mitte", "Neukölln", "Friedrichshain", "Prenzlauer Berg", "Kreuzberg", "Charlottenburg", "Wedding", "Moabit"]
        district = st.selectbox("District", districts, index=0, key="listings_district")
        max_rent = st.number_input("Max rent (€)", min_value=0, max_value=10000, value=0, step=50, key="listings_maxrent")
        st.markdown("</div>", unsafe_allow_html=True)

        st.write("")
        st.markdown("<div class='rb-card'>", unsafe_allow_html=True)
        st.write("### Results")
        rows = list_listings(active_only=True, q=q, district=district, max_rent=int(max_rent))
        if not rows:
            st.write("No matches. Try different filters.")
        else:
            for r in rows:
                render_listing_card(user["id"], r, show_actions=True)
                st.write("")
        st.markdown("</div>", unsafe_allow_html=True)

    with right:
        st.markdown("<div class='rb-card'>", unsafe_allow_html=True)
        st.write("### Publish a Listing")
        st.caption("Post a rental or room. This is a lightweight CRUD: publish now, expand later.")

        with st.form("create_listing_form"):
            title = st.text_input("Title", placeholder="e.g., Bright 2-room Altbau near Tempelhofer Feld")
            district2 = st.text_input("District", placeholder="e.g., Neukölln")
            rent = st.number_input("Rent (€ / month)", min_value=0, max_value=20000, value=1200, step=50)
            rooms = st.number_input("Rooms", min_value=0.0, max_value=10.0, value=2.0, step=0.5)
            move_in = st.text_input("Move-in date", placeholder="YYYY-MM-DD or Flexible")
            desc = st.text_area("Description", placeholder="Short, clear description. Add requirements and viewing times.")
            submitted = st.form_submit_button("Publish", type="primary", use_container_width=True)

        if submitted:
            ok, msg = create_listing(user["id"], title, district2, int(rent), float(rooms), move_in, desc)
            if ok:
                st.success(msg)
                st.session_state["listings_q"] = ""
                st.rerun()
            else:
                st.error(msg)

        st.markdown("</div>", unsafe_allow_html=True)


def page_saved(user: Dict[str, Any]):
    st.markdown("<div class='rb-card'>", unsafe_allow_html=True)
    st.write("### Saved")
    rows = my_saved_listings(user["id"])
    if not rows:
        st.write("No saved listings yet. Save from the Listings page.")
    else:
        for r in rows:
            render_listing_card(user["id"], r, show_actions=True)
            st.write("")
    st.markdown("</div>", unsafe_allow_html=True)


def page_messages(user: Dict[str, Any]):
    st.markdown("<div class='rb-card'>", unsafe_allow_html=True)
    st.write("### Messages (demo)")
    st.caption("Lightweight messaging layer (DB). Upgrade later with threads, read receipts, moderation.")

    # prefill from listing
    prefill_receiver = st.session_state.pop("msg_prefill_receiver", None)
    prefill_context = st.session_state.pop("msg_prefill_context", "")

    with st.expander("Send a message", expanded=True):
        email = st.text_input("To (email)", placeholder="owner@email.com", key="msg_to_email")
        if prefill_receiver:
            # best effort to fill receiver email
            with conn() as c:
                row = c.execute("SELECT email FROM users WHERE id=?", (prefill_receiver,)).fetchone()
            if row and not email:
                st.session_state["msg_to_email"] = row["email"]
                email = row["email"]

        body_default = f"{prefill_context}\n\nHi! Is this still available?" if prefill_context else ""
        body = st.text_area("Message", value=body_default, height=120, key="msg_body")

        if st.button("Send", type="primary", use_container_width=True):
            receiver_id = find_user_by_email(email)
            if not receiver_id:
                st.error("User not found (email).")
            else:
                ok, msg = send_message(user["id"], receiver_id, body)
                if ok:
                    st.success(msg)
                    st.session_state["msg_body"] = ""
                    st.rerun()
                else:
                    st.error(msg)

    st.write("")
    st.write("### Inbox")
    msgs = inbox_for(user["id"])
    if not msgs:
        st.write("No messages yet.")
    else:
        for m in msgs:
            direction = "➡️ Sent to" if int(m["sender_id"]) == int(user["id"]) else "⬅️ From"
            other = m["receiver_username"] if direction.startswith("➡️") else m["sender_username"]
            st.markdown(
                f"""
                <div class="rb-listing">
                  <div style="display:flex; justify-content:space-between; gap:10px; align-items:center;">
                    <div><b>{direction} {other}</b></div>
                    <div class="rb-muted">{m["created_at"]}</div>
                  </div>
                  <div class="rb-muted" style="margin-top:10px; white-space:pre-wrap;">{(m["body"] or "").strip()}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            st.write("")

    st.markdown("</div>", unsafe_allow_html=True)


def page_profile(user: Dict[str, Any]):
    st.markdown("<div class='rb-card'>", unsafe_allow_html=True)
    st.write("### Profile")
    st.caption("These fields are used to build trust (real estate is trust-heavy).")

    with st.form("profile_form"):
        display_name = st.text_input("Display name", value=user.get("display_name", ""), placeholder="e.g., Alex M.")
        bio = st.text_area("Bio", value=user.get("bio", ""), placeholder="Short intro: who you are, what you're looking for.")
        submitted = st.form_submit_button("Save", type="primary", use_container_width=True)

    if submitted:
        with conn() as c:
            c.execute(
                "UPDATE profiles SET display_name=?, bio=?, updated_at=? WHERE user_id=?",
                (display_name.strip()[:80], bio.strip()[:1200], now_iso(), user["id"]),
            )
            c.commit()
        st.success("Profile updated.")
        st.rerun()

    st.write("")
    st.write("### Account")
    st.write("**Email:**", user.get("email", ""))
    st.write("**Username:**", user.get("username", ""))
    st.write("**Provider:**", user.get("provider", "local"))
    st.write("**Verified:**", "✅" if int(user.get("is_verified", 0)) == 1 else "— (add email verification next)")
    st.markdown("</div>", unsafe_allow_html=True)


def page_settings(user: Dict[str, Any]):
    st.markdown("<div class='rb-card'>", unsafe_allow_html=True)
    st.write("### Settings")
    st.caption("Security + control. Expand: 2FA, email verification, active sessions, device management.")

    st.write("#### Active Sessions")
    with conn() as c:
        rows = c.execute("""
          SELECT token, created_at, last_seen, expires_at
          FROM sessions
          WHERE user_id=?
          ORDER BY last_seen DESC
          LIMIT 20
        """, (user["id"],)).fetchall()
    if not rows:
        st.write("No sessions found.")
    else:
        for r in rows:
            is_current = (r["token"] == st.session_state.get("session_token", ""))
            st.markdown(
                f"""
                <div class="rb-listing">
                  <div style="display:flex; justify-content:space-between; gap:10px;">
                    <div><b>{'🟢 Current' if is_current else '⚪ Session'}</b> <span class="rb-muted">token…{r["token"][-10:]}</span></div>
                    <div class="rb-muted">expires {r["expires_at"]}</div>
                  </div>
                  <div class="rb-muted" style="margin-top:8px;">created {r["created_at"]} • last seen {r["last_seen"]}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            st.write("")

    st.write("#### Danger Zone")
    c1, c2 = st.columns(2)
    with c1:
        if st.button("Logout all sessions", use_container_width=True):
            with conn() as c:
                c.execute("DELETE FROM sessions WHERE user_id=?", (user["id"],))
                c.commit()
            st.success("All sessions cleared. Please sign in again.")
            logout()
            st.rerun()

    with c2:
        st.caption("URL token mode is enabled. Clearing sessions also invalidates old shared links.")
    st.markdown("</div>", unsafe_allow_html=True)


# =============================
# ROUTER / BOOT
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


def page_app():
    user = get_user(st.session_state["user_id"])
    topbar(user)

    st.write("")
    nav = st.session_state.get("nav", "Dashboard")

    if nav == "Dashboard":
        page_dashboard(user)
    elif nav == "Listings":
        page_listings(user)
    elif nav == "Messages":
        page_messages(user)
    elif nav == "Saved":
        page_saved(user)
    elif nav == "Profile":
        page_profile(user)
    elif nav == "Settings":
        page_settings(user)
    else:
        st.session_state["nav"] = "Dashboard"
        st.rerun()


def main():
    init_db()
    cleanup_expired()
    seed_demo_data_if_needed()

    if "theme_mode" not in st.session_state:
        st.session_state["theme_mode"] = "dark"
    inject_global_css()

    # Handle reset-link route by query params (works even if route says login)
    if _query_param_value("reset") == "1":
        st.session_state["route"] = "reset"

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
