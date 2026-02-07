# main.py
# Run: streamlit run main.py
# RentinBerlin — ONE-FILE Streamlit app (Website-like URL routing + Mobile-first auth + SQLite)

import os
import re
import time
import uuid
import sqlite3
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from urllib.parse import urlencode

import streamlit as st

# =============================
# CONFIG
# =============================
APP_NAME = "RentinBerlin"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "berlinrent_social.db")
ASSETS_DIR = os.path.join(BASE_DIR, "assets")
os.makedirs(ASSETS_DIR, exist_ok=True)

SESSION_DAYS = 30
REGISTRATION_ENABLED = True

# Berlin timezone
try:
    from zoneinfo import ZoneInfo
    BERLIN_TZ = ZoneInfo("Europe/Berlin")
except Exception:
    BERLIN_TZ = None

# favicon
favicon = "🏠"
try:
    from PIL import Image
    fav_path = os.path.join(ASSETS_DIR, "logo.png")
    if os.path.exists(fav_path):
        favicon = Image.open(fav_path)
except Exception:
    pass

st.set_page_config(page_title=APP_NAME, page_icon=favicon, layout="wide")


# =============================
# TIME / UTIL
# =============================
def now_berlin_dt() -> datetime:
    return datetime.now(BERLIN_TZ) if BERLIN_TZ else datetime.now()


def now_iso() -> str:
    return now_berlin_dt().replace(microsecond=0).isoformat()


def sha256(s: str) -> str:
    return hashlib.sha256((s or "").encode("utf-8")).hexdigest()


def normalize_email(e: str) -> str:
    return (e or "").strip().lower()


def normalize_phone(p: str) -> str:
    p = (p or "").strip()
    p = re.sub(r"[^\d+]", "", p)
    return p[:25]


def asset_path(name: str) -> str:
    p = os.path.join(ASSETS_DIR, name)
    return p if os.path.exists(p) else ""


# =============================
# QUERY PARAMS = WEBSITE ROUTING
# =============================
def qp_get(key: str, default: str = "") -> str:
    try:
        v = st.query_params.get(key)
        if isinstance(v, list):
            return v[0] if v else default
        return v if v is not None else default
    except Exception:
        try:
            qp = st.experimental_get_query_params()
            return (qp.get(key, [default])[0]) if qp else default
        except Exception:
            return default


def qp_set(**kwargs):
    clean = {k: v for k, v in kwargs.items() if v is not None and str(v) != ""}
    try:
        st.query_params.clear()
        for k, v in clean.items():
            st.query_params[k] = v
    except Exception:
        try:
            st.experimental_set_query_params(**clean)
        except Exception:
            pass


def build_url(**kwargs) -> str:
    clean = {k: v for k, v in kwargs.items() if v is not None and str(v) != ""}
    qs = urlencode(clean, doseq=False)
    return f"?{qs}" if qs else ""


def nav_to(route: str, page: str = "", token: str = ""):
    t = token or st.session_state.get("session_token", "") or qp_get("t", "")
    if route in ["login", "register", "reset"]:
        qp_set(t=t, r=route)
        st.session_state["route"] = route
        st.session_state["page"] = ""
    else:
        qp_set(t=t, r="app", p=page or "Feed")
        st.session_state["route"] = "app"
        st.session_state["page"] = page or "Feed"
    st.rerun()


# =============================
# DB
# =============================
def conn():
    c = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL;")
    c.execute("PRAGMA synchronous=NORMAL;")
    c.execute("PRAGMA busy_timeout=8000;")
    return c


def with_retry(fn, tries: int = 12, base_sleep: float = 0.12):
    last = None
    for i in range(tries):
        try:
            return fn()
        except sqlite3.OperationalError as e:
            last = e
            msg = str(e).lower()
            if "locked" in msg or "busy" in msg:
                time.sleep(base_sleep * (i + 1))
                continue
            raise
    raise last


def init_db():
    if st.session_state.get("_db_inited"):
        return

    def _init():
        c = conn()
        cur = c.cursor()
        cur.execute("BEGIN IMMEDIATE;")

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
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS profiles (
            user_id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            display_name TEXT,
            bio TEXT,
            updated_at TEXT NOT NULL
        )
        """)

        cur.execute("COMMIT;")
        c.close()

    with_retry(_init)
    st.session_state["_db_inited"] = True


# =============================
# AUTH
# =============================
def ensure_profile_for_user(user_id: int, email: str):
    base = (email.split("@")[0] if "@" in email else "user").lower()
    base = re.sub(r"[^a-z0-9._]", "", base)[:30] or "user"

    def _do():
        c = conn()
        cur = c.cursor()
        cur.execute("BEGIN IMMEDIATE;")
        row = cur.execute("SELECT user_id FROM profiles WHERE user_id=?", (user_id,)).fetchone()
        if row:
            cur.execute("COMMIT;")
            c.close()
            return

        suffix = 0
        while True:
            u = base if suffix == 0 else f"{base}{suffix}"
            try:
                cur.execute("""
                    INSERT INTO profiles (user_id, username, display_name, bio, updated_at)
                    VALUES (?,?,?,?,?)
                """, (user_id, u, "", "", now_iso()))
                break
            except sqlite3.IntegrityError:
                suffix += 1
                if suffix > 9999:
                    break

        cur.execute("COMMIT;")
        c.close()

    with_retry(_do)


def create_user(email: str, phone: str, password: str) -> (bool, str):
    email = normalize_email(email)
    phone = normalize_phone(phone)
    password = (password or "").strip()

    if not email or "@" not in email:
        return False, "Enter a valid email."
    if len(password) < 6:
        return False, "Password must be at least 6 characters."

    def _do():
        c = conn()
        cur = c.cursor()
        cur.execute("BEGIN IMMEDIATE;")
        try:
            cur.execute(
                "INSERT INTO users (created_at, email, phone, password_hash) VALUES (?,?,?,?)",
                (now_iso(), email, phone, sha256(password)),
            )
        except sqlite3.IntegrityError:
            cur.execute("ROLLBACK;")
            c.close()
            return False, "Email already exists."
        uid = cur.lastrowid
        cur.execute("COMMIT;")
        c.close()
        ensure_profile_for_user(uid, email)
        return True, "Account created."

    return with_retry(_do)


def authenticate(email: str, password: str) -> Optional[int]:
    email = normalize_email(email)
    password = (password or "").strip()

    def _do():
        c = conn()
        row = c.execute("SELECT id, email, password_hash FROM users WHERE email=?", (email,)).fetchone()
        c.close()
        return dict(row) if row else None

    u = with_retry(_do)
    if not u:
        return None
    if u["password_hash"] != sha256(password):
        return None

    uid = int(u["id"])
    ensure_profile_for_user(uid, u["email"])
    return uid


def reset_password(email: str, new_password: str) -> (bool, str):
    email = normalize_email(email)
    new_password = (new_password or "").strip()

    if not email or "@" not in email:
        return False, "Enter a valid email."
    if len(new_password) < 6:
        return False, "New password must be at least 6 characters."

    def _do():
        c = conn()
        cur = c.cursor()
        cur.execute("BEGIN IMMEDIATE;")
        cur.execute("UPDATE users SET password_hash=? WHERE email=?", (sha256(new_password), email))
        changed = cur.rowcount
        cur.execute("COMMIT;")
        c.close()
        return changed

    changed = with_retry(_do)
    return (True, "Password reset.") if changed else (False, "Email not found.")


# =============================
# SESSIONS
# =============================
def create_session(user_id: int) -> str:
    token = uuid.uuid4().hex + uuid.uuid4().hex
    expires = (now_berlin_dt() + timedelta(days=SESSION_DAYS)).replace(microsecond=0).isoformat()

    def _do():
        c = conn()
        cur = c.cursor()
        cur.execute("BEGIN IMMEDIATE;")
        cur.execute("""
            INSERT INTO sessions (token, user_id, created_at, last_seen, expires_at)
            VALUES (?,?,?,?,?)
        """, (token, user_id, now_iso(), now_iso(), expires))
        cur.execute("COMMIT;")
        c.close()

    with_retry(_do)
    return token


def load_session_from_token(token: str) -> Optional[int]:
    token = (token or "").strip()
    if not token:
        return None

    def _do():
        c = conn()
        row = c.execute("SELECT user_id, expires_at FROM sessions WHERE token=?", (token,)).fetchone()
        c.close()
        return dict(row) if row else None

    r = with_retry(_do)
    if not r:
        return None

    try:
        exp = datetime.fromisoformat(r["expires_at"])
    except Exception:
        return None

    # exp may be naive; compare naive with naive or aware with aware
    now = now_berlin_dt().replace(microsecond=0)
    if exp.tzinfo is None and now.tzinfo is not None:
        now = now.replace(tzinfo=None)

    if exp < now:
        return None

    def _touch():
        c = conn()
        cur = c.cursor()
        cur.execute("BEGIN IMMEDIATE;")
        cur.execute("UPDATE sessions SET last_seen=? WHERE token=?", (now_iso(), token))
        cur.execute("COMMIT;")
        c.close()

    with_retry(_touch)
    return int(r["user_id"])


def delete_session(token: str):
    token = (token or "").strip()
    if not token:
        return

    def _do():
        c = conn()
        cur = c.cursor()
        cur.execute("BEGIN IMMEDIATE;")
        cur.execute("DELETE FROM sessions WHERE token=?", (token,))
        cur.execute("COMMIT;")
        c.close()

    with_retry(_do)


def logout():
    tok = st.session_state.get("session_token") or qp_get("t", "")
    if tok:
        delete_session(tok)
    for k in list(st.session_state.keys()):
        if k not in ["_db_inited"]:
            st.session_state.pop(k, None)
    qp_set(r="login")
    st.rerun()


def get_profile(uid: int) -> Dict[str, Any]:
    def _do():
        c = conn()
        row = c.execute("""
            SELECT u.id, u.email, u.phone,
                   COALESCE(p.username,'') AS username,
                   COALESCE(p.display_name,'') AS display_name,
                   COALESCE(p.bio,'') AS bio
            FROM users u
            LEFT JOIN profiles p ON p.user_id=u.id
            WHERE u.id=?
        """, (uid,)).fetchone()
        c.close()
        return dict(row) if row else {}

    return with_retry(_do)


# =============================
# UI STYLE (MOBILE-FIRST)
# =============================
def inject_style():
    st.markdown("""
    <style>
      #MainMenu {visibility:hidden;}
      footer {visibility:hidden;}
      header {visibility:hidden;}

      .stApp { background: #f6f8fb; }
      section.main > div.block-container{
        max-width: 1180px;
        padding-top: 0.7rem;
        padding-bottom: 4.5rem;
      }
      @media (max-width: 768px){
        section.main > div.block-container{
          padding-left: 0.9rem;
          padding-right: 0.9rem;
        }
      }

      /* NAV LINKS */
      .rb-navwrap{
        background:#fff;
        border:1px solid #eef2f7;
        border-radius:18px;
        box-shadow: 0 18px 45px rgba(16,24,40,0.06);
        padding: 10px 14px;
      }
      .rb-navrow{ display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap; }
      .rb-logo{ display:flex; align-items:center; gap:10px; font-weight:950; font-size:18px; color:#0f172a; }
      .rb-navlinks{ display:flex; gap:10px; align-items:center; flex-wrap:wrap; justify-content:flex-end; }
      .rb-navlinks a{
        text-decoration:none !important;
        border-radius:14px;
        border:1px solid rgba(226,232,240,1);
        background:#fff;
        color:#0f172a;
        padding:10px 14px;
        font-weight:900;
        display:inline-flex;
        align-items:center;
        gap:8px;
      }
      .rb-navlinks a:hover{ border-color: rgba(203,213,225,1); background:#fbfdff; }
      .rb-navlinks a.rb-active{
        background:#ff7a1a;
        border-color:#ff7a1a;
        color:#fff;
        box-shadow: 0 10px 30px rgba(255, 122, 26, 0.20);
      }

      /* AUTH: full bg + centered card */
      .rb-auth-bg{
        position: fixed; inset: 0; z-index: 0; pointer-events:none;
        background:
          radial-gradient(900px 520px at 15% 20%, rgba(0, 229, 255, 0.16), transparent 60%),
          radial-gradient(800px 480px at 85% 18%, rgba(255, 122, 26, 0.18), transparent 62%),
          radial-gradient(900px 720px at 55% 90%, rgba(168, 85, 247, 0.16), transparent 64%),
          linear-gradient(135deg, #05060b 0%, #070a14 45%, #04040a 100%);
      }
      section.main{ position: relative; z-index: 2; }

      .rb-auth-shell{
        max-width: 440px;
        margin: 0 auto;
        padding-top: 6vh;
        padding-bottom: 6vh;
      }
      @media (max-width: 480px){
        .rb-auth-shell{ max-width: 100%; padding-top: 3vh; }
      }

      .rb-auth-card{
        background: rgba(255,255,255,0.06);
        border: 1px solid rgba(255,255,255,0.14);
        border-radius: 22px;
        backdrop-filter: blur(14px);
        -webkit-backdrop-filter: blur(14px);
        box-shadow: 0 30px 90px rgba(0,0,0,0.40);
        padding: 18px 16px 14px 16px;
      }

      .rb-auth-top{
        display:flex; flex-direction:column; align-items:center; text-align:center; gap:10px;
        margin-bottom: 10px;
      }
      .rb-auth-logoimg{ width:64px; height:64px; object-fit:contain; border-radius:18px; }
      .rb-auth-title{ font-weight: 950; font-size: 30px; color: rgba(255,255,255,0.95); margin: 0; }
      .rb-auth-sub{ color: rgba(255,255,255,0.75); font-size: 14px; margin-top: 4px; }

      /* Inputs on dark */
      .rb-auth-card .stTextInput input{
        height: 46px !important;
        border-radius: 14px !important;
        border: 1px solid rgba(255,255,255,0.16) !important;
        background: rgba(255,255,255,0.08) !important;
        color: rgba(255,255,255,0.92) !important;
      }
      .rb-auth-card label{ color: rgba(255,255,255,0.86) !important; font-weight: 900 !important; }

      /* Buttons */
      .stButton>button{
        border-radius: 14px !important;
        border: 1px solid rgba(226,232,240,1) !important;
        background: #ffffff !important;
        color: #0f172a !important;
        padding: 0.60rem 0.95rem !important;
        font-weight: 900 !important;
      }
      .stButton>button[kind="primary"]{
        background: #ff7a1a !important;
        border-color: #ff7a1a !important;
        color: white !important;
        box-shadow: 0 10px 30px rgba(255, 122, 26, 0.20) !important;
      }

      /* Remove “white line” around images */
      img{ outline:none !important; border:none !important; }
    </style>
    """, unsafe_allow_html=True)


def render_brand_logo(size: int = 56):
    logo = asset_path("logo.png")
    if logo:
        st.image(logo, width=size)
    else:
        st.markdown(f"<div style='font-size:{size-10}px; line-height:1;'>🏠</div>", unsafe_allow_html=True)


def render_navbar(current_page: str, uid: int):
    token = st.session_state.get("session_token") or qp_get("t", "")
    def link(label: str, page: str):
        href = build_url(t=token, r="app", p=page)
        active = "rb-active" if current_page == page else ""
        return f"<a class='{active}' href='{href}'>{label}</a>"

    st.markdown("<div class='rb-navwrap'><div class='rb-navrow'>", unsafe_allow_html=True)

    # left: logo + name
    left = st.container()
    with left:
        cols = st.columns([0.22, 1.78], vertical_alignment="center")
        with cols[0]:
            logo = asset_path("logo.png")
            if logo:
                st.image(logo, width=40)
            else:
                st.write("🏠")
        with cols[1]:
            st.markdown("<div class='rb-logo'>RentinBerlin</div>", unsafe_allow_html=True)

    # right: links
    st.markdown(
        "<div class='rb-navlinks'>"
        + link("Home", "Feed")
        + link("Profile", "Profile")
        + link("Logout", "Logout")
        + "</div>",
        unsafe_allow_html=True
    )
    st.markdown("</div></div>", unsafe_allow_html=True)


# =============================
# PAGES (AUTH)
# =============================
def auth_shell_start():
    st.markdown("<div class='rb-auth-bg'></div>", unsafe_allow_html=True)
    st.markdown("<div class='rb-auth-shell'>", unsafe_allow_html=True)
    st.markdown("<div class='rb-auth-card'>", unsafe_allow_html=True)


def auth_shell_end():
    st.markdown("</div></div>", unsafe_allow_html=True)


def page_login():
    auth_shell_start()

    logo = asset_path("logo.png")
    if logo:
        st.markdown(f"""
        <div class="rb-auth-top">
          <img class="rb-auth-logoimg" src="app/static/{os.path.basename(logo)}" />
        </div>
        """, unsafe_allow_html=True)

    # Safe logo render (works everywhere)
    st.markdown("<div class='rb-auth-top'>", unsafe_allow_html=True)
    render_brand_logo(64)
    st.markdown(f"<h1 class='rb-auth-title'>Sign in</h1>", unsafe_allow_html=True)
    st.markdown("<div class='rb-auth-sub'>Welcome back to RentinBerlin</div>", unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

    with st.form("login_form", clear_on_submit=False):
        email = st.text_input("Email", placeholder="name@email.com")
        password = st.text_input("Password", type="password", placeholder="••••••••")
        submitted = st.form_submit_button("Login", type="primary", use_container_width=True)

    row = st.columns(2)
    if row[0].button("Create account", use_container_width=True, disabled=(not REGISTRATION_ENABLED)):
        nav_to("register")
    if row[1].button("Reset password", use_container_width=True):
        nav_to("reset")

    st.caption("Password must be at least 6 characters.")

    if submitted:
        uid = authenticate(email, password)
        if not uid:
            st.error("Wrong email or password.")
        else:
            token = create_session(uid)
            st.session_state["user_id"] = uid
            st.session_state["session_token"] = token
            nav_to("app", page="Feed", token=token)

    auth_shell_end()


def page_register():
    auth_shell_start()

    st.markdown("<div class='rb-auth-top'>", unsafe_allow_html=True)
    render_brand_logo(64)
    st.markdown(f"<h1 class='rb-auth-title'>Create account</h1>", unsafe_allow_html=True)
    st.markdown("<div class='rb-auth-sub'>Start posting and messaging in Berlin</div>", unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

    with st.form("register_form", clear_on_submit=False):
        email = st.text_input("Email", placeholder="name@email.com")
        phone = st.text_input("Phone (optional)", placeholder="+49 …")
        password = st.text_input("Password", type="password", placeholder="min 6 characters")
        submitted = st.form_submit_button("Create account", type="primary", use_container_width=True)

    st.cafrom typing import Optional, Dict, Any, List, Tuple
from urllib.parse import quote_plus

import streamlit as st
import streamlit.components.v1 as components

# Pillow recommended
PIL_OK = True
try:
    from PIL import Image
except Exception:
    PIL_OK = False

# Berlin timezone
try:
    from zoneinfo import ZoneInfo
    BERLIN_TZ = ZoneInfo("Europe/Berlin")
except Exception:
    BERLIN_TZ = None


# =============================
# CONFIG
# =============================
APP_NAME = "RentinBerlin"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "berlinrent_social.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
ASSETS_DIR = os.path.join(BASE_DIR, "assets")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(ASSETS_DIR, exist_ok=True)

SESSION_DAYS = 30
REGISTRATION_ENABLED = True

INCLUDED_FEATURES = [
    "Utilities included", "Electricity included", "Internet/WiFi", "Furnished",
    "Washing machine", "Dishwasher", "Balcony", "Elevator", "Parking",
    "Pets allowed", "Smoking allowed",
]

# Building number is optional: NOT required
REQUIRED_POST_FIELDS = ["title", "postcode", "street_name", "warm_rent_eur", "deposit_eur", "available_from", "room_type"]

# favicon
FAVICON_PATH = os.path.join(ASSETS_DIR, "logo.png")
favicon_obj = None
if os.path.exists(FAVICON_PATH) and PIL_OK:
    try:
        favicon_obj = Image.open(FAVICON_PATH)
    except Exception:
        favicon_obj = None

st.set_page_config(
    page_title=APP_NAME,
    page_icon=(favicon_obj if favicon_obj else "🏠"),
    layout="wide"
)


# =============================
# TIME / UTIL
# =============================
def now_berlin_dt() -> datetime:
    if BERLIN_TZ:
        return datetime.now(BERLIN_TZ)
    return datetime.now()


def now_iso() -> str:
    # store Berlin time iso
    return now_berlin_dt().replace(microsecond=0).isoformat()


def parse_iso(s: str) -> datetime:
    try:
        dt = datetime.fromisoformat(s)
        if BERLIN_TZ and dt.tzinfo is None:
            dt = dt.replace(tzinfo=BERLIN_TZ)
        return dt
    except Exception:
        return now_berlin_dt()


def human_time(iso_s: str) -> str:
    dt = parse_iso(iso_s)
    return dt.strftime("%d.%m.%Y • %H:%M")


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def md5(s: str) -> str:
    return hashlib.md5(s.encode("utf-8")).hexdigest()


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


def html_escape(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def json_escape(s: str) -> str:
    s = (s or "").replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return f"\"{s}\""


def format_eur(x: Any) -> str:
    try:
        return f"€{int(x):,}".replace(",", ".")
    except Exception:
        return "€—"


def google_maps_link(address: str) -> str:
    return f"https://www.google.com/maps/search/?api=1&query={quote_plus(address)}"


def asset_path(name: str) -> str:
    p = os.path.join(ASSETS_DIR, name)
    return p if os.path.exists(p) else ""


def abs_upload_path(rel_or_abs: str) -> str:
    p = (rel_or_abs or "").strip()
    if not p:
        return ""
    if os.path.isabs(p):
        return p
    return os.path.join(BASE_DIR, p.replace("/", os.sep))


def rel_upload_path(abs_path: str) -> str:
    if not abs_path:
        return ""
    ap = os.path.abspath(abs_path)
    try:
        return os.path.relpath(ap, BASE_DIR).replace("\\", "/")
    except Exception:
        return ap.replace("\\", "/")


def rate_limit(key: str, seconds: float = 0.8) -> bool:
    now = time.time()
    last = st.session_state.get(key)
    if last and (now - last) < seconds:
        return False
    st.session_state[key] = now
    return True


def ensure_placeholder_png(path: str, size=(256, 256)):
    if os.path.exists(path):
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not PIL_OK:
        with open(path, "wb") as f:
            f.write(b"")
        return
    img = Image.new("RGBA", size, (240, 240, 240, 255))
    img.save(path, format="PNG")


PLACEHOLDER_AVATAR = os.path.join(UPLOAD_DIR, "placeholders", "avatar_placeholder.png")
ensure_placeholder_png(PLACEHOLDER_AVATAR)


def default_avatar_for_gender(gender: Optional[str]) -> str:
    g = (gender or "").strip().lower()
    if g.startswith("m"):
        return asset_path("avatar_male.png") or asset_path("avatar_unknown.png") or PLACEHOLDER_AVATAR
    if g.startswith("f"):
        return asset_path("avatar_female.png") or asset_path("avatar_unknown.png") or PLACEHOLDER_AVATAR
    return asset_path("avatar_unknown.png") or PLACEHOLDER_AVATAR


def show_avatar(path_rel: str, gender: Optional[str] = None, size: int = 56):
    p = abs_upload_path(path_rel)
    if p and os.path.exists(p):
        st.image(p, width=size)
    else:
        st.image(default_avatar_for_gender(gender), width=size)


def address_string(p: Dict[str, Any]) -> str:
    street = (p.get("street_name") or "").strip()
    bn = (p.get("building_number") or "").strip()
    pc = (p.get("postcode") or "").strip()
    city = (p.get("city") or "Berlin").strip()
    if bn:
        x = f"{street} {bn}, {pc} {city}"
    else:
        x = f"{street}, {pc} {city}"
    return re.sub(r"\s+", " ", x).strip()


def copy_button(text_to_copy: str, label: str = "Copy"):
    html = f"""
    <div style="display:flex; gap:10px; align-items:center; margin-top:4px;">
      <button style="
        padding:6px 10px; border-radius:10px; border:1px solid #e9eef5;
        background:white; cursor:pointer; font-size:12px; font-weight:900;
      " onclick="navigator.clipboard.writeText({json_escape(text_to_copy)});">
        {html_escape(label)}
      </button>
      <span style="font-size:12px; color:#64748b; word-break:break-word;">{html_escape(text_to_copy)}</span>
    </div>
    """
    components.html(html, height=44)


# =============================
# URL TOKEN HELPERS
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
def conn():
    c = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL;")
    c.execute("PRAGMA synchronous=NORMAL;")
    c.execute("PRAGMA busy_timeout=8000;")
    return c


def with_retry(fn, tries: int = 14, base_sleep: float = 0.12):
    last = None
    for i in range(tries):
        try:
            return fn()
        except sqlite3.OperationalError as e:
            last = e
            msg = str(e).lower()
            if "locked" in msg or "busy" in msg:
                time.sleep(base_sleep * (i + 1))
                continue
            raise
    raise last


def _col_exists(c: sqlite3.Connection, table: str, col: str) -> bool:
    rows = c.execute(f"PRAGMA table_info({table})").fetchall()
    return any(r["name"] == col for r in rows)


def init_db():
    if st.session_state.get("_db_inited"):
        return

    def _init():
        c = conn()
        cur = c.cursor()
        cur.execute("BEGIN IMMEDIATE;")

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
            bio TEXT,
            avatar_path TEXT,
            bio_pic_path TEXT,
            gender TEXT,
            updated_at TEXT NOT NULL
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS follows (
            follower_id INTEGER NOT NULL,
            following_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(follower_id, following_id)
        )
        """)

        # building_number OPTIONAL (TEXT nullable)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            user_id INTEGER NOT NULL,

            title TEXT NOT NULL,
            description TEXT,

            postcode TEXT NOT NULL,
            street_name TEXT NOT NULL,
            building_number TEXT,
            district_hint TEXT,
            city TEXT NOT NULL DEFAULT 'Berlin',

            warm_rent_eur INTEGER NOT NULL,
            cold_rent_eur INTEGER,
            utilities_eur INTEGER,
            deposit_eur INTEGER NOT NULL,

            rooms REAL,
            size_sqm REAL,
            floor TEXT,
            furnished INTEGER NOT NULL DEFAULT 0,

            available_from TEXT NOT NULL,

            viewing_possible INTEGER NOT NULL DEFAULT 1,
            viewing_details TEXT,

            is_sublet INTEGER NOT NULL DEFAULT 0,
            anmeldung_possible INTEGER NOT NULL DEFAULT 0,
            schufa_required INTEGER NOT NULL DEFAULT 0,

            room_type TEXT,
            shared_with INTEGER,
            included_str TEXT,

            status TEXT NOT NULL DEFAULT 'active'
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS media (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            media_type TEXT NOT NULL,
            path TEXT NOT NULL
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            text TEXT NOT NULL,
            context_post_id INTEGER
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS message_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            text TEXT NOT NULL,
            context_post_id INTEGER,
            status TEXT NOT NULL DEFAULT 'pending'
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS conversations (
            user_a INTEGER NOT NULL,
            user_b INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            accepted INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(user_a, user_b)
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS post_likes (
            post_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(post_id, user_id)
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS post_comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            text TEXT NOT NULL
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            reporter_id INTEGER NOT NULL,
            target_type TEXT NOT NULL,
            target_id INTEGER NOT NULL,
            reason TEXT NOT NULL,
            details TEXT
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS support_tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            user_id INTEGER,
            type TEXT NOT NULL,
            subject TEXT NOT NULL,
            message TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open'
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS app_ratings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            user_id INTEGER,
            rating INTEGER NOT NULL,
            comment TEXT
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

        cur.execute("COMMIT;")
        c.close()

        # migrations
        c2 = conn()
        cur2 = c2.cursor()
        cur2.execute("BEGIN IMMEDIATE;")
        add_cols = [
            ("posts", "building_number", "TEXT"),
            ("posts", "utilities_eur", "INTEGER"),
            ("posts", "viewing_possible", "INTEGER NOT NULL DEFAULT 1"),
            ("posts", "viewing_details", "TEXT"),
            ("posts", "schufa_required", "INTEGER NOT NULL DEFAULT 0"),
            ("messages", "context_post_id", "INTEGER"),
            ("message_requests", "context_post_id", "INTEGER"),
            ("profiles", "bio_pic_path", "TEXT"),
        ]
        for tbl, col, ddl in add_cols:
            if not _col_exists(c2, tbl, col):
                cur2.execute(f"ALTER TABLE {tbl} ADD COLUMN {col} {ddl}")
        cur2.execute("COMMIT;")
        c2.close()

    with_retry(_init)
    st.session_state["_db_inited"] = True


# =============================
# UI STYLE
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
            .rb-title { font-size: 34px !important; }
            .rb-subtitle { font-size: 14px !important; }
            .rb-navwrap { padding: 8px 10px !important; }
            .stButton>button { padding: 0.5rem 0.7rem !important; font-size: 12px !important; }
          }

          .stButton>button {
            border-radius: 14px !important;
            border: 1px solid rgba(226,232,240,1) !important;
            background: #ffffff !important;
            color: #0f172a !important;
            padding: 0.55rem 0.9rem !important;
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

          .stTextInput input, .stNumberInput input, .stSelectbox div[data-baseweb="select"] {
            border-radius: 14px !important;
          }

          .rb-card {
            background: #ffffff;
            border: 1px solid #eef2f7;
            border-radius: 18px;
            box-shadow: 0 18px 45px rgba(16, 24, 40, 0.06);
            padding: 14px;
          }
          .rb-card-tight {
            background: #ffffff;
            border: 1px solid #eef2f7;
            border-radius: 18px;
            box-shadow: 0 18px 45px rgba(16, 24, 40, 0.06);
            padding: 0;
            overflow: hidden;
          }

          .rb-muted { color: #6b7280; font-size: 12px; }
          .rb-title { font-weight: 950; font-size: 46px; line-height: 1.03; margin: 0; color:#0f172a;}
          .rb-subtitle { font-size: 16px; color:#6b7280; margin-top: 10px; }

          /* Professional ONE color pills */
          .rb-chip{
            display:inline-flex;
            align-items:center;
            font-size:12px;
            padding:6px 10px;
            border-radius:999px;
            margin-right:8px;
            margin-bottom:8px;
            font-weight:900;
            border:1px solid #e5e7eb;
            background:#f8fafc;
            color:#0f172a;
            white-space:nowrap;
          }
          .rb-chip-dark{ background:#0f172a; border-color:#0f172a; color:white; }

          .rb-section-title { font-size: 26px; font-weight: 950; margin-top: 8px; color:#0f172a; }

          .rb-navwrap {
            background: #ffffff;
            border: 1px solid #eef2f7;
            border-radius: 18px;
            box-shadow: 0 18px 45px rgba(16, 24, 40, 0.06);
            padding: 10px 14px;
          }
          .rb-logo { display:flex; align-items:center; gap:10px; font-weight:950; font-size:18px; color:#0f172a; }

          .rb-bubble-me {
            background: #ffedd5;
            border: 1px solid #fed7aa;
            padding: 10px 12px;
            border-radius: 16px;
            font-weight: 900;
            color: #0f172a;
          }
          .rb-bubble-them {
            background: #f1f5f9;
            border: 1px solid #e2e8f0;
            padding: 10px 12px;
            border-radius: 16px;
            font-weight: 900;
            color: #0f172a;
          }

          .rb-fab {
            position: fixed;
            right: 18px;
            bottom: 18px;
            z-index: 9999;
          }
          .rb-fab button {
            border-radius: 999px !important;
            padding: 14px 16px !important;
            font-weight: 950 !important;
            box-shadow: 0 18px 45px rgba(16, 24, 40, 0.18) !important;
          }
        </style>
        """,
        unsafe_allow_html=True,
    )


def chip_html(text: str, dark: bool = False) -> str:
    cls = "rb-chip-dark" if dark else "rb-chip"
    return f"<span class='{cls}'>{html_escape(text)}</span>"


# =============================
# MEDIA SAVE
# =============================
def save_any_upload_as_image(file, subdir: str) -> str:
    if not file:
        return ""
    if not PIL_OK:
        raise ValueError("Install pillow: pip install pillow")

    folder = os.path.join(UPLOAD_DIR, subdir)
    os.makedirs(folder, exist_ok=True)

    raw_ext = os.path.splitext(file.name)[1].lower()
    raw_path = os.path.join(folder, f"{uuid.uuid4().hex}{raw_ext if raw_ext else ''}")
    with open(raw_path, "wb") as f:
        f.write(file.getbuffer())

    img = Image.open(raw_path).convert("RGBA")
    png_abs = os.path.join(folder, f"{uuid.uuid4().hex}.png")
    img.save(png_abs, format="PNG")
    return rel_upload_path(png_abs)


def save_video(file, subdir: str) -> str:
    if not file:
        return ""
    ext = os.path.splitext(file.name)[1].lower()
    folder = os.path.join(UPLOAD_DIR, subdir)
    os.makedirs(folder, exist_ok=True)
    abs_path = os.path.join(folder, f"{uuid.uuid4().hex}{ext}")
    with open(abs_path, "wb") as f:
        f.write(file.getbuffer())
    return rel_upload_path(abs_path)


# =============================
# AUTH / PROFILE
# =============================
def password_matches(stored: str, password: str) -> bool:
    stored = (stored or "").strip()
    password = (password or "").strip()
    if not stored:
        return False
    if stored == password:
        return True
    if len(stored) == 64 and re.fullmatch(r"[0-9a-fA-F]{64}", stored):
        return stored.lower() == sha256(password)
    if len(stored) == 32 and re.fullmatch(r"[0-9a-fA-F]{32}", stored):
        return stored.lower() == md5(password)
    return False


def ensure_profile_for_user(user_id: int, email: str):
    def _do():
        c = conn()
        cur = c.cursor()
        cur.execute("BEGIN IMMEDIATE;")
        row = cur.execute("SELECT user_id FROM profiles WHERE user_id=?", (user_id,)).fetchone()
        if row:
            cur.execute("COMMIT;")
            c.close()
            return

        base_username = sanitize_username(email.split("@")[0]) or "user"
        suffix = 0
        while True:
            try_u = base_username if suffix == 0 else f"{base_username}{suffix}"
            try:
                cur.execute("""
                    INSERT INTO profiles (user_id, username, display_name, bio, avatar_path, bio_pic_path, gender, updated_at)
                    VALUES (?,?,?,?,?,?,?,?)
                """, (user_id, try_u, "", "", "", "", None, now_iso()))
                break
            except sqlite3.IntegrityError:
                suffix += 1
                if suffix > 9999:
                    break
        cur.execute("COMMIT;")
        c.close()
    with_retry(_do)


def create_user(email: str, phone: str, password: str) -> Tuple[bool, str]:
    email = normalize_email(email)
    phone = normalize_phone(phone)
    password = (password or "").strip()

    if not email or "@" not in email:
        return False, "Enter a valid email."
    if not password or len(password) < 6:
        return False, "Password must be at least 6 characters."

    def _do():
        c = conn()
        cur = c.cursor()
        cur.execute("BEGIN IMMEDIATE;")
        try:
            cur.execute(
                "INSERT INTO users (created_at, email, phone, password_hash) VALUES (?,?,?,?)",
                (now_iso(), email, phone, sha256(password))
            )
        except sqlite3.IntegrityError:
            cur.execute("ROLLBACK;")
            c.close()
            return False, "Email already exists."
        user_id = cur.lastrowid
        cur.execute("COMMIT;")
        c.close()
        ensure_profile_for_user(user_id, email)
        return True, "Account created. You can login now."

    return with_retry(_do)


def authenticate(email: str, password: str) -> Optional[int]:
    email = normalize_email(email)
    password = (password or "").strip()

    def _do():
        c = conn()
        row = c.execute("SELECT id, email, password_hash FROM users WHERE email=?", (email,)).fetchone()
        c.close()
        return dict(row) if row else None

    u = with_retry(_do)
    if not u:
        return None
    if not password_matches(u["password_hash"], password):
        return None

    uid = int(u["id"])
    ensure_profile_for_user(uid, u["email"])
    return uid


def reset_password(email: str, new_password: str) -> Tuple[bool, str]:
    email = normalize_email(email)
    new_password = (new_password or "").strip()
    if not email or "@" not in email:
        return False, "Enter a valid email."
    if len(new_password) < 6:
        return False, "New password must be at least 6 characters."

    def _do():
        c = conn()
        cur = c.cursor()
        cur.execute("BEGIN IMMEDIATE;")
        cur.execute("UPDATE users SET password_hash=? WHERE email=?", (sha256(new_password), email))
        changed = cur.rowcount
        cur.execute("COMMIT;")
        c.close()
        return changed

    changed = with_retry(_do)
    return (True, "Password reset.") if changed else (False, "Email not found.")


def get_user(user_id: int) -> Dict[str, Any]:
    def _do():
        c = conn()
        row = c.execute("""
            SELECT u.id, u.email, u.phone,
                   COALESCE(p.username,'') AS username,
                   COALESCE(p.display_name,'') AS display_name,
                   COALESCE(p.bio,'') AS bio,
                   COALESCE(p.avatar_path,'') AS avatar_path,
                   COALESCE(p.bio_pic_path,'') AS bio_pic_path,
                   p.gender AS gender
            FROM users u
            LEFT JOIN profiles p ON p.user_id=u.id
            WHERE u.id=?
        """, (user_id,)).fetchone()
        c.close()
        return dict(row) if row else {}
    return with_retry(_do)


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    username = (username or "").strip().lower()
    if not username:
        return None

    def _do():
        c = conn()
        row = c.execute("""
            SELECT u.id, u.email, u.phone,
                   p.username, p.display_name, p.bio, p.avatar_path, p.bio_pic_path, p.gender
            FROM profiles p
            JOIN users u ON u.id=p.user_id
            WHERE p.username=?
        """, (username,)).fetchone()
        c.close()
        return dict(row) if row else None

    return with_retry(_do)


def update_profile(user_id: int, username: str, display_name: str, bio: str,
                   avatar_path: str, bio_pic_path: str, gender: Optional[str]):
    username = sanitize_username(username)
    if not username:
        raise ValueError("Username invalid. Use a-z 0-9 . _")

    def _do():
        c = conn()
        cur = c.cursor()
        cur.execute("BEGIN IMMEDIATE;")
        try:
            cur.execute("""
                UPDATE profiles
                SET username=?, display_name=?, bio=?, avatar_path=?, bio_pic_path=?, gender=?, updated_at=?
                WHERE user_id=?
            """, (username, display_name[:60], bio[:700], avatar_path, bio_pic_path, gender, now_iso(), user_id))
            cur.execute("COMMIT;")
        except sqlite3.IntegrityError:
            cur.execute("ROLLBACK;")
            c.close()
            raise ValueError("Username already taken.")
        c.close()
    with_retry(_do)


# =============================
# SESSIONS (persistent login)
# =============================
def create_session(user_id: int) -> str:
    token = uuid.uuid4().hex + uuid.uuid4().hex
    expires = (now_berlin_dt() + timedelta(days=SESSION_DAYS)).replace(microsecond=0).isoformat()

    def _do():
        c = conn()
        cur = c.cursor()
        cur.execute("BEGIN IMMEDIATE;")
        cur.execute("""
            INSERT INTO sessions (token, user_id, created_at, last_seen, expires_at)
            VALUES (?,?,?,?,?)
        """, (token, user_id, now_iso(), now_iso(), expires))
        cur.execute("COMMIT;")
        c.close()

    with_retry(_do)
    return token


def load_session_from_token(token: str) -> Optional[int]:
    token = (token or "").strip()
    if not token:
        return None

    def _do():
        c = conn()
        row = c.execute("SELECT user_id, expires_at FROM sessions WHERE token=?", (token,)).fetchone()
        c.close()
        return dict(row) if row else None

    r = with_retry(_do)
    if not r:
        return None

    exp = parse_iso(r["expires_at"])
    if exp < now_berlin_dt().replace(microsecond=0):
        return None

    def _touch():
        c = conn()
        cur = c.cursor()
        cur.execute("BEGIN IMMEDIATE;")
        cur.execute("UPDATE sessions SET last_seen=? WHERE token=?", (now_iso(), token))
        cur.execute("COMMIT;")
        c.close()

    with_retry(_touch)
    return int(r["user_id"])


def delete_session(token: str):
    token = (token or "").strip()
    if not token:
        return

    def _do():
        c = conn()
        cur = c.cursor()
        cur.execute("BEGIN IMMEDIATE;")
        cur.execute("DELETE FROM sessions WHERE token=?", (token,))
        cur.execute("COMMIT;")
        c.close()
    with_retry(_do)


def logout():
    tok = st.session_state.get("session_token") or get_query_token()
    if tok:
        delete_session(tok)
    clear_query_token()
    for k in list(st.session_state.keys()):
        if k in ["user_id", "route", "page", "session_token", "selected_profile_id", "dm_user_id", "rq_sender_id",
                 "post_details_id", "edit_post_id", "report_target", "report_target_id", "manage_mode",
                 "media_index", "media_autoplay"]:
            st.session_state.pop(k, None)


# =============================
# FOLLOWS
# =============================
def follow(follower_id: int, following_id: int):
    if follower_id == following_id:
        return

    def _do():
        c = conn()
        cur = c.cursor()
        cur.execute("BEGIN IMMEDIATE;")
        cur.execute("INSERT OR IGNORE INTO follows (follower_id, following_id, created_at) VALUES (?,?,?)",
                    (follower_id, following_id, now_iso()))
        cur.execute("COMMIT;")
        c.close()
    with_retry(_do)


def unfollow(follower_id: int, following_id: int):
    def _do():
        c = conn()
        cur = c.cursor()
        cur.execute("BEGIN IMMEDIATE;")
        cur.execute("DELETE FROM follows WHERE follower_id=? AND following_id=?", (follower_id, following_id))
        cur.execute("COMMIT;")
        c.close()
    with_retry(_do)


def is_following(follower_id: int, following_id: int) -> bool:
    def _do():
        c = conn()
        row = c.execute("SELECT 1 FROM follows WHERE follower_id=? AND following_id=?",
                        (follower_id, following_id)).fetchone()
        c.close()
        return bool(row)
    return with_retry(_do)


def follower_counts(user_id: int) -> Tuple[int, int]:
    def _do():
        c = conn()
        followers = c.execute("SELECT COUNT(*) c FROM follows WHERE following_id=?", (user_id,)).fetchone()["c"]
        following = c.execute("SELECT COUNT(*) c FROM follows WHERE follower_id=?", (user_id,)).fetchone()["c"]
        c.close()
        return int(followers), int(following)
    return with_retry(_do)


def list_followers(user_id: int) -> List[Dict[str, Any]]:
    def _do():
        c = conn()
        rows = c.execute("""
            SELECT u.id AS user_id, COALESCE(p.username,'') AS username,
                   COALESCE(p.display_name,'') AS display_name,
                   COALESCE(p.avatar_path,'') AS avatar_path,
                   p.gender AS gender
            FROM follows f
            JOIN users u ON u.id=f.follower_id
            LEFT JOIN profiles p ON p.user_id=u.id
            WHERE f.following_id=?
            ORDER BY f.created_at DESC
            LIMIT 300
        """, (user_id,)).fetchall()
        c.close()
        return [dict(r) for r in rows]
    return with_retry(_do)


def list_following(user_id: int) -> List[Dict[str, Any]]:
    def _do():
        c = conn()
        rows = c.execute("""
            SELECT u.id AS user_id, COALESCE(p.username,'') AS username,
                   COALESCE(p.display_name,'') AS display_name,
                   COALESCE(p.avatar_path,'') AS avatar_path,
                   p.gender AS gender
            FROM follows f
            JOIN users u ON u.id=f.following_id
            LEFT JOIN profiles p ON p.user_id=u.id
            WHERE f.follower_id=?
            ORDER BY f.created_at DESC
            LIMIT 300
        """, (user_id,)).fetchall()
        c.close()
        return [dict(r) for r in rows]
    return with_retry(_do)


# =============================
# LIKES / COMMENTS / SAVED
# =============================
def like_post(user_id: int, post_id: int):
    def _do():
        c = conn()
        cur = c.cursor()
        cur.execute("BEGIN IMMEDIATE;")
        cur.execute("INSERT OR IGNORE INTO post_likes (post_id, user_id, created_at) VALUES (?,?,?)",
                    (post_id, user_id, now_iso()))
        cur.execute("COMMIT;")
        c.close()
    with_retry(_do)


def unlike_post(user_id: int, post_id: int):
    def _do():
        c = conn()
        cur = c.cursor()
        cur.execute("BEGIN IMMEDIATE;")
        cur.execute("DELETE FROM post_likes WHERE post_id=? AND user_id=?", (post_id, user_id))
        cur.execute("COMMIT;")
        c.close()
    with_retry(_do)


def is_liked(user_id: int, post_id: int) -> bool:
    def _do():
        c = conn()
        row = c.execute("SELECT 1 FROM post_likes WHERE post_id=? AND user_id=?",
                        (post_id, user_id)).fetchone()
        c.close()
        return bool(row)
    return with_retry(_do)


def like_count(post_id: int) -> int:
    def _do():
        c = conn()
        row = c.execute("SELECT COUNT(*) c FROM post_likes WHERE post_id=?", (post_id,)).fetchone()
        c.close()
        return int(row["c"])
    return with_retry(_do)


def add_comment(user_id: int, post_id: int, text: str):
    text = (text or "").strip()
    if not text:
        return

    def _do():
        c = conn()
        cur = c.cursor()
        cur.execute("BEGIN IMMEDIATE;")
        cur.execute("INSERT INTO post_comments (post_id, user_id, created_at, text) VALUES (?,?,?,?)",
                    (post_id, user_id, now_iso(), text[:800]))
        cur.execute("COMMIT;")
        c.close()
    with_retry(_do)


def fetch_comments(post_id: int, limit: int = 30) -> List[Dict[str, Any]]:
    def _do():
        c = conn()
        rows = c.execute("""
            SELECT pc.id, pc.created_at, pc.text, pc.user_id,
                   COALESCE(p.username,'') AS username,
                   COALESCE(p.display_name,'') AS display_name
            FROM post_comments pc
            LEFT JOIN profiles p ON p.user_id=pc.user_id
            WHERE pc.post_id=?
            ORDER BY pc.created_at DESC
            LIMIT ?
        """, (post_id, limit)).fetchall()
        c.close()
        return [dict(r) for r in rows]
    return with_retry(_do)


def list_saved_posts(user_id: int) -> List[int]:
    def _do():
        c = conn()
        rows = c.execute("SELECT post_id FROM post_likes WHERE user_id=? ORDER BY created_at DESC LIMIT 500",
                         (user_id,)).fetchall()
        c.close()
        return [int(r["post_id"]) for r in rows]
    return with_retry(_do)


# =============================
# REPORT / SUPPORT / RATINGS
# =============================
def create_report(reporter_id: int, target_type: str, target_id: int, reason: str, details: str):
    def _do():
        c = conn()
        cur = c.cursor()
        cur.execute("BEGIN IMMEDIATE;")
        cur.execute("""
            INSERT INTO reports (created_at, reporter_id, target_type, target_id, reason, details)
            VALUES (?,?,?,?,?,?)
        """, (now_iso(), reporter_id, target_type, int(target_id), reason[:120], details[:1500]))
        cur.execute("COMMIT;")
        c.close()
    with_retry(_do)


def create_support_ticket(user_id: Optional[int], ticket_type: str, subject: str, message: str):
    def _do():
        c = conn()
        cur = c.cursor()
        cur.execute("BEGIN IMMEDIATE;")
        cur.execute("""
            INSERT INTO support_tickets (created_at, user_id, type, subject, message, status)
            VALUES (?,?,?,?,?,'open')
        """, (now_iso(), user_id, ticket_type, subject[:120], message[:2000]))
        cur.execute("COMMIT;")
        c.close()
    with_retry(_do)


def submit_app_rating(user_id: Optional[int], rating: int, comment: str):
    rating = int(rating)
    if rating < 1 or rating > 5:
        return

    def _do():
        c = conn()
        cur = c.cursor()
        cur.execute("BEGIN IMMEDIATE;")
        cur.execute("""
            INSERT INTO app_ratings (created_at, user_id, rating, comment)
            VALUES (?,?,?,?)
        """, (now_iso(), user_id, rating, comment[:1000]))
        cur.execute("COMMIT;")
        c.close()
    with_retry(_do)


def app_rating_summary() -> Tuple[float, int]:
    def _do():
        c = conn()
        row = c.execute("SELECT AVG(rating) avg_r, COUNT(*) cnt FROM app_ratings").fetchone()
        c.close()
        avg_r = float(row["avg_r"]) if row["avg_r"] is not None else 0.0
        cnt = int(row["cnt"])
        return avg_r, cnt
    return with_retry(_do)


# =============================
# MESSAGING + REQUESTS
# =============================
def _conv_key(a: int, b: int) -> Tuple[int, int]:
    return (a, b) if a < b else (b, a)


def ensure_conversation_row(a: int, b: int):
    ua, ub = _conv_key(a, b)

    def _do():
        c = conn()
        cur = c.cursor()
        cur.execute("BEGIN IMMEDIATE;")
        cur.execute("INSERT OR IGNORE INTO conversations (user_a, user_b, created_at, accepted) VALUES (?,?,?,0)",
                    (ua, ub, now_iso()))
        cur.execute("COMMIT;")
        c.close()
    with_retry(_do)


def conversation_has_any_message(a: int, b: int) -> bool:
    def _do():
        c = conn()
        row = c.execute("""
            SELECT 1 FROM messages
            WHERE (sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?)
            LIMIT 1
        """, (a, b, b, a)).fetchone()
        c.close()
        return bool(row)
    return with_retry(_do)


def is_conversation_accepted(a: int, b: int) -> bool:
    if conversation_has_any_message(a, b):
        return True
    ua, ub = _conv_key(a, b)

    def _do():
        c = conn()
        row = c.execute("SELECT accepted FROM conversations WHERE user_a=? AND user_b=?",
                        (ua, ub)).fetchone()
        c.close()
        return bool(row and int(row["accepted"]) == 1)
    return with_retry(_do)


def count_pending_request_msgs(sender_id: int, receiver_id: int) -> int:
    def _do():
        c = conn()
        row = c.execute("""
            SELECT COUNT(*) c FROM message_requests
            WHERE sender_id=? AND receiver_id=? AND status='pending'
        """, (sender_id, receiver_id)).fetchone()
        c.close()
        return int(row["c"])
    return with_retry(_do)


def send_message_or_request(sender_id: int, receiver_id: int, text: str, context_post_id: Optional[int] = None) -> Tuple[bool, str]:
    text = (text or "").strip()
    if not text:
        return False, "Empty message."

    ensure_conversation_row(sender_id, receiver_id)

    # if following OR accepted OR any prior msg exists -> direct
    if is_following(sender_id, receiver_id) or is_conversation_accepted(sender_id, receiver_id):
        def _do():
            c = conn()
            cur = c.cursor()
            cur.execute("BEGIN IMMEDIATE;")
            cur.execute("INSERT INTO messages (created_at, sender_id, receiver_id, text, context_post_id) VALUES (?,?,?,?,?)",
                        (now_iso(), sender_id, receiver_id, text, context_post_id))
            cur.execute("COMMIT;")
            c.close()
        with_retry(_do)
        return True, "Sent."

    # otherwise request max 2
    if count_pending_request_msgs(sender_id, receiver_id) >= 2:
        return False, "You already sent 2 request messages. Wait for accept."

    def _rq():
        c = conn()
        cur = c.cursor()
        cur.execute("BEGIN IMMEDIATE;")
        cur.execute("""
            INSERT INTO message_requests (created_at, sender_id, receiver_id, text, context_post_id, status)
            VALUES (?,?,?,?,?, 'pending')
        """, (now_iso(), sender_id, receiver_id, text, context_post_id))
        cur.execute("COMMIT;")
        c.close()

    with_retry(_rq)
    return True, "Sent as request."


def accept_request(receiver_id: int, sender_id: int):
    ua, ub = _conv_key(receiver_id, sender_id)

    def _do():
        c = conn()
        cur = c.cursor()
        cur.execute("BEGIN IMMEDIATE;")

        rows = cur.execute("""
            SELECT created_at, sender_id, receiver_id, text, context_post_id
            FROM message_requests
            WHERE sender_id=? AND receiver_id=? AND status='pending'
            ORDER BY created_at ASC
        """, (sender_id, receiver_id)).fetchall()

        for r in rows:
            cur.execute("INSERT INTO messages (created_at, sender_id, receiver_id, text, context_post_id) VALUES (?,?,?,?,?)",
                        (r["created_at"], r["sender_id"], r["receiver_id"], r["text"], r["context_post_id"]))

        cur.execute("""
            UPDATE message_requests
            SET status='accepted'
            WHERE sender_id=? AND receiver_id=? AND status='pending'
        """, (sender_id, receiver_id))

        cur.execute("INSERT OR IGNORE INTO conversations (user_a, user_b, created_at, accepted) VALUES (?,?,?,0)",
                    (ua, ub, now_iso()))
        cur.execute("UPDATE conversations SET accepted=1 WHERE user_a=? AND user_b=?", (ua, ub))

        cur.execute("COMMIT;")
        c.close()

    with_retry(_do)


def decline_request(receiver_id: int, sender_id: int):
    def _do():
        c = conn()
        cur = c.cursor()
        cur.execute("BEGIN IMMEDIATE;")
        cur.execute("""
            UPDATE message_requests
            SET status='declined'
            WHERE sender_id=? AND receiver_id=? AND status='pending'
        """, (sender_id, receiver_id))
        cur.execute("COMMIT;")
        c.close()
    with_retry(_do)


def get_requests_for_user(receiver_id: int) -> List[Dict[str, Any]]:
    def _do():
        c = conn()
        rows = c.execute("""
            SELECT sender_id, COUNT(*) AS cnt, MAX(created_at) AS last_time
            FROM message_requests
            WHERE receiver_id=? AND status='pending'
            GROUP BY sender_id
            ORDER BY last_time DESC
        """, (receiver_id,)).fetchall()
        c.close()

        out = []
        for r in rows:
            sender = get_user(int(r["sender_id"]))
            out.append({
                "sender_id": int(r["sender_id"]),
                "username": sender.get("username"),
                "display_name": sender.get("display_name"),
                "cnt": int(r["cnt"]),
                "last_time": r["last_time"],
            })
        return out
    return with_retry(_do)


def get_request_thread(receiver_id: int, sender_id: int) -> List[Dict[str, Any]]:
    def _do():
        c = conn()
        rows = c.execute("""
            SELECT * FROM message_requests
            WHERE receiver_id=? AND sender_id=? AND status='pending'
            ORDER BY created_at ASC
        """, (receiver_id, sender_id)).fetchall()
        c.close()
        return [dict(r) for r in rows]
    return with_retry(_do)


def get_conversations(user_id: int) -> List[Dict[str, Any]]:
    # FIXED: no "other_id" column anywhere; we compute it as an alias.
    sql = """
    SELECT
      CASE WHEN sender_id = ? THEN receiver_id ELSE sender_id END AS other_id,
      MAX(created_at) AS last_time
    FROM messages
    WHERE sender_id=? OR receiver_id=?
    GROUP BY other_id
    ORDER BY last_time DESC
    """

    def _do():
        c = conn()
        rows = c.execute(sql, (user_id, user_id, user_id)).fetchall()
        c.close()
        conv = []
        for r in rows:
            other_id = int(r["other_id"])
            other = get_user(other_id)
            conv.append({
                "other_id": other_id,
                "username": other.get("username"),
                "display_name": other.get("display_name"),
                "avatar_path": other.get("avatar_path"),
                "gender": other.get("gender"),
                "last_time": r["last_time"]
            })
        return conv
    return with_retry(_do)


def get_thread(user_id: int, other_id: int, limit: int = 400) -> List[Dict[str, Any]]:
    def _do():
        c = conn()
        rows = c.execute("""
            SELECT * FROM messages
            WHERE (sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?)
            ORDER BY created_at ASC
            LIMIT ?
        """, (user_id, other_id, other_id, user_id, limit)).fetchall()
        c.close()
        return [dict(r) for r in rows]
    return with_retry(_do)


# =============================
# POSTS
# =============================
def fetch_media_for_post(post_id: int) -> List[Dict[str, Any]]:
    def _do():
        c = conn()
        rows = c.execute("SELECT id, media_type, path FROM media WHERE post_id=? ORDER BY created_at ASC",
                         (post_id,)).fetchall()
        c.close()
        return [dict(r) for r in rows]
    return with_retry(_do)


def create_post(user_id: int, post: Dict[str, Any], media_paths: List[Tuple[str, str]]):
    def _do():
        c = conn()
        cur = c.cursor()
        cur.execute("BEGIN IMMEDIATE;")
        cur.execute("""
            INSERT INTO posts (
                created_at, updated_at, user_id,
                title, description,
                postcode, street_name, building_number, district_hint, city,
                warm_rent_eur, cold_rent_eur, utilities_eur, deposit_eur,
                rooms, size_sqm, floor, furnished,
                available_from,
                viewing_possible, viewing_details,
                is_sublet, anmeldung_possible, schufa_required,
                room_type, shared_with, included_str,
                status
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            now_iso(), now_iso(), user_id,
            post["title"], post.get("description", ""),
            post["postcode"], post["street_name"], post.get("building_number") or None,
            post.get("district_hint", ""), "Berlin",
            int(post["warm_rent_eur"]), post.get("cold_rent_eur"), post.get("utilities_eur"), int(post["deposit_eur"]),
            post.get("rooms"), post.get("size_sqm"), post.get("floor", ""), 1 if post.get("furnished") else 0,
            post["available_from"],
            1 if post.get("viewing_possible") else 0, post.get("viewing_details", ""),
            1 if post.get("is_sublet") else 0,
            1 if post.get("anmeldung_possible") else 0,
            1 if post.get("schufa_required") else 0,
            post.get("room_type"), post.get("shared_with"), post.get("included_str", ""),
            "active"
        ))
        post_id = cur.lastrowid
        for media_type, path in media_paths:
            cur.execute("INSERT INTO media (post_id, created_at, media_type, path) VALUES (?,?,?,?)",
                        (post_id, now_iso(), media_type, path))
        cur.execute("COMMIT;")
        c.close()
    with_retry(_do)


def delete_post(user_id: int, post_id: int):
    def _do():
        c = conn()
        cur = c.cursor()
        cur.execute("BEGIN IMMEDIATE;")
        row = cur.execute("SELECT user_id FROM posts WHERE id=? AND status='active'", (post_id,)).fetchone()
        if not row or int(row["user_id"]) != user_id:
            cur.execute("ROLLBACK;")
            c.close()
            raise ValueError("Not allowed.")
        cur.execute("UPDATE posts SET status='deleted', updated_at=? WHERE id=?", (now_iso(), post_id))
        cur.execute("COMMIT;")
        c.close()
    with_retry(_do)


def fetch_posts(filters: Dict[str, Any], limit: int = 240) -> List[Dict[str, Any]]:
    where = ["p.status='active'"]
    params: List[Any] = []

    q = (filters.get("q") or "").strip().lower()
    if q:
        where.append("(LOWER(p.title) LIKE ? OR LOWER(p.description) LIKE ? OR LOWER(p.street_name) LIKE ? OR LOWER(p.postcode) LIKE ?)")
        like = f"%{q}%"
        params += [like, like, like, like]

    postcode = (filters.get("postcode") or "").strip()
    if postcode:
        where.append("p.postcode LIKE ?")
        params.append(f"%{postcode}%")

    street = (filters.get("street") or "").strip().lower()
    if street:
        where.append("LOWER(p.street_name) LIKE ?")
        params.append(f"%{street}%")

    min_rent = filters.get("min_rent")
    max_rent = filters.get("max_rent")
    if min_rent is not None:
        where.append("p.warm_rent_eur >= ?")
        params.append(int(min_rent))
    if max_rent is not None:
        where.append("p.warm_rent_eur <= ?")
        params.append(int(max_rent))

    rooms = filters.get("rooms")
    if rooms:
        if rooms == "4+":
            where.append("p.rooms >= 4")
        else:
            try:
                where.append("p.rooms >= ?")
                params.append(float(rooms))
            except Exception:
                pass

    room_type = filters.get("room_type")
    if room_type:
        where.append("p.room_type=?")
        params.append(room_type)

    owner_id = filters.get("user_id")
    if owner_id is not None:
        where.append("p.user_id=?")
        params.append(int(owner_id))

    if filters.get("sublet_only"):
        where.append("p.is_sublet=1")
    if filters.get("anmeldung_only"):
        where.append("p.anmeldung_possible=1")

    sql = f"""
        SELECT p.*,
               COALESCE(pr.username, SUBSTR(u.email, 1, INSTR(u.email,'@')-1)) AS username,
               COALESCE(pr.display_name, '') AS display_name,
               COALESCE(pr.avatar_path, '') AS avatar_path,
               pr.gender AS gender
        FROM posts p
        JOIN users u ON u.id=p.user_id
        LEFT JOIN profiles pr ON pr.user_id=p.user_id
        WHERE {' AND '.join(where)}
        ORDER BY p.updated_at DESC
        LIMIT ?
    """

    def _do():
        c = conn()
        rows = c.execute(sql, params + [int(limit)]).fetchall()
        c.close()
        posts = []
        for r in rows:
            d = dict(r)
            d["media"] = fetch_media_for_post(int(d["id"]))
            posts.append(d)
        return posts

    return with_retry(_do)


def get_post_by_id(post_id: int) -> Optional[Dict[str, Any]]:
    def _do():
        c = conn()
        row = c.execute("""
            SELECT p.*,
                   COALESCE(pr.username, SUBSTR(u.email, 1, INSTR(u.email,'@')-1)) AS username,
                   COALESCE(pr.display_name, '') AS display_name,
                   COALESCE(pr.avatar_path, '') AS avatar_path,
                   pr.gender AS gender
            FROM posts p
            JOIN users u ON u.id=p.user_id
            LEFT JOIN profiles pr ON pr.user_id=p.user_id
            WHERE p.id=? AND p.status='active'
        """, (post_id,)).fetchone()
        c.close()
        if not row:
            return None
        d = dict(row)
        d["media"] = fetch_media_for_post(int(d["id"]))
        return d
    return with_retry(_do)


# =============================
# NAV + UI COMPONENTS
# =============================
def open_profile(user_id: int):
    st.session_state["selected_profile_id"] = int(user_id)
    st.session_state["page"] = "Profile"
    st.rerun()


def open_chat(user_id: int):
    st.session_state["dm_user_id"] = int(user_id)
    st.session_state["page"] = "Messages"
    st.rerun()


def open_details(post_id: int):
    st.session_state["post_details_id"] = int(post_id)
    st.session_state["page"] = "PostDetails"
    st.rerun()


def open_report(target_type: str, target_id: int):
    st.session_state["report_target"] = target_type
    st.session_state["report_target_id"] = int(target_id)
    st.session_state["page"] = "Report"
    st.rerun()


def render_logo():
    logo = asset_path("logo.png")
    if logo and os.path.exists(logo):
        cols = st.columns([0.25, 2.75])
        with cols[0]:
            st.image(logo, width=44)
        with cols[1]:
            st.markdown("<div class='rb-logo'>RentinBerlin</div>", unsafe_allow_html=True)
    else:
        st.markdown("<div class='rb-logo'>🏠 RentinBerlin</div>", unsafe_allow_html=True)


def count_my_likes(uid: int) -> int:
    def _do():
        c = conn()
        row = c.execute("SELECT COUNT(*) c FROM post_likes WHERE user_id=?", (uid,)).fetchone()
        c.close()
        return int(row["c"]) if row else 0
    return with_retry(_do)


def render_navbar(current_page: str, uid: Optional[int] = None):
    likes_count = count_my_likes(uid) if uid else 0

    st.markdown('<div class="rb-navwrap">', unsafe_allow_html=True)
    row = st.columns([2.4, 1.0, 1.0, 1.2, 1.2, 1.25, 0.8, 0.9], vertical_alignment="center")

    with row[0]:
        render_logo()

    def tab_button(label: str, page_value: str):
        active = (current_page == page_value)
        clicked = st.button(label, key=f"nav_{page_value}", use_container_width=True)
        if clicked:
            st.session_state["page"] = page_value
            st.rerun()
        if active:
            st.markdown("<div style='height:3px;background:#ff7a1a;border-radius:999px;margin-top:4px;'></div>",
                        unsafe_allow_html=True)
        else:
            st.markdown("<div style='height:3px;'></div>", unsafe_allow_html=True)

    with row[1]:
        tab_button("Home", "Feed")
    with row[2]:
        tab_button("Explore", "Search")
    with row[3]:
        tab_button("Messages", "Messages")
    with row[4]:
        tab_button("Requests", "Requests")
    with row[5]:
        tab_button("My Profile", "Profile")

    with row[6]:
        if st.button("⚑", help="Report / Support", use_container_width=True, key="nav_flag"):
            st.session_state["page"] = "Support"
            st.rerun()

    with row[7]:
        st.button(f"🧡 {likes_count}", help="Saved (liked)", use_container_width=True, key="nav_saved")

    st.markdown("</div>", unsafe_allow_html=True)
    st.write("")

    # Floating Post button (professional)
    if uid:
        st.markdown('<div class="rb-fab">', unsafe_allow_html=True)
        if st.button("＋ Post", type="primary", key="fab_post"):
            st.session_state["page"] = "Post"
            st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)


def render_hero_and_search():
    st.markdown('<div class="rb-card">', unsafe_allow_html=True)
    left, right = st.columns([1.3, 1.0], vertical_alignment="center")

    with left:
        st.markdown("<p class='rb-title'>Find Your Next Apartment<br/>in Berlin</p>", unsafe_allow_html=True)
        st.markdown("<div class='rb-subtitle'>Browse, message, and connect — fast.</div>", unsafe_allow_html=True)
        st.write("")

        bar = st.columns([3.5, 1.2, 1.2, 1.2, 1.0], vertical_alignment="center")
        q = bar[0].text_input(" ", placeholder="Search street, postcode, keywords", key="home_q", label_visibility="collapsed")
        price = bar[1].selectbox("Price", ["Any", "≤ 800", "≤ 1200", "≤ 1600", "≤ 2000"], key="home_price")
        rooms = bar[2].selectbox("Rooms", ["Any", "1", "2", "3", "4+"], key="home_rooms")
        more = bar[3].selectbox("More", ["Any", "Sublet only", "Anmeldung only", "Sublet + Anmeldung"], key="home_more")
        do_search = bar[4].button("Search", type="primary", use_container_width=True)

        if do_search:
            st.session_state["search_prefill"] = {"q": q, "price": price, "rooms": rooms, "more": more}
            st.session_state["page"] = "Search"
            st.rerun()

    with right:
        hero = asset_path("hero.png")
        if hero and os.path.exists(hero):
            st.image(hero, use_container_width=True)
        else:
            st.markdown("""
              <div style="
                height: 230px;border-radius:18px;
                background: linear-gradient(135deg,#eff6ff,#ffffff);
                border:1px solid #eef2f7;
                display:flex;align-items:center;justify-content:center;
                color:#94a3b8;font-weight:900;
              ">Berlin Apartments</div>
            """, unsafe_allow_html=True)

    st.markdown("</div>", unsafe_allow_html=True)
    st.write("")


def render_media_slider(media: List[Dict[str, Any]], key_prefix: str):
    items = []
    for m in media or []:
        ap = abs_upload_path(m.get("path", ""))
        if ap and os.path.exists(ap):
            items.append({"type": m.get("media_type"), "path": ap})

    if not items:
        return

    idx_key = f"{key_prefix}_media_index"
    auto_key = f"{key_prefix}_media_autoplay"

    st.session_state.setdefault(idx_key, 0)
    st.session_state.setdefault(auto_key, False)

    idx = int(st.session_state[idx_key]) % len(items)

    # Optional autoplay (tries different APIs depending on Streamlit version)
    if st.session_state[auto_key]:
        try:
            st.autorefresh(interval=2500, key=f"{key_prefix}_autorefresh")
            st.session_state[idx_key] = (idx + 1) % len(items)
            idx = int(st.session_state[idx_key])
        except Exception:
            try:
                st.experimental_rerun()
            except Exception:
                pass

    top = st.columns([1.0, 1.0, 2.0, 1.0, 1.0], vertical_alignment="center")
    if top[0].button("◀", key=f"{key_prefix}_prev", use_container_width=True):
        st.session_state[idx_key] = (idx - 1) % len(items)
        st.rerun()
    if top[1].button("▶", key=f"{key_prefix}_next", use_container_width=True):
        st.session_state[idx_key] = (idx + 1) % len(items)
        st.rerun()

    with top[2]:
        st.caption(f"{idx+1}/{len(items)}")

    with top[3]:
        if st.button("Auto", key=f"{key_prefix}_auto", use_container_width=True):
            st.session_state[auto_key] = not st.session_state[auto_key]
            st.rerun()

    with top[4]:
        st.caption("")

    item = items[idx]
    if item["type"] == "image":
        st.image(item["path"], use_container_width=True)
    else:
        st.video(item["path"])

    thumbs = items[:6]
    if len(thumbs) > 1:
        cols = st.columns(len(thumbs))
        for i, it in enumerate(thumbs):
            with cols[i]:
                if it["type"] == "image":
                    st.image(it["path"], use_container_width=True)
                else:
                    st.markdown("<div class='rb-card' style='text-align:center;font-weight:900;'>🎥 Video</div>", unsafe_allow_html=True)
                if st.button("Select", key=f"{key_prefix}_sel_{i}", use_container_width=True):
                    st.session_state[idx_key] = i
                    st.rerun()


def render_listing_card(uid: int, p: Dict[str, Any], ctx: str = "card"):
    """
    IMPORTANT: ctx must be unique per *instance* where the card is rendered.
    This prevents StreamlitDuplicateElementKey when the same post appears
    in multiple sections (e.g., Profile > Posts and Profile > Saved).
    """
    post_id = int(p["id"])
    owner_id = int(p["user_id"])
    media = p.get("media") or []

    ctx = (ctx or "card").strip().replace(" ", "_")
    base = f"{ctx}_{post_id}"

    like_key = f"{base}_like"
    details_key = f"{base}_details"
    map_key = f"{base}_map"
    msg_key = f"{base}_msg"

    st.markdown('<div class="rb-card-tight">', unsafe_allow_html=True)

    # Cover: show first image if exists (no blank dent)
    cover = ""
    for m in media:
        if m.get("media_type") == "image":
            ap = abs_upload_path(m.get("path", ""))
            if ap and os.path.exists(ap):
                cover = ap
                break
    if cover:
        st.image(cover, use_container_width=True)

    body = st.container()
    with body:
        top = st.columns([6, 1], vertical_alignment="center")
        with top[0]:
            st.markdown(f"{chip_html(format_eur(p.get('warm_rent_eur')), dark=True)}", unsafe_allow_html=True)
            st.caption(f"Available: {p.get('available_from') or '—'}")
        with top[1]:
            liked = is_liked(uid, post_id)
            if st.button("🧡" if liked else "♡", key=like_key, help="Save"):
                (unlike_post(uid, post_id) if liked else like_post(uid, post_id))
                st.rerun()

        addr = address_string(p)
        st.markdown(f"**{html_escape(addr)}**", unsafe_allow_html=True)
        st.write("")

        pills = []
        pills.append(chip_html(f"Deposit {format_eur(p.get('deposit_eur'))}"))
        if p.get("utilities_eur"):
            pills.append(chip_html(f"Utilities {format_eur(p.get('utilities_eur'))}"))
        pills.append(chip_html("Sublet" if int(p.get("is_sublet", 0)) == 1 else "Not sublet"))
        pills.append(chip_html("Anmeldung" if int(p.get("anmeldung_possible", 0)) == 1 else "No Anmeldung"))
        pills.append(chip_html("Viewing ✅" if int(p.get("viewing_possible", 1)) == 1 else "Viewing ❌"))
        if int(p.get("schufa_required", 0)) == 1:
            pills.append(chip_html("SCHUFA required"))

        st.markdown("".join(pills), unsafe_allow_html=True)

        b = st.columns([1.25, 1.0, 1.0], vertical_alignment="center")
        with b[0]:
            if st.button("View Details", key=details_key, type="primary", use_container_width=True):
                open_details(post_id)
        with b[1]:
            if st.button("Map", key=map_key, use_container_width=True):
                st.session_state["map_open_addr"] = addr
                st.rerun()
        with b[2]:
            if owner_id != uid and st.button("Message", key=msg_key, use_container_width=True):
                open_chat(owner_id)

    st.markdown("</div>", unsafe_allow_html=True)


# =============================
# PAGES
# =============================
def page_login():
    st.markdown("<div class='rb-card'>", unsafe_allow_html=True)
    cols = st.columns([1.3, 1.0], vertical_alignment="center")

    with cols[0]:
        render_logo()
        st.caption("Login to your account (Berlin time)")

    with cols[1]:
        if REGISTRATION_ENABLED and st.button("Register", use_container_width=True):
            st.session_state["route"] = "register"
            st.rerun()

    st.write("")
    with st.form("login_form"):
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login", type="primary")

    c = st.columns([1, 1, 8])
    if c[0].button("Reset password"):
        st.session_state["route"] = "reset"
        st.rerun()

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
            st.session_state["page"] = "Feed"
            st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)


def page_register():
    st.markdown("<div class='rb-card'>", unsafe_allow_html=True)
    cols = st.columns([1.3, 1.0], vertical_alignment="center")

    with cols[0]:
        render_logo()
        st.caption("Create a new account")

    with cols[1]:
        if st.button("Login", use_container_width=True):
            st.session_state["route"] = "login"
            st.rerun()

    st.write("")
    with st.form("reg_form"):
        email = st.text_input("Email")
        phone = st.text_input("Phone (optional)")
        password = st.text_input("Password (min 6 chars)", type="password")
        submitted = st.form_submit_button("Create account", type="primary")

    if submitted:
        ok, msg = create_user(email, phone, password)
        if ok:
            st.success(msg)
            st.session_state["route"] = "login"
            st.rerun()
        else:
            st.error(msg)

    st.markdown("</div>", unsafe_allow_html=True)


def page_reset():
    st.markdown("<div class='rb-card'>", unsafe_allow_html=True)
    st.markdown("## Reset Password")
    with st.form("reset_form"):
        email = st.text_input("Email")
        new_password = st.text_input("New password", type="password")
        submitted = st.form_submit_button("Reset", type="primary")

    if submitted:
        ok, msg = reset_password(email, new_password)
        (st.success(msg) if ok else st.error(msg))
        if ok:
            st.session_state["route"] = "login"
            st.rerun()

    if st.button("Back to login"):
        st.session_state["route"] = "login"
        st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)


def page_feed(uid: int):
    render_navbar("Feed", uid=uid)
    render_hero_and_search()

    if st.session_state.get("map_open_addr"):
        addr = st.session_state.pop("map_open_addr")
        st.markdown("<div class='rb-card'>", unsafe_allow_html=True)
        st.markdown(f"### Map: {addr}")
        st.markdown(f"[Open in Google Maps]({google_maps_link(addr)})")
        copy_button(addr, label="Copy address")
        st.markdown("</div>", unsafe_allow_html=True)
        st.write("")

    st.markdown("<div class='rb-section-title'>Recent Listings</div>", unsafe_allow_html=True)
    st.write("")

    posts = fetch_posts({}, limit=120)
    if not posts:
        st.info("No posts yet.")
        return

    cols = st.columns(3, gap="large")
    for i, p in enumerate(posts[:36]):
        with cols[i % 3]:
            render_listing_card(uid, p, ctx=f"feed_{i}")
            st.write("")


def page_search(uid: int):
    render_navbar("Search", uid=uid)

    pre = st.session_state.pop("search_prefill", None)
    q0, price0, rooms0, more0 = "", "Any", "Any", "Any"
    if pre:
        q0 = pre.get("q", "")
        price0 = pre.get("price", "Any")
        rooms0 = pre.get("rooms", "Any")
        more0 = pre.get("more", "Any")

    st.markdown("<div class='rb-card'>", unsafe_allow_html=True)
    st.markdown("## Explore")

    c = st.columns([3, 1.2, 1.2, 1.6], vertical_alignment="center")
    q = c[0].text_input("Search", value=q0, placeholder="Street, postcode, keyword")
    price = c[1].selectbox("Price", ["Any", "≤ 800", "≤ 1200", "≤ 1600", "≤ 2000"],
                          index=["Any", "≤ 800", "≤ 1200", "≤ 1600", "≤ 2000"].index(price0))
    rooms = c[2].selectbox("Rooms", ["Any", "1", "2", "3", "4+"],
                           index=["Any", "1", "2", "3", "4+"].index(rooms0))
    more = c[3].selectbox("More", ["Any", "Sublet only", "Anmeldung only", "Sublet + Anmeldung"],
                          index=["Any", "Sublet only", "Anmeldung only", "Sublet + Anmeldung"].index(more0))

    c2 = st.columns([1.2, 1.2, 1.2, 1.2, 2.2], vertical_alignment="center")
    postcode = c2[0].text_input("Postcode", placeholder="e.g. 12043")
    street = c2[1].text_input("Street", placeholder="e.g. Sonnenallee")
    room_type = c2[2].selectbox("Type", ["Any", "Private", "Shared"])
    min_r = c2[3].number_input("Min €", min_value=0, value=0, step=50)
    max_r = c2[4].number_input("Max €", min_value=0, value=2000, step=50)

    run = st.button("Search", type="primary")

    min_rent = int(min_r) if min_r and min_r > 0 else None
    max_rent = int(max_r) if max_r and max_r > 0 else None
    if price != "Any":
        try:
            max_rent = int(price.replace("≤", "").strip())
        except Exception:
            pass

    sublet_only = (more in ["Sublet only", "Sublet + Anmeldung"])
    anmeldung_only = (more in ["Anmeldung only", "Sublet + Anmeldung"])

    if run:
        filters = {
            "q": q,
            "postcode": postcode,
            "street": street,
            "room_type": None if room_type == "Any" else room_type,
            "min_rent": min_rent,
            "max_rent": max_rent,
            "rooms": None if rooms == "Any" else rooms,
            "sublet_only": sublet_only,
            "anmeldung_only": anmeldung_only
        }
        posts = fetch_posts(filters, limit=240)
        st.write("")
        st.caption(f"Results: {len(posts)}")

        if posts:
            cols = st.columns(3, gap="large")
            for i, p in enumerate(posts[:90]):
                with cols[i % 3]:
                    render_listing_card(uid, p, ctx=f"search_{i}")
                    st.write("")
        else:
            st.info("No results.")

    st.markdown("</div>", unsafe_allow_html=True)


def page_post(uid: int):
    render_navbar("Post", uid=uid)

    st.markdown("<div class='rb-card'>", unsafe_allow_html=True)
    st.markdown("## Publish a Listing")

    with st.form("post_form"):
        title = st.text_input("Title *", placeholder="Bright 2-room apartment in Neukölln")
        description = st.text_area("Description", height=120)

        c = st.columns(4)
        postcode = c[0].text_input("Postcode *", placeholder="12043")
        street_name = c[1].text_input("Street name *", placeholder="Sonnenallee")
        building_number = c[2].text_input("Building number (optional)", placeholder="19")
        district_hint = c[3].text_input("District (optional)", placeholder="Neukölln")

        c2 = st.columns(4)
        warm_rent = c2[0].number_input("Warm rent (€) *", min_value=0, value=1200, step=10)
        cold_rent = c2[1].number_input("Cold rent (€)", min_value=0, value=0, step=10)
        utilities = c2[2].number_input("Utilities (€)", min_value=0, value=0, step=10)
        deposit = c2[3].number_input("Deposit (€) *", min_value=0, value=2000, step=50)

        c3 = st.columns(4)
        rooms = c3[0].number_input("Rooms", min_value=0.0, value=2.0, step=0.5)
        size_sqm = c3[1].number_input("Size (sqm)", min_value=0.0, value=45.0, step=1.0)
        floor = c3[2].text_input("Floor (optional)", placeholder="3rd")
        furnished = c3[3].checkbox("Furnished")

        available_from = st.text_input("Available from *", placeholder="2026-03-01 or ASAP")

        c4 = st.columns(4)
        room_type = c4[0].selectbox("Room type *", ["Private", "Shared"])
        is_sublet = c4[1].checkbox("Sublet?")
        anmeldung_possible = c4[2].checkbox("Anmeldung possible?")
        schufa_required = c4[3].checkbox("SCHUFA required?")

        viewing_possible = st.checkbox("Viewing possible?", value=True)
        viewing_details = ""
        if viewing_possible:
            viewing_details = st.text_input("Viewing details (optional)", placeholder="Weekends / appointment only")

        shared_with = None
        if room_type == "Shared":
            shared_with = st.number_input("Shared with how many people?", min_value=1, value=2, step=1)

        included = st.multiselect("Included features", INCLUDED_FEATURES)

        images_any = st.file_uploader("Images (any image type)", accept_multiple_files=True)
        videos = st.file_uploader("Videos", type=["mp4", "mov", "m4v", "webm"], accept_multiple_files=True)

        submit = st.form_submit_button("Publish", type="primary")

    if submit:
        post = {
            "title": title.strip(),
            "description": description.strip(),
            "postcode": postcode.strip(),
            "street_name": street_name.strip(),
            "building_number": building_number.strip() if building_number.strip() else None,
            "district_hint": district_hint.strip(),
            "warm_rent_eur": int(warm_rent),
            "cold_rent_eur": int(cold_rent) if cold_rent > 0 else None,
            "utilities_eur": int(utilities) if utilities > 0 else None,
            "deposit_eur": int(deposit),
            "rooms": float(rooms) if rooms > 0 else None,
            "size_sqm": float(size_sqm) if size_sqm > 0 else None,
            "floor": floor.strip(),
            "furnished": bool(furnished),
            "available_from": available_from.strip(),
            "room_type": room_type,
            "shared_with": int(shared_with) if (room_type == "Shared" and shared_with) else None,
            "included_str": "|".join(included) if included else "",
            "is_sublet": bool(is_sublet),
            "anmeldung_possible": bool(anmeldung_possible),
            "schufa_required": bool(schufa_required),
            "viewing_possible": bool(viewing_possible),
            "viewing_details": viewing_details.strip(),
        }

        missing = [f for f in REQUIRED_POST_FIELDS if post.get(f) in [None, ""]]
        if missing:
            st.error("Missing required fields: " + ", ".join(missing))
            st.markdown("</div>", unsafe_allow_html=True)
            return
        if not re.match(r"^\d{5}$", post["postcode"]):
            st.error("Postcode must be 5 digits.")
            st.markdown("</div>", unsafe_allow_html=True)
            return

        media_paths: List[Tuple[str, str]] = []
        try:
            for f in (images_any or []):
                media_paths.append(("image", save_any_upload_as_image(f, "post_media")))
            for f in (videos or []):
                media_paths.append(("video", save_video(f, "post_media")))
        except Exception as e:
            st.error(str(e))
            st.markdown("</div>", unsafe_allow_html=True)
            return

        create_post(uid, post, media_paths)
        st.success("Published.")
        st.session_state["page"] = "Feed"
        st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)


def page_post_details(uid: int):
    render_navbar("PostDetails", uid=uid)
    post_id = st.session_state.get("post_details_id")
    if not post_id:
        st.session_state["page"] = "Feed"
        st.rerun()

    p = get_post_by_id(int(post_id))
    if not p:
        st.error("Post not found.")
        if st.button("Back"):
            st.session_state["page"] = "Feed"
            st.rerun()
        return

    owner_id = int(p["user_id"])

    st.markdown("<div class='rb-card'>", unsafe_allow_html=True)
    head = st.columns([3, 1], vertical_alignment="center")
    with head[0]:
        st.markdown(f"## {p['title']}")
        st.caption(f"@{p.get('username','')} · {human_time(p.get('created_at',''))}")
    with head[1]:
        if st.button("Back", use_container_width=True):
            st.session_state["page"] = "Feed"
            st.rerun()

    urow = st.columns([0.7, 2.3, 1.1, 1.1, 0.7], vertical_alignment="center")
    with urow[0]:
        show_avatar(p.get("avatar_path", ""), p.get("gender"), 46)
    with urow[1]:
        if st.button(f"{p.get('display_name') or p.get('username')}  (@{p.get('username')})",
                     key=f"pd_open_profile_{post_id}"):
            open_profile(owner_id)
    with urow[2]:
        if owner_id != uid:
            if is_following(uid, owner_id):
                if st.button("Unfollow", key=f"pd_unfollow_{post_id}"):
                    unfollow(uid, owner_id)
                    st.rerun()
            else:
                if st.button("Follow", type="primary", key=f"pd_follow_{post_id}"):
                    follow(uid, owner_id)
                    st.rerun()
    with urow[3]:
        if owner_id != uid:
            if st.button("Message", key=f"pd_msg_{post_id}", use_container_width=True):
                open_chat(owner_id)
    with urow[4]:
        if st.button("⚑", key=f"pd_flag_{post_id}", help="Report listing"):
            open_report("post", int(post_id))

    addr = address_string(p)
    st.markdown(f"**Address:** [{addr}]({google_maps_link(addr)})")
    copy_button(addr, label="Copy address")

    pills = []
    pills.append(chip_html(format_eur(p.get("warm_rent_eur")), dark=True))
    pills.append(chip_html(f"Deposit {format_eur(p.get('deposit_eur'))}"))
    if p.get("utilities_eur"):
        pills.append(chip_html(f"Utilities {format_eur(p.get('utilities_eur'))}"))
    pills.append(chip_html(f"Available {p.get('available_from') or '—'}"))
    pills.append(chip_html("Sublet" if int(p.get("is_sublet", 0)) else "Not sublet"))
    pills.append(chip_html("Anmeldung" if int(p.get("anmeldung_possible", 0)) else "No Anmeldung"))
    pills.append(chip_html("Viewing ✅" if int(p.get("viewing_possible", 1)) else "Viewing ❌"))
    if int(p.get("schufa_required", 0)) == 1:
        pills.append(chip_html("SCHUFA required"))
    st.markdown("".join(pills), unsafe_allow_html=True)

    if p.get("viewing_details"):
        st.caption(f"Viewing details: {p.get('viewing_details')}")

    if p.get("description"):
        st.write("")
        st.markdown("### Description")
        st.write(p["description"])

    media = p.get("media") or []
    if media:
        st.write("")
        st.markdown("### Photos & Videos")
        render_media_slider(media, key_prefix=f"pd_{post_id}")

    included_str = (p.get("included_str") or "").strip()
    if included_str:
        st.write("")
        st.markdown("### Included")
        features = [x.strip() for x in included_str.split("|") if x.strip()]
        st.markdown("".join([chip_html(x) for x in features]), unsafe_allow_html=True)

    st.write("")
    a = st.columns([1.2, 1.2, 2.6], vertical_alignment="center")
    with a[0]:
        liked = is_liked(uid, int(post_id))
        if st.button("🧡 Saved" if liked else "♡ Save", type="primary", use_container_width=True):
            (unlike_post(uid, int(post_id)) if liked else like_post(uid, int(post_id)))
            st.rerun()
    with a[1]:
        st.write(f"Saved: {like_count(int(post_id))}")
    with a[2]:
        if owner_id != uid:
            if st.button("Share to chat", use_container_width=True):
                open_chat(owner_id)

    st.markdown("### Comments")
    with st.form(f"comment_form_{post_id}", clear_on_submit=True):
        txt = st.text_input("Write a comment…")
        send = st.form_submit_button("Post", type="primary")
    if send:
        add_comment(uid, int(post_id), txt)
        st.rerun()

    cmts = fetch_comments(int(post_id), limit=30)
    if not cmts:
        st.caption("No comments yet.")
    else:
        for cmt in reversed(cmts):
            who = cmt.get("display_name") or ("@" + (cmt.get("username") or "user"))
            st.markdown(f"**{who}:** {cmt['text']}")
            st.caption(human_time(cmt["created_at"]))

    if owner_id == uid:
        st.write("")
        with st.expander("Owner actions"):
            if st.button("Delete post"):
                delete_post(uid, int(post_id))
                st.success("Deleted.")
                st.session_state["page"] = "Feed"
                st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)


def page_messages(uid: int):
    render_navbar("Messages", uid=uid)
    st.markdown("<div class='rb-card'>", unsafe_allow_html=True)
    st.markdown("## Messages")

    if st.button("⚑ Report / Support", key="msg_flag"):
        st.session_state["page"] = "Support"
        st.rerun()

    left, right = st.columns([1.1, 2.4], gap="large")

    with left:
        st.caption("Chats")
        conv = get_conversations(uid)
        if not conv:
            st.info("No chats yet.")
        else:
            for c in conv:
                name = c["display_name"] or ("@" + (c["username"] or "user"))
                row = st.columns([0.7, 2.3], vertical_alignment="center")
                with row[0]:
                    show_avatar(c.get("avatar_path", ""), c.get("gender"), 36)
                with row[1]:
                    if st.button(name, key=f"conv_{c['other_id']}", use_container_width=True):
                        st.session_state["dm_user_id"] = c["other_id"]
                        st.rerun()
                st.caption(human_time(c["last_time"]) if c.get("last_time") else "")

        st.write("")
        st.caption("Start a new chat (by username)")
        with st.form("new_chat", clear_on_submit=True):
            to_username = st.text_input("Username", placeholder="e.g. maria_berlin")
            open_btn = st.form_submit_button("Open chat", type="primary")
        if open_btn:
            u = get_user_by_username(to_username)
            if not u:
                st.error("Username not found.")
            else:
                open_chat(int(u["id"]))

    with right:
        other_id = st.session_state.get("dm_user_id")
        if not other_id:
            st.info("Select a chat on the left, or message someone from a listing.")
        else:
            other = get_user(int(other_id))
            top = st.columns([0.7, 2.1, 0.7], vertical_alignment="center")
            with top[0]:
                show_avatar(other.get("avatar_path", ""), other.get("gender"), 44)
            with top[1]:
                st.subheader(f"@{other.get('username','')}")
                if other.get("display_name"):
                    st.caption(other.get("display_name"))
            with top[2]:
                if st.button("⚑", help="Report user", key="msg_user_flag"):
                    open_report("user", int(other_id))

            thread = get_thread(uid, int(other_id))

            chat_box = st.container()
            with chat_box:
                for m in thread[-200:]:
                    me = int(m["sender_id"]) == uid
                    bubble = "rb-bubble-me" if me else "rb-bubble-them"
                    who = "You" if me else (other.get("display_name") or ("@" + other.get("username", "user")))
                    st.markdown(f"<div class='{bubble}'><b>{html_escape(who)}:</b> {html_escape(m['text'])}</div>",
                                unsafe_allow_html=True)
                    st.caption(human_time(m["created_at"]))

            with st.form("send_msg", clear_on_submit=True):
                text = st.text_input("Type a message…")
                sent = st.form_submit_button("Send", type="primary")
            if sent:
                ok, msg = send_message_or_request(uid, int(other_id), text)
                if ok:
                    st.rerun()
                else:
                    st.error(msg)

    st.markdown("</div>", unsafe_allow_html=True)


def page_requests(uid: int):
    render_navbar("Requests", uid=uid)
    st.markdown("<div class='rb-card'>", unsafe_allow_html=True)
    st.markdown("## Requests")

    if st.button("⚑ Report / Support", key="rq_flag"):
        st.session_state["page"] = "Support"
        st.rerun()

    reqs = get_requests_for_user(uid)
    if not reqs:
        st.info("No requests.")
        st.markdown("</div>", unsafe_allow_html=True)
        return

    for r in reqs:
        with st.container(border=True):
            st.markdown(f"**@{r['username']}** · {r['cnt']} message(s)")
            st.caption(human_time(r["last_time"]))
            if st.button("Open", key=f"openrq_{r['sender_id']}", type="primary"):
                st.session_state["rq_sender_id"] = r["sender_id"]
                st.rerun()

    sender_id = st.session_state.get("rq_sender_id")
    if sender_id:
        sender = get_user(int(sender_id))
        st.divider()
        st.subheader(f"Request from @{sender.get('username','')}")
        thread = get_request_thread(uid, int(sender_id))
        for m in thread:
            st.markdown(f"**@{sender.get('username','')}:** {m['text']}")
            st.caption(human_time(m["created_at"]))

        c = st.columns(2)
        if c[0].button("Accept", type="primary", use_container_width=True):
            accept_request(uid, int(sender_id))
            st.session_state["rq_sender_id"] = None
            st.session_state["dm_user_id"] = int(sender_id)
            st.session_state["page"] = "Messages"
            st.rerun()
        if c[1].button("Decline", use_container_width=True):
            decline_request(uid, int(sender_id))
            st.session_state["rq_sender_id"] = None
            st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)


def page_profile(uid: int):
    render_navbar("Profile", uid=uid)
    viewing_id = int(st.session_state.get("selected_profile_id") or uid)
    u = get_user(viewing_id)

    st.markdown("<div class='rb-card'>", unsafe_allow_html=True)
    header = st.columns([1, 3, 2], vertical_alignment="center")
    with header[0]:
        show_avatar(u.get("avatar_path", ""), u.get("gender"), 110)
    with header[1]:
        st.markdown(f"## @{u.get('username','')}")
        if u.get("display_name"):
            st.write(u.get("display_name"))
        if u.get("bio"):
            st.caption(u.get("bio"))
        followers, following = follower_counts(viewing_id)

        posts_count = len(fetch_posts({"user_id": viewing_id}, limit=999))
        st.markdown("".join([
            chip_html(f"{posts_count} Posts"),
            chip_html(f"{followers} Followers"),
            chip_html(f"{following} Following"),
        ]), unsafe_allow_html=True)

    with header[2]:
        if st.button("⚑ Support", use_container_width=True, key="pf_support"):
            st.session_state["page"] = "Support"
            st.rerun()

        if viewing_id != uid:
            if is_following(uid, viewing_id):
                if st.button("Unfollow", use_container_width=True):
                    unfollow(uid, viewing_id)
                    st.rerun()
            else:
                if st.button("Follow", type="primary", use_container_width=True):
                    follow(uid, viewing_id)
                    st.rerun()
            if st.button("Message", use_container_width=True):
                open_chat(viewing_id)
            if st.button("⚑ Report user", use_container_width=True):
                open_report("user", viewing_id)
        else:
            if st.button("Manage Profile", type="primary", use_container_width=True):
                st.session_state["manage_mode"] = True
                st.rerun()
            if st.button("Logout", use_container_width=True):
                logout()
                st.session_state["route"] = "login"
                st.rerun()

    if viewing_id == uid and st.session_state.get("manage_mode"):
        st.divider()
        st.markdown("### Manage Profile")
        with st.form("edit_profile"):
            username = st.text_input("Username", value=u.get("username", ""))
            display_name = st.text_input("Name", value=u.get("display_name", ""))
            bio = st.text_area("Bio", value=u.get("bio", ""), height=120)
            gender = st.selectbox("Gender (optional)", ["", "Male", "Female", "Non-binary", "Prefer not to say"], index=0)

            avatar = st.file_uploader("Profile photo (any image type)", accept_multiple_files=False)
            biopic = st.file_uploader("Bio picture (any image type)", accept_multiple_files=False)

            save = st.form_submit_button("Save", type="primary")

        if save:
            avatar_path = u.get("avatar_path", "") or ""
            bio_pic_path = u.get("bio_pic_path", "") or ""
            try:
                if avatar is not None:
                    avatar_path = save_any_upload_as_image(avatar, "avatars")
                if biopic is not None:
                    bio_pic_path = save_any_upload_as_image(biopic, "bio_pics")

                update_profile(
                    user_id=uid,
                    username=username,
                    display_name=display_name,
                    bio=bio,
                    avatar_path=avatar_path,
                    bio_pic_path=bio_pic_path,
                    gender=(gender if gender else None)
                )
                st.success("Updated.")
                st.session_state["manage_mode"] = False
                st.rerun()
            except Exception as e:
                st.error(str(e))

        if st.button("Close Manage Profile"):
            st.session_state["manage_mode"] = False
            st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)
    st.write("")

    tab_posts, tab_saved, tab_followers, tab_following = st.tabs(["Posts", "Saved", "Followers", "Following"])

    with tab_posts:
        posts = fetch_posts({"user_id": viewing_id}, limit=240)
        if not posts:
            st.info("No posts yet.")
        else:
            cols = st.columns(3, gap="large")
            for i, p in enumerate(posts[:90]):
                with cols[i % 3]:
                    render_listing_card(uid, p, ctx=f"profile_posts_{i}")
                    st.write("")

    with tab_saved:
        if viewing_id != uid:
            st.info("Saved posts are private.")
        else:
            ids = list_saved_posts(uid)
            if not ids:
                st.info("No saved posts yet.")
            else:
                posts2 = []
                for pid in ids[:120]:
                    pp = get_post_by_id(pid)
                    if pp:
                        posts2.append(pp)
                cols = st.columns(3, gap="large")
                for i, p in enumerate(posts2[:90]):
                    with cols[i % 3]:
                        render_listing_card(uid, p, ctx=f"profile_saved_{i}")
                        st.write("")

    with tab_followers:
        flw = list_followers(viewing_id)
        if not flw:
            st.info("No followers yet.")
        else:
            for x in flw:
                row = st.columns([0.7, 3.0, 1.3], vertical_alignment="center")
                with row[0]:
                    show_avatar(x.get("avatar_path", ""), x.get("gender"), 40)
                with row[1]:
                    name = x.get("display_name") or ("@" + (x.get("username") or "user"))
                    if st.button(name, key=f"pf_fol_{viewing_id}_{x['user_id']}"):
                        open_profile(int(x["user_id"]))
                with row[2]:
                    if st.button("Open", key=f"open_fol_{viewing_id}_{x['user_id']}"):
                        open_profile(int(x["user_id"]))

    with tab_following:
        flw = list_following(viewing_id)
        if not flw:
            st.info("Not following anyone yet.")
        else:
            for x in flw:
                row = st.columns([0.7, 3.0, 1.3], vertical_alignment="center")
                with row[0]:
                    show_avatar(x.get("avatar_path", ""), x.get("gender"), 40)
                with row[1]:
                    name = x.get("display_name") or ("@" + (x.get("username") or "user"))
                    if st.button(name, key=f"pf_ing_{viewing_id}_{x['user_id']}"):
                        open_profile(int(x["user_id"]))
                with row[2]:
                    if st.button("Open", key=f"open_ing_{viewing_id}_{x['user_id']}"):
                        open_profile(int(x["user_id"]))


def page_support(uid: int):
    render_navbar("Support", uid=uid)
    st.markdown("<div class='rb-card'>", unsafe_allow_html=True)
    st.markdown("## Support & Feedback")

    avg_r, cnt = app_rating_summary()
    st.caption(f"⭐ {avg_r:.2f}/5 · {cnt} ratings" if cnt else "⭐ No ratings yet")

    tab1, tab2, tab3 = st.tabs(["Contact support", "Suggestions", "Rate app"])

    with tab1:
        with st.form("support_form"):
            subject = st.text_input("Subject")
            message = st.text_area("Message", height=140)
            send = st.form_submit_button("Send", type="primary")
        if send:
            if not subject.strip() or not message.strip():
                st.error("Subject and message required.")
            else:
                create_support_ticket(uid, "support", subject, message)
                st.success("Sent.")

    with tab2:
        with st.form("suggest_form"):
            subject = st.text_input("Title")
            message = st.text_area("Suggestion", height=140)
            send = st.form_submit_button("Submit", type="primary")
        if send:
            if not subject.strip() or not message.strip():
                st.error("Title and details required.")
            else:
                create_support_ticket(uid, "suggestion", subject, message)
                st.success("Submitted.")

    with tab3:
        with st.form("rating_form"):
            rating = st.slider("Rating", 1, 5, 5)
            comment = st.text_area("Comment (optional)", height=120)
            submit = st.form_submit_button("Submit rating", type="primary")
        if submit:
            submit_app_rating(uid, rating, comment)
            st.success("Thanks!")
            st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)


def page_report(uid: int):
    render_navbar("Report", uid=uid)
    target_type = st.session_state.get("report_target")
    target_id = st.session_state.get("report_target_id")
    if not target_type or not target_id:
        st.session_state["page"] = "Feed"
        st.rerun()

    st.markdown("<div class='rb-card'>", unsafe_allow_html=True)
    st.markdown("## Report")
    st.caption(f"Target: {target_type} #{target_id}")

    reason = st.selectbox("Reason", ["Scam", "Wrong info", "Spam", "Unsafe", "Other"])
    details = st.text_area("Details (optional)", height=120)

    c = st.columns(2)
    if c[0].button("Submit", type="primary", use_container_width=True):
        create_report(uid, target_type, int(target_id), reason, details)
        st.success("Submitted.")
        st.session_state["page"] = "Feed"
        st.rerun()

    if c[1].button("Cancel", use_container_width=True):
        st.session_state["page"] = "Feed"
        st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)


# =============================
# ROUTER
# =============================
def app_router(uid: int):
    page = st.session_state.get("page", "Feed")
    if page == "Feed":
        page_feed(uid)
    elif page == "Search":
        page_search(uid)
    elif page == "Post":
        page_post(uid)
    elif page == "PostDetails":
        page_post_details(uid)
    elif page == "Messages":
        page_messages(uid)
    elif page == "Requests":
        page_requests(uid)
    elif page == "Profile":
        page_profile(uid)
    elif page == "Support":
        page_support(uid)
    elif page == "Report":
        page_report(uid)
    else:
        st.session_state["page"] = "Feed"
        st.rerun()


# =============================
# MAIN
# =============================
def main():
    inject_style()
    init_db()

    if not PIL_OK:
        st.warning("For best image support install pillow: pip install pillow")

    st.session_state.setdefault("route", "login")
    st.session_state.setdefault("page", "Feed")

    # Auto-login after refresh/back using URL token
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
    app_router(int(uid))


if __name__ == "__main__":
    main()

