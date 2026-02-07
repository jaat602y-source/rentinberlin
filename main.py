# main.py
# Run: streamlit run main.py
#
# ✅ REAL AUTH (Email/Password + Google OAuth + Apple OAuth) using Supabase
# ✅ Mobile-first centered login/signup/reset (no white screen)
# ✅ No fake buttons: Google/Apple redirect to Supabase OAuth (works ONLY after you configure providers in Supabase)
#
# REQUIRED SECRETS (Streamlit Cloud -> App -> Settings -> Secrets):
#   SUPABASE_URL = "https://xxxx.supabase.co"
#   SUPABASE_ANON_KEY = "eyJ..."
#
# REQUIREMENTS (put in requirements.txt):
#   streamlit
#   supabase
#
# IMPORTANT:
# - Google/Apple login will NOT work until you enable/configure them in Supabase Auth -> Providers.
# - Apple provider usually requires a paid Apple Developer account.

import os
import re
import uuid
from typing import Optional

import streamlit as st

try:
    from supabase import create_client, Client
except Exception:
    create_client = None
    Client = None


APP_NAME = "RentinBerlin"
REDIRECT_PATH = "/"
SESSION_KEY = "rb_session"


# -----------------------------
# Utilities
# -----------------------------
def get_base_url() -> str:
    # Streamlit Cloud usually sets this; fallback to relative routing
    return (st.secrets.get("PUBLIC_APP_URL", "") or "").strip().rstrip("/")


def normalize_email(e: str) -> str:
    return (e or "").strip().lower()


def normalize_phone(p: str) -> str:
    p = (p or "").strip()
    p = re.sub(r"[^\d+]", "", p)
    return p[:25]


def valid_password(pw: str) -> bool:
    pw = (pw or "").strip()
    return len(pw) >= 6


def username_rules(u: str) -> Optional[str]:
    u = (u or "").strip()
    if not u:
        return "Username is required."
    if re.match(r"^\d", u):
        return "Username cannot begin with numbers."
    if not re.fullmatch(r"[A-Za-z0-9._]{3,30}", u):
        return "Username must be 3–30 chars and only use letters, numbers, '.' or '_'"
    return None


def set_qp(**kwargs):
    # Works on new & old Streamlit
    try:
        for k, v in kwargs.items():
            st.query_params[k] = v
    except Exception:
        st.experimental_set_query_params(**kwargs)


def get_qp(name: str) -> str:
    try:
        return (st.query_params.get(name) or "").strip()
    except Exception:
        qp = st.experimental_get_query_params()
        return (qp.get(name, [""])[0] or "").strip()


def clear_qp():
    try:
        st.query_params.clear()
    except Exception:
        st.experimental_set_query_params()


# -----------------------------
# Supabase
# -----------------------------
def supabase() -> "Client":
    if create_client is None:
        st.error("Missing dependency: supabase. Add `supabase` to requirements.txt")
        st.stop()

    url = (st.secrets.get("SUPABASE_URL", "") or "").strip()
    key = (st.secrets.get("SUPABASE_ANON_KEY", "") or "").strip()
    if not url or not key:
        st.error("SUPABASE_URL / SUPABASE_ANON_KEY missing in Streamlit Secrets.")
        st.stop()

    # PKCE flow is required to exchange ?code=... on callback
    return create_client(url, key, options={"auth": {"flow_type": "pkce"}})


def store_session(session_obj):
    st.session_state[SESSION_KEY] = session_obj


def clear_session():
    st.session_state.pop(SESSION_KEY, None)
    st.session_state.pop("user", None)


def get_user() -> Optional[dict]:
    return st.session_state.get("user")


def hydrate_user_from_session():
    try:
        sb = supabase()
        sess = st.session_state.get(SESSION_KEY)
        if not sess:
            return
        # Make sure client uses stored tokens
        sb.auth.set_session(sess.get("access_token"), sess.get("refresh_token"))
        u = sb.auth.get_user()
        if u and getattr(u, "user", None):
            st.session_state["user"] = u.user.model_dump() if hasattr(u.user, "model_dump") else dict(u.user)
    except Exception:
        # If anything fails, keep app stable
        return


def handle_oauth_callback():
    # Supabase PKCE flow returns ?code=...
    code = get_qp("code")
    if not code:
        return

    try:
        sb = supabase()
        res = sb.auth.exchange_code_for_session({"auth_code": code})
        # `res.session` shape differs by version; normalize safely
        session_obj = None
        if hasattr(res, "session") and res.session:
            session_obj = res.session
            if hasattr(session_obj, "model_dump"):
                session_obj = session_obj.model_dump()
        elif isinstance(res, dict) and res.get("session"):
            session_obj = res["session"]

        if session_obj:
            store_session(session_obj)
            sb.auth.set_session(session_obj.get("access_token"), session_obj.get("refresh_token"))
            u = sb.auth.get_user()
            if u and getattr(u, "user", None):
                st.session_state["user"] = u.user.model_dump() if hasattr(u.user, "model_dump") else dict(u.user)

        # Clean URL (remove ?code=...)
        clear_qp()
        st.rerun()

    except Exception as e:
        st.error(f"OAuth callback failed: {e}")
        clear_qp()


# -----------------------------
# UI Style (modern + mobile)
# -----------------------------
def inject_style():
    st.markdown(
        """
        <style>
          :root{
            --bg0:#05060b;
            --bg1:#070a14;
            --card: rgba(255,255,255,0.08);
            --card2: rgba(255,255,255,0.06);
            --stroke: rgba(255,255,255,0.14);
            --txt: rgba(255,255,255,0.92);
            --muted: rgba(255,255,255,0.70);
            --muted2: rgba(255,255,255,0.55);
            --glow: rgba(0,229,255,0.16);
          }

          .stApp{
            background:
              radial-gradient(900px 520px at 15% 20%, rgba(0, 229, 255, 0.18), transparent 60%),
              radial-gradient(800px 480px at 85% 18%, rgba(255, 122, 26, 0.20), transparent 62%),
              radial-gradient(900px 720px at 55% 90%, rgba(168, 85, 247, 0.18), transparent 64%),
              linear-gradient(135deg, var(--bg0) 0%, var(--bg1) 45%, #04040a 100%) !important;
          }

          #MainMenu, footer, header { visibility:hidden; }

          section.main > div.block-container{
            max-width: 1100px;
            padding-top: 5vh;
            padding-bottom: 7vh;
          }
          @media (max-width: 900px){
            section.main > div.block-container{ padding-top: 2.5vh; }
          }

          /* Center column wrapper */
          .rb-center{
            max-width: 520px;
            margin: 0 auto;
          }

          /* Glass card */
          div[data-testid="stVerticalBlockBorderWrapper"]{
            background: var(--card2) !important;
            border: 1px solid var(--stroke) !important;
            border-radius: 22px !important;
            backdrop-filter: blur(16px) !important;
            -webkit-backdrop-filter: blur(16px) !important;
            box-shadow: 0 30px 90px rgba(0,0,0,0.42) !important;
          }

          /* Typography */
          .rb-brand{
            text-align:center;
            margin-bottom: 6px;
          }
          .rb-brand img{
            display:block;
            margin: 0 auto;
            border-radius: 18px;
            box-shadow: 0 18px 60px rgba(0,0,0,0.35);
            border: 0 !important;
            outline: none !important;
          }
          .rb-appname{
            font-weight: 950;
            color: var(--txt);
            letter-spacing: 0.2px;
            font-size: 22px;
            margin-top: 10px;
          }
          .rb-sub{
            color: var(--muted);
            font-size: 14px;
            margin-top: 6px;
          }
          .rb-h1{
            font-weight: 950;
            color: var(--txt);
            font-size: 34px;
            margin: 10px 0 0 0;
          }
          @media (max-width: 900px){
            .rb-h1{ font-size: 28px; }
          }

          /* Inputs */
          .stTextInput input{
            height: 46px !important;
            border-radius: 14px !important;
            border: 1px solid rgba(255,255,255,0.16) !important;
            background: rgba(255,255,255,0.08) !important;
            color: var(--txt) !important;
          }
          .stTextInput input::placeholder{ color: var(--muted2) !important; }
          .stTextInput input:focus{
            border-color: rgba(0,229,255,0.55) !important;
            box-shadow: 0 0 0 4px rgba(0,229,255,0.14) !important;
          }

          label, .stMarkdown, .stCaption, .stText, p, li, span {
            color: rgba(255,255,255,0.86) !important;
          }

          /* Buttons */
          .stButton > button{
            border-radius: 14px !important;
            padding: 0.75rem 0.95rem !important;
            font-weight: 950 !important;
            border: 1px solid rgba(255,255,255,0.16) !important;
            background: rgba(255,255,255,0.08) !important;
            color: var(--txt) !important;
          }
          .stButton > button:hover{
            border-color: rgba(255,255,255,0.26) !important;
            background: rgba(255,255,255,0.10) !important;
          }
          .stButton > button[kind="primary"]{
            border: 1px solid rgba(0,229,255,0.45) !important;
            background: linear-gradient(135deg, rgba(0,229,255,0.22), rgba(168,85,247,0.18), rgba(255,122,26,0.16)) !important;
            box-shadow: 0 18px 55px rgba(0,229,255,0.14) !important;
          }

          /* Links */
          a, a:visited { color: rgba(0,229,255,0.92) !important; }

          /* Small helper rows */
          .rb-row{
            display:flex;
            justify-content:space-between;
            gap: 10px;
            align-items:center;
            margin-top: 6px;
          }
          .rb-hint{
            font-size: 12px;
            color: rgba(255,255,255,0.62) !important;
            margin-top: 6px;
          }
          .rb-divider{
            height: 1px;
            background: rgba(255,255,255,0.12);
            margin: 14px 0;
            border-radius: 999px;
          }
        </style>
        """,
        unsafe_allow_html=True,
    )


# -----------------------------
# Pages (Login / Signup / Reset)
# -----------------------------
def brand_header():
    logo_path = os.path.join(os.path.dirname(__file__), "assets", "logo.png")
    st.markdown('<div class="rb-brand">', unsafe_allow_html=True)
    if os.path.exists(logo_path):
        st.image(logo_path, width=84)
    st.markdown(f'<div class="rb-appname">{APP_NAME}</div>', unsafe_allow_html=True)
    st.markdown('<div class="rb-sub">Apartments • Berlin • Fast</div>', unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)


def oauth_button(provider: str, label: str):
    sb = supabase()
    redirect_to = (get_base_url() + REDIRECT_PATH) if get_base_url() else None

    # Supabase will return a URL to redirect to provider login
    try:
        res = sb.auth.sign_in_with_oauth(
            {
                "provider": provider,
                "options": {"redirect_to": redirect_to} if redirect_to else {},
            }
        )

        # res.url varies by version
        url = None
        if hasattr(res, "url"):
            url = res.url
        elif isinstance(res, dict):
            url = res.get("url") or (res.get("data") or {}).get("url")

        if not url:
            st.error("OAuth URL not returned. Check Supabase provider configuration.")
            return

        # Use link-button behavior
        st.link_button(label, url, use_container_width=True)

    except Exception as e:
        st.error(f"{label} failed: {e}")


def page_login():
    st.markdown('<div class="rb-center">', unsafe_allow_html=True)
    with st.container(border=True):
        brand_header()
        st.markdown('<div class="rb-h1">Sign in</div>', unsafe_allow_html=True)
        st.markdown('<div class="rb-hint">Password must be at least 6 characters.</div>', unsafe_allow_html=True)

        with st.form("login_form", clear_on_submit=False):
            email = st.text_input("Email", placeholder="name@email.com")
            password = st.text_input("Password", type="password", placeholder="••••••••")
            submit = st.form_submit_button("Login", type="primary", use_container_width=True)

        st.markdown(
            '<div class="rb-row"><span class="rb-hint"></span><span class="rb-hint">Forgot password?</span></div>',
            unsafe_allow_html=True,
        )
        if st.button("Reset password", use_container_width=True, key="go_reset"):
            st.session_state["route"] = "reset"
            st.rerun()

        st.markdown('<div class="rb-divider"></div>', unsafe_allow_html=True)

        # REAL buttons: they redirect to Supabase OAuth. If provider not configured, it will fail.
        oauth_button("google", "Continue with Google")
        oauth_button("apple", "Continue with Apple")

        st.markdown('<div class="rb-divider"></div>', unsafe_allow_html=True)
        st.markdown(
            '<div class="rb-row"><span class="rb-hint">New to RentinBerlin?</span></div>',
            unsafe_allow_html=True,
        )
        if st.button("Create account", use_container_width=True, key="go_signup"):
            st.session_state["route"] = "signup"
            st.rerun()

        if submit:
            email_n = normalize_email(email)
            if "@" not in email_n:
                st.error("Enter a valid email.")
            elif not valid_password(password):
                st.error("Password must be at least 6 characters.")
            else:
                try:
                    sb = supabase()
                    res = sb.auth.sign_in_with_password({"email": email_n, "password": password})
                    # normalize session
                    sess = None
                    if hasattr(res, "session") and res.session:
                        sess = res.session.model_dump() if hasattr(res.session, "model_dump") else res.session
                    elif isinstance(res, dict) and res.get("session"):
                        sess = res["session"]
                    if not sess:
                        st.error("Login failed. Check email/password.")
                    else:
                        store_session(sess)
                        sb.auth.set_session(sess.get("access_token"), sess.get("refresh_token"))
                        u = sb.auth.get_user()
                        if u and getattr(u, "user", None):
                            st.session_state["user"] = u.user.model_dump() if hasattr(u.user, "model_dump") else dict(u.user)
                        st.session_state["route"] = "app"
                        st.rerun()
                except Exception as e:
                    st.error(f"Login failed: {e}")

    st.markdown("</div>", unsafe_allow_html=True)


def page_signup():
    st.markdown('<div class="rb-center">', unsafe_allow_html=True)
    with st.container(border=True):
        brand_header()
        st.markdown('<div class="rb-h1">Create account</div>', unsafe_allow_html=True)
        st.markdown(
            '<div class="rb-hint">Username cannot begin with numbers. Password: 6+ characters.</div>',
            unsafe_allow_html=True,
        )

        with st.form("signup_form", clear_on_submit=False):
            username = st.text_input("Username", placeholder="e.g. rentin_berlin")
            email = st.text_input("Email", placeholder="name@email.com")
            phone = st.text_input("Phone (optional)", placeholder="+49 …")
            password = st.text_input("Password", type="password", placeholder="••••••••")
            submit = st.form_submit_button("Create account", type="primary", use_container_width=True)

        st.markdown('<div class="rb-divider"></div>', unsafe_allow_html=True)
        oauth_button("google", "Continue with Google")
        oauth_button("apple", "Continue with Apple")

        st.markdown('<div class="rb-divider"></div>', unsafe_allow_html=True)
        if st.button("Back to login", use_container_width=True, key="back_login"):
            st.session_state["route"] = "login"
            st.rerun()

        if submit:
            email_n = normalize_email(email)
            phone_n = normalize_phone(phone)
            err_u = username_rules(username)
            if err_u:
                st.error(err_u)
            elif "@" not in email_n:
                st.error("Enter a valid email.")
            elif not valid_password(password):
                st.error("Password must be at least 6 characters.")
            else:
                try:
                    sb = supabase()
                    # Store profile fields in user_metadata so you have them after login
                    res = sb.auth.sign_up(
                        {
                            "email": email_n,
                            "password": password,
                            "options": {
                                "data": {
                                    "username": username.strip(),
                                    "phone": phone_n,
                                }
                            },
                        }
                    )
                    st.success("Account created. Check your email if confirmation is required, then login.")
                    st.session_state["route"] = "login"
                    st.rerun()
                except Exception as e:
                    st.error(f"Signup failed: {e}")

    st.markdown("</div>", unsafe_allow_html=True)


def page_reset():
    st.markdown('<div class="rb-center">', unsafe_allow_html=True)
    with st.container(border=True):
        brand_header()
        st.markdown('<div class="rb-h1">Reset password</div>', unsafe_allow_html=True)
        st.markdown('<div class="rb-hint">We will send a reset link to your email.</div>', unsafe_allow_html=True)

        with st.form("reset_form", clear_on_submit=False):
            email = st.text_input("Email", placeholder="name@email.com")
            submit = st.form_submit_button("Send reset email", type="primary", use_container_width=True)

        if st.button("Back to login", use_container_width=True, key="back_login2"):
            st.session_state["route"] = "login"
            st.rerun()

        if submit:
            email_n = normalize_email(email)
            if "@" not in email_n:
                st.error("Enter a valid email.")
            else:
                try:
                    sb = supabase()
                    # Supabase sends recovery email using your Auth email templates
                    sb.auth.reset_password_for_email(email_n)
                    st.success("Reset email sent. Open your inbox.")
                except Exception as e:
                    st.error(f"Reset failed: {e}")

    st.markdown("</div>", unsafe_allow_html=True)


# -----------------------------
# App (protected)
# -----------------------------
def page_app():
    user = get_user()
    st.markdown('<div class="rb-center">', unsafe_allow_html=True)
    with st.container(border=True):
        st.markdown(f'<div class="rb-h1">Welcome</div>', unsafe_allow_html=True)
        if user:
            st.write("You are logged in as:")
            st.code(user.get("email", ""), language="text")
        st.markdown('<div class="rb-divider"></div>', unsafe_allow_html=True)

        c1, c2 = st.columns(2)
        with c1:
            if st.button("Logout", use_container_width=True):
                try:
                    sb = supabase()
                    sb.auth.sign_out()
                except Exception:
                    pass
                clear_session()
                clear_qp()
                st.session_state["route"] = "login"
                st.rerun()
        with c2:
            st.link_button("Open Supabase Auth settings", "https://supabase.com/dashboard", use_container_width=True)

    st.markdown("</div>", unsafe_allow_html=True)


# -----------------------------
# Main Router
# -----------------------------
def main():
    st.set_page_config(page_title=APP_NAME, page_icon="🏠", layout="centered")
    inject_style()

    st.session_state.setdefault("route", "login")

    # If user returned from Google/Apple, handle ?code=... once
    handle_oauth_callback()

    # Try hydrate from stored session (keeps user logged in on refresh)
    if st.session_state.get(SESSION_KEY) and not st.session_state.get("user"):
        hydrate_user_from_session()

    if st.session_state.get("user"):
        st.session_state["route"] = "app"

    route = st.session_state.get("route", "login")

    if route == "signup":
        page_signup()
    elif route == "reset":
        page_reset()
    elif route == "app":
        page_app()
    else:
        st.session_state["route"] = "login"
        page_login()


if __name__ == "__main__":
    main()

