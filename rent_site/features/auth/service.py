# rent_site/features/auth/service.py
from __future__ import annotations
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask import current_app

from rent_site.core.db import get_db
from rent_site.core.models import User
from rent_site.core.security import hash_password, verify_password

def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt="rent-reset")

def create_user(email: str, password: str, full_name: str | None) -> tuple[bool, str]:
    email = (email or "").strip().lower()
    if not email or not password:
        return False, "Email and password are required."

    db = get_db()
    existing = db.query(User).filter(User.email == email).first()
    if existing:
        return False, "This email is already registered."

    user = User(email=email, password_hash=hash_password(password), full_name=(full_name or None))
    db.add(user)
    db.commit()
    return True, "Account created. Please log in."

def authenticate_user(email: str, password: str) -> tuple[User | None, str]:
    email = (email or "").strip().lower()
    db = get_db()
    user = db.query(User).filter(User.email == email).first()
    if not user:
        return None, "Invalid email or password."
    if not verify_password(password, user.password_hash):
        return None, "Invalid email or password."
    if not user.is_active:
        return None, "Your account is disabled."
    return user, "OK"

def create_reset_token(email: str) -> str:
    return _serializer().dumps({"email": email.strip().lower()})

def verify_reset_token(token: str, max_age_seconds: int = 3600) -> str | None:
    try:
        data = _serializer().loads(token, max_age=max_age_seconds)
        return data.get("email")
    except (BadSignature, SignatureExpired):
        return None

def set_new_password(email: str, new_password: str) -> tuple[bool, str]:
    db = get_db()
    user = db.query(User).filter(User.email == email).first()
    if not user:
        return False, "User not found."
    user.password_hash = hash_password(new_password)
    db.commit()
    return True, "Password updated. Please log in."
