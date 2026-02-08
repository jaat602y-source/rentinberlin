# rent_site/features/auth/routes.py
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required
from flask_login import current_user

from rent_site.features.auth.service import (
    create_user, authenticate_user,
    create_reset_token, verify_reset_token, set_new_password
)

auth_bp = Blueprint("auth", __name__, template_folder="templates")

@auth_bp.get("/login")
def login():
    return render_template("auth/login.html", auth_page="login")

@auth_bp.post("/login")
def login_post():
    email = request.form.get("email", "")
    password = request.form.get("password", "")
    user, msg = authenticate_user(email, password)
    if not user:
        flash(msg, "error")
        return redirect(url_for("auth.login"))
    login_user(user, remember=True)
    flash("Logged in successfully.", "success")
    return redirect(url_for("home.home"))

@auth_bp.get("/signup")
def signup():
    return render_template("auth/signup.html", auth_page="signup")

@auth_bp.post("/signup")
def signup_post():
    full_name = request.form.get("full_name", "").strip() or None
    email = request.form.get("email", "")
    password = request.form.get("password", "")
    ok, msg = create_user(email, password, full_name)
    flash(msg, "success" if ok else "error")
    return redirect(url_for("auth.login" if ok else "auth.signup"))

@auth_bp.get("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.", "success")
    return redirect(url_for("home.home"))

@auth_bp.get("/reset")
def reset_request():
    return render_template("auth/reset.html")

@auth_bp.post("/reset")
def reset_request_post():
    email = (request.form.get("email", "") or "").strip().lower()
    # We generate a token and show a link on screen (no email sending yet).
    if not email:
        flash("Please enter your email.", "error")
        return redirect(url_for("auth.reset_request"))

    token = create_reset_token(email)
    reset_link = url_for("auth.reset_confirm", token=token, _external=True)
    flash("Reset link generated (demo mode). Copy it below.", "success")
    return render_template("auth/reset_link.html", reset_link=reset_link)

@auth_bp.get("/reset/<token>")
def reset_confirm(token: str):
    email = verify_reset_token(token)
    if not email:
        flash("Reset link is invalid or expired.", "error")
        return redirect(url_for("auth.reset_request"))
    return render_template("auth/reset_confirm.html", token=token)

@auth_bp.post("/reset/<token>")
def reset_confirm_post(token: str):
    email = verify_reset_token(token)
    if not email:
        flash("Reset link is invalid or expired.", "error")
        return redirect(url_for("auth.reset_request"))

    new_password = request.form.get("password", "")
    if len(new_password) < 6:
        flash("Password must be at least 6 characters.", "error")
        return redirect(url_for("auth.reset_confirm", token=token))

    ok, msg = set_new_password(email, new_password)
    flash(msg, "success" if ok else "error")
    return redirect(url_for("auth.login"))

@auth_bp.get("/oauth/google")
def oauth_google():
    flash("Google login will be added soon (OAuth setup needed).", "error")
    return redirect(url_for("auth.login"))

@auth_bp.get("/oauth/apple")
def oauth_apple():
    flash("Apple login will be added soon (OAuth setup needed).", "error")
    return redirect(url_for("auth.login"))

@auth_bp.get("/oauth/facebook")
def oauth_facebook():
    flash("Facebook login will be added soon (OAuth setup needed).", "error")
    return redirect(url_for("auth.login"))

