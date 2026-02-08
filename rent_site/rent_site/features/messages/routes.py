# rent_site/features/messages/routes.py
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user

from rent_site.features.messages.service import get_threads_for_user, get_thread, add_message

messages_bp = Blueprint("messages", __name__, template_folder="templates")

@messages_bp.get("/messages")
@login_required
def inbox():
    threads = get_threads_for_user(current_user.id)
    return render_template("messages/inbox.html", threads=threads)

@messages_bp.get("/messages/<int:thread_id>")
@login_required
def thread(thread_id: int):
    t = get_thread(thread_id)
    if not t:
        return render_template("errors/404.html"), 404
    # simple permission check
    if current_user.id not in (t.user1_id, t.user2_id):
        flash("Not allowed.", "error")
        return redirect(url_for("messages.inbox"))
    return render_template("messages/thread.html", thread=t)

@messages_bp.post("/messages/<int:thread_id>")
@login_required
def thread_post(thread_id: int):
    body = request.form.get("body", "").strip()
    if not body:
        return redirect(url_for("messages.thread", thread_id=thread_id))
    t = get_thread(thread_id)
    if not t or current_user.id not in (t.user1_id, t.user2_id):
        flash("Not allowed.", "error")
        return redirect(url_for("messages.inbox"))
    add_message(thread_id, current_user.id, body)
    return redirect(url_for("messages.thread", thread_id=thread_id))
