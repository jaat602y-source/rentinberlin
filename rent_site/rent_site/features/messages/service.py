# rent_site/features/messages/service.py
from datetime import datetime
from rent_site.core.db import get_db
from rent_site.core.models import Thread, Message

def get_threads_for_user(user_id: int):
    db = get_db()
    return (
        db.query(Thread)
        .filter((Thread.user1_id == user_id) | (Thread.user2_id == user_id))
        .order_by(Thread.updated_at.desc())
        .all()
    )

def get_thread(thread_id: int):
    db = get_db()
    return db.get(Thread, thread_id)

def add_message(thread_id: int, sender_id: int, body: str):
    db = get_db()
    msg = Message(thread_id=thread_id, sender_id=sender_id, body=body.strip())
    db.add(msg)

    thread = db.get(Thread, thread_id)
    if thread:
        thread.last_message_preview = (body.strip()[:180] if body else "")
        thread.updated_at = datetime.utcnow()

    db.commit()
