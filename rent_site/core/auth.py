# rent_site/core/auth.py
from flask_login import LoginManager
from rent_site.core.db import get_db
from rent_site.core.models import User

login_manager = LoginManager()
login_manager.login_view = "auth.login"

def init_auth(app):
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id: str):
        db = get_db()
        return db.get(User, int(user_id))
