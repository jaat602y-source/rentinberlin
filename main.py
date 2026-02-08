# rent_site/main.py
from flask import Flask
from rent_site.config import Config
from rent_site.core.db import init_db, SessionLocal
from rent_site.core.auth import init_auth
from rent_site.core.errors import register_error_handlers

def create_app():
    app = Flask(
        __name__,
        template_folder="shared_ui/templates",
        static_folder="shared_ui/static",
        static_url_path="/static",
    )
    app.config.from_object(Config)

    # Init DB + auth
    init_db()
    init_auth(app)
    register_error_handlers(app)

    # Clean DB sessions per request
    @app.teardown_appcontext
    def shutdown_session(exception=None):
        SessionLocal.remove()

    # Register blueprints
    from rent_site.features.auth.routes import auth_bp
    from rent_site.features.home.routes import home_bp
    from rent_site.features.listings.routes import listings_bp
    from rent_site.features.explore.routes import explore_bp
    from rent_site.features.messages.routes import messages_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(home_bp)
    app.register_blueprint(listings_bp)
    app.register_blueprint(explore_bp)
    app.register_blueprint(messages_bp)

    return app

app = create_app()

if __name__ == "__main__":
    app.run(debug=Config.DEBUG)
