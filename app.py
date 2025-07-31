from flask import Flask
from extensions import db
from extensions import login_manager
from routes.test import testbp
from helperfuncs.error_handling import register_error_handlers
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from routes.home import homebp
from routes.chatbot import chatbot
from routes.posts import *
from routes.community import *
from routes.acc import *
from routes.profile import *
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
import secrets
from flask import g

def create_app():
    app =Flask(__name__, static_folder = "static")

    app.config.from_mapping(
        # need to change key very important 
        SECRET_KEY="SECRET",
        SQLALCHEMY_DATABASE_URI="mysql+pymysql://developer:temppassword@localhost:3306/app_sec_db",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        MAX_CONTENT_LENGTH = 16 * 1024 * 1024,
        UPLOAD_EXTENSIONS = ['.jpg', '.png', '.gif', '.jpeg'],
        SESSION_COOKIE_SECURE = True,
        SESSION_COOKIE_HTTPSONLY = True,
        SESSION_COOKIE_SAMESITE = 'Lax',
        REMEMBER_COOKIE_SECURE = 'True'

    )


    csp = {
        'script-src': [
            "'self'",
            'https://cdn.jsdelivr.net',
            'https://code.jquery.com',
            'https://ajax.googleapis.com',
            "'unsafe-inline'"  # Required for some Bootstrap styles

        ],
        'style-src': [
            "'self'",
            'https://cdn.jsdelivr.net',
            "'unsafe-inline'"  # Required for some Bootstrap styles
        ],
        'font-src': [
            "'self'",
            'https://cdn.jsdelivr.net'
        ],
        'img-src': [
            "'self'", 'data:'
        ]
    }
    Talisman(app, force_https = True,content_security_policy=csp)
    login_manager.init_app(app)
    login_manager.login_view = 'account.login'
    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, user_id)
    db.init_app(app)
    # Enable CSRF protection
    csrf = CSRFProtect(app)

    # register blueprints here for your routes
    app.register_blueprint(account)
    app.register_blueprint(homebp)
    app.register_blueprint(chatbot)
    app.register_blueprint(view_post)
    app.register_blueprint(community)
    app.register_blueprint(create_community)
    app.register_blueprint(testbp)
    app.register_blueprint(create_post)
    app.register_blueprint(profile)
    register_error_handlers(app)


    return app


if __name__ == '__main__':
    app = create_app()
    app.run(ssl_context=('cert.pem', 'key.pem'))










