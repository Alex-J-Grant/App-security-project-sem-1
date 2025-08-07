from flask import Flask
from extensions import db
from extensions import login_manager,mail
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
from routes.search import *
from routes.friends import friends  # ADD THIS LINE
from routes.users import users  # ADD THIS LINE
<<<<<<< HEAD
from routes.pages import pages
=======
from routes.admin import adminbp
>>>>>>> weifeng
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
from models.user import User  # ADD THIS LINE
from models.session import *
from security.friends_owasp_security import initialize_friends_security  # ADD THIS LINE
from routes.comments import comments
from dotenv import load_dotenv
from datetime import timedelta

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
        REMEMBER_COOKIE_SECURE = True,
        SESSION_TYPE = 'sqlalchemy',
        SESSION_SQLALCHEMY = db,
        MAIL_SERVER='smtp.gmail.com',
        MAIL_PORT=587,
        MAIL_USE_SSL=False,
        MAIL_USE_TLS=True,
        MAIL_USERNAME=os.getenv('EMAIL'),
        MAIL_PASSWORD=os.getenv('EMAIL_PASSWORD'),  # must be a Gmail app password
        MAIL_DEFAULT_SENDER=os.getenv('EMAIL'),
        REMEMBER_COOKIE_DURATION = timedelta(days=7)


    )


    csp = {
        'script-src': [
            "'self'",
            'https://cdn.jsdelivr.net',
            'https://code.jquery.com',
            'https://ajax.googleapis.com',
            'https://stackpath.bootstrapcdn.com',
            'https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js',
            "'unsafe-inline'"  # Required for some Bootstrap styles

        ],
        'style-src': [
            "'self'",
            'https://cdn.jsdelivr.net',
            'https://stackpath.bootstrapcdn.com',
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
        return User.query.get(user_id)  # CHANGED: Use .get() instead of db.session.get()
    db.init_app(app)
    sess = Session(app)
    # Enable CSRF protection
    csrf = CSRFProtect(app)
<<<<<<< HEAD
    app.config.update(
        MAIL_SERVER='smtp.gmail.com',
        MAIL_PORT=587,
        MAIL_USE_SSL=False,
        MAIL_USE_TLS=True,
        MAIL_USERNAME=os.getenv('EMAIL'),
        MAIL_PASSWORD=os.getenv('EMAIL_PASSWORD'),
        MAIL_DEFAULT_SENDER=os.getenv('EMAIL'),
    )
=======
>>>>>>> weifeng
    mail.init_app(app)

    limiter.init_app(app)


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
    app.register_blueprint(search_bp)
    app.register_blueprint(friends)  # ADD THIS LINE
    app.register_blueprint(users)  # ADD THIS LINE
    app.register_blueprint(pages)
    app.register_blueprint(comments)
    app.register_blueprint(like_bp)
    app.register_blueprint(adminbp)
    register_error_handlers(app)

    # Initialize OWASP security features
    initialize_friends_security(app)  # ADD THIS LINE

    return app


if __name__ == '__main__':
    app = create_app()
    app.run(ssl_context=('cert.pem', 'key.pem'), debug=True)
