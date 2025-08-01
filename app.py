from flask import Flask
from extensions import login_manager
from routes.test import testbp
from helperfuncs.error_handling import register_error_handlers
from routes.home import homebp
from routes.chatbot import chatbot
from routes.posts import *
from routes.community import *
from routes.acc import *
from routes.profile import *
from routes.friends import friends  # ADD THIS LINE
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
from models.user import User  # ADD THIS LINE
from security.friends_owasp_security import initialize_friends_security



def create_app():
    app = Flask(__name__, static_folder="static")

    app.config.from_mapping(
        # need to change key very important
        SECRET_KEY="SECRET",
        SQLALCHEMY_DATABASE_URI="mysql+pymysql://developer:temppassword@localhost:3306/app_sec_db",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        MAX_CONTENT_LENGTH=3 * 1024 * 1024,
        UPLOAD_EXTENSIONS=['.jpg', '.png', '.gif', '.jpeg'],
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPSONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        REMEMBER_COOKIE_SECURE='True'
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

    Talisman(app, force_https=True, content_security_policy=csp)
    login_manager.init_app(app)
    login_manager.login_view = 'account.login'

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(user_id)  # Updated to use .get() instead of db.session.get()

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
    app.register_blueprint(friends)  # ADD THIS LINE
    register_error_handlers(app)

    initialize_friends_security(app)


    return app


if __name__ == '__main__':
    app = create_app()
<<<<<<< Updated upstream
    app.run(ssl_context=('cert.pem', 'key.pem'))
=======
    app.run(ssl_context=('cert.pem', 'key.pem'))









>>>>>>> Stashed changes
