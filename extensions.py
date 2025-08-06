from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from flask_limiter import Limiter
login_manager = LoginManager()
db = SQLAlchemy()
mail = Mail()
