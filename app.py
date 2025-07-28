from flask import Flask
import shelve
import html
from flask import *
from functools import *
from flask_mail import Mail, Message
from ff3 import FF3Cipher
import os
import google.generativeai as genai
from datetime import datetime
import markdown
import bleach
# from routes import
from extensions import db
# from routes import
from routes.test import testbp
from helperfuncs.error_handling import register_error_handlers
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from routes.home import homebp
from routes.chatbot import chatbot
from routes.posts import *
from flask_session import Session
def create_app():
    app =Flask(__name__, static_folder = "static")

    app.config.from_mapping(
        # need to change key very important 
        SECRET_KEY="SECRET",
        SQLALCHEMY_DATABASE_URI="mysql+pymysql://developer:temppassword@localhost:3306/app_sec_db",
        SQLALCHEMY_TRACK_MODIFICATIONS=False

    )
    #make sure uploads are not too big for server
    app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024
    #ensure only image files uploaded
    app.config['UPLOAD_EXTENSIONS'] = ['.jpg', '.png', '.gif','.jpeg']
    db.init_app(app)
    # register blueprints here for your routes
    app.register_blueprint(homebp)
    app.register_blueprint(chatbot)
    app.register_blueprint(view_post)
    app.register_blueprint(community)
    app.register_blueprint(testbp)
    app.register_blueprint(create_post)
    register_error_handlers(app)

    return app


if __name__ == '__main__':
    app = create_app()
    app.run()










