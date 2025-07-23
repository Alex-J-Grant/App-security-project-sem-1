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
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from routes.home import homebp
from routes.chatbot import chatbot
from routes.posts import *
from flask_session import Session

def create_app():
    app =Flask(__name__, static_folder = "static")

    app.config.from_mapping(
        # NEEDS TO BE CHANGED VERY IMPORTANT 
        SECRET_KEY = "SECRET"
    #     U GUYS NEED TO SET YOUR OWN DATABASE LINK SINCE WE ARE ALL USING A LOCAL SQL SERVER
    #     DATABASE = 
    )

    # register blueprints here for your routes
    app.register_blueprint(homebp)
    app.register_blueprint(chatbot)
    app.register_blueprint(view_post)
    app.register_blueprint(community)

    return app

#
# def get_role():
#     user_id=session.get("user_id",{})
#     with shelve.open('database/user_database/user.db') as db:
#         users = db.get('Users', {})
#         try:
#             user = users[user_id]
#             role = str(user.role)
#         except TypeError:
#             role = "not_signed_in"
#     return role
#
# # weifeng decorator for RBA
# #done by weifeng
# def role_required(required_role):
#     def decorator(func):
#         @wraps(func)
#         def wrapper(*args, **kwargs):
#             user_id = session.get('user_id', False)
#             try:
#                 with shelve.open('database/user_database/user.db') as db:
#                     users = db.get('Users', {})
#                     user = users[user_id]
#                     role = str(user.role)
#                 if user_id and not role == required_role:
#                     return render_template('403.html')
#                 return func(*args, **kwargs)
#             except (IOError, KeyError):
#                 return render_template('503.html')
#
#         return wrapper
#
#     return decorator
#
# @app.errorhandler(404)
# def not_found_error(error):
#     return render_template('404.html'), 404
#
#
# # Error handler for 500 - Internal Server Error
# #Done by Alexander
# @app.errorhandler(500)
# def internal_error(error):
#     return render_template('500.html'), 500
#
#
#
#
#
#
#
#
#



if __name__ == '__main__':
    app = create_app()
    app.run()










