import shelve
import html
from flask import *
from functools import *

app = Flask(__name__, static_folder="static")

def get_role():
    user_id=session.get("user_id",{})
    with shelve.open('database/user_database/user.db') as db:
        users = db.get('Users', {})
        try:
            user = users[user_id]
            role = str(user.role)
        except TypeError:
            role = "not_signed_in"
    return role

# weifeng decorator for RBA
#done by weifeng
def role_required(required_role):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user_id = session.get('user_id', False)
            try:
                with shelve.open('database/user_database/user.db') as db:
                    users = db.get('Users', {})
                    user = users[user_id]
                    role = str(user.role)
                if user_id and not role == required_role:
                    return render_template('403.html')
                return func(*args, **kwargs)
            except (IOError, KeyError):
                return render_template('503.html')

        return wrapper

    return decorator

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404


# Error handler for 500 - Internal Server Error
#Done by Alexander
@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500


@app.route("/")
def home():

    return render_template('home.html')








if __name__ == '__main__':
    app.run()









