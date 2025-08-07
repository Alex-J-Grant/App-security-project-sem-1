from functools import wraps
from flask import render_template
from flask_login import current_user

def banneduser(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_active:
            return render_template('503.html')
        return f(*args, **kwargs)
    return decorated_function

