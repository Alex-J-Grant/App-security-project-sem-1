from functools import wraps
from flask import render_template, flash
from flask_login import current_user

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role != 'Admin':
            return render_template('503.html')
        return f(*args, **kwargs)
    return decorated_function

