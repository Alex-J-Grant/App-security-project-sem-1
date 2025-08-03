from flask_limiter import Limiter
from flask_login import current_user
from flask import session

#FIXXX when have session id
def get_rate_limit_key():
    try:
        if current_user.id is not None:
            return f"user:{current_user.id}"
    except AttributeError:
        try:
            return f'session:{session['session_id']}'
        except:
            pass



limiter = Limiter(
    key_func=get_rate_limit_key,
    default_limits=["10 per minute"],
)
