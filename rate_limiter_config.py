from flask_limiter import Limiter
from flask_login import current_user
from flask import session

def get_rate_limit_key():
    try:
        return f"user:{current_user.id}"
    except AttributeError:
        return f'session:{session.get("session_id")}'



limiter = Limiter(
    key_func=get_rate_limit_key,
    default_limits=["10 per minute"],
)
