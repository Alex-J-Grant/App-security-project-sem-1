# from flask_limiter import Limiter
# from flask_limiter.util import get_remote_address
# import uuid
# from flask import session
#
# def get_rate_limit_key():
#     if 'user_id' in session:
#         return f"user:{session['user_id']}"
#     if 'session_id' not in session:
#         session['session_id'] = str(uuid.uuid4())
#     return f"session:{session['session_id']}"
#
#
# limiter = Limiter(
#     key_func=get_rate_limit_key,
#     default_limits=["10 per minute"],
# )