from flask_login import current_user
from sqlalchemy import text
from extensions import db
def has_liked_post(post_id):
    try:
        
        stmt = text("SELECT 1 FROM POST_LIKE WHERE USER_ID = :uid AND POST_ID = :pid")
        with db.engine.connect() as conn:
            result = conn.execute(stmt, {"uid": current_user.id, "pid": post_id}).first()
        return result is not None
    
    except AttributeError:
        return False




