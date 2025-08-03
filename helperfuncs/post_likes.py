from flask_login import current_user
from sqlalchemy import text
from extensions import db
def has_liked_post(user_id, post_id):
    stmt = text("SELECT 1 FROM POST_LIKE WHERE USER_ID = :uid AND POST_ID = :pid")
    with db.engine.connect() as conn:
        result = conn.execute(stmt, {"uid": user_id, "pid": post_id}).first()
    return result is not None

def like_post(user_id, post_id):
    # Returns new like count or None on failure
    with db.engine.begin() as conn:  # transaction
        # Try insert; ignore if already exists
        insert_stmt = text("""
            INSERT IGNORE INTO POST_LIKE (USER_ID, POST_ID)
            VALUES (:uid, :pid)
        """)
        res = conn.execute(insert_stmt, {"uid": user_id, "pid": post_id})
        if res.rowcount == 0:
            # already liked
            return None
        # increment counter
        update_stmt = text("""
            UPDATE POST
            SET LIKE_COUNT = LIKE_COUNT + 1
            WHERE POST_ID = :pid
        """)
        conn.execute(update_stmt, {"pid": post_id})
        # fetch updated count
        select_stmt = text("SELECT LIKE_COUNT FROM POST WHERE POST_ID = :pid")
        row = conn.execute(select_stmt, {"pid": post_id}).first()
    return row["LIKE_COUNT"] if row else None

def unlike_post(user_id, post_id):
    with db.engine.begin() as conn:
        delete_stmt = text("""
            DELETE FROM POST_LIKE
            WHERE USER_ID = :uid AND POST_ID = :pid
        """)
        res = conn.execute(delete_stmt, {"uid": user_id, "pid": post_id})
        if res.rowcount == 0:
            # wasn't liked
            return None
        update_stmt = text("""
            UPDATE POST
            SET LIKE_COUNT = GREATEST(LIKE_COUNT - 1, 0)
            WHERE POST_ID = :pid
        """)
        conn.execute(update_stmt, {"pid": post_id})
        select_stmt = text("SELECT LIKE_COUNT FROM POST WHERE POST_ID = :pid")
        row = conn.execute(select_stmt, {"pid": post_id}).first()
    return row["LIKE_COUNT"] if row else None
