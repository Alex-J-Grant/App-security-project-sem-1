from flask_login import current_user
from sqlalchemy import text
from extensions import db


def has_joined_comm(comm_id):
    try:

        stmt = text("SELECT 1 FROM COMMUNITY_MEMBERS WHERE USER_ID = :uid AND COMMUNITY_ID = :cid")
        with db.engine.connect() as conn:
            result = conn.execute(stmt, {"uid": current_user.id, "cid": comm_id}).first()
        return result is not None

    except AttributeError:
        return False
