from extensions import db
from datetime import datetime, timezone

class Usersession(db.Model):
    __tablename__ = 'USERSESSION'
    session_id = db.Column('SESS_ID', db.String(255), primary_key = True)
    user_id = db.Column('USER_ID', db.String(50), nullable = True)
    created_at = db.Column('CREATED_AT', db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable = False)
    last_active = db.Column('LAST_ACTIVE', db.DateTime(timezone=True), default = lambda: datetime.now(timezone.utc), onupdate = lambda: datetime.now(timezone.utc), nullable = False)

