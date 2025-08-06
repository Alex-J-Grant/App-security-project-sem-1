from extensions import db 
from datetime import datetime, timezone
from helperfuncs.uuidgen import gen_uuid

class BanReq(db.Model):
    __tablename__ = 'BANREQ'
    banid = db.Column('BAN_ID', db.String(50), primary_key = True, unique = True, nullable = False, default= gen_uuid)
    userid = db.Column('USER_ID', db.String(50), db.ForeignKey('USERS.USER_ID'), nullable = False)
    reason = db.Column('REASON', db.Text, nullable = False)
    createdat = db.Column('CREATED_AT', db.DateTime(timezone = True), default=lambda: datetime.now(timezone.utc), nullable = False)
    handled = db.Column('HANDLED', db.Boolean, default = False)
    user = db.relationship('User', backref = 'ban_requests')
