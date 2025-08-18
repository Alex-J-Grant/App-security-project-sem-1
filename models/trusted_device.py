# models/trusted_device.py
from extensions import db
from datetime import datetime, timezone

class TrustedDevice(db.Model):
    __tablename__ = 'trusted_devices'

    id = db.Column(db.Integer, primary_key=True)
    device_token = db.Column(db.String(64), unique=True, nullable=False)
    verified = db.Column(db.Boolean, default=False)   # starts as False
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    verified_at = db.Column(db.DateTime)

class UserTrustedDevice(db.Model):
    __tablename__ = 'user_trusted_devices'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String, db.ForeignKey('USERS.USER_ID'), nullable=False)
    device_id = db.Column(db.Integer, db.ForeignKey('trusted_devices.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
