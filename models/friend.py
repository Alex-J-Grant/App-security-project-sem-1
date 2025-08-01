# models/friend.py
from extensions import db
from datetime import datetime
from sqlalchemy import Enum


class FriendRequest(db.Model):
    __tablename__ = 'FRIEND_REQ'

    ID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    SENDER_ID = db.Column(db.String(50), db.ForeignKey('USERS.USER_ID'), nullable=False)
    RECV_ID = db.Column(db.String(50), db.ForeignKey('USERS.USER_ID'), nullable=False)
    STATUS = db.Column(Enum('pending', 'accepted', 'rejected', name='request_status'), default='pending')
    CREATED_AT = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    sender = db.relationship('User', foreign_keys=[SENDER_ID], backref='sent_requests')
    receiver = db.relationship('User', foreign_keys=[RECV_ID], backref='received_requests')

    def __repr__(self):
        return f'<FriendRequest {self.SENDER_ID} -> {self.RECV_ID}: {self.STATUS}>'


class Friend(db.Model):
    __tablename__ = 'FRIENDS'

    USER_ID = db.Column(db.String(50), db.ForeignKey('USERS.USER_ID'), primary_key=True)
    FRIEND_ID = db.Column(db.String(50), db.ForeignKey('USERS.USER_ID'), primary_key=True)
    CREATED_AT = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Friendship {self.USER_ID} <-> {self.FRIEND_ID}>'


class Message(db.Model):
    __tablename__ = 'MESSAGES'

    ID = db.Column(db.String(50), primary_key=True)
    SENDER_ID = db.Column(db.String(50), db.ForeignKey('USERS.USER_ID'), nullable=False)
    RECV_ID = db.Column(db.String(50), db.ForeignKey('USERS.USER_ID'), nullable=False)
    CONTENT = db.Column(db.Text, nullable=False)
    CREATED_AT = db.Column(db.DateTime, default=datetime.utcnow)
    IS_READ = db.Column(db.Boolean, default=False)

    # Relationships
    sender = db.relationship('User', foreign_keys=[SENDER_ID], backref='sent_messages')
    receiver = db.relationship('User', foreign_keys=[RECV_ID], backref='received_messages')

    def __repr__(self):
        return f'<Message {self.SENDER_ID} -> {self.RECV_ID}: {self.CONTENT[:30]}...>'