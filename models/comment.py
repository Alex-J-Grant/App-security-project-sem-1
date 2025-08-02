# models/comment.py
from extensions import db
from datetime import datetime


class Comment(db.Model):
    __tablename__ = 'COMMENTS'

    COMMENT_ID = db.Column(db.String(50), primary_key=True)
    POST_ID = db.Column(db.String(50), db.ForeignKey('POST.POST_ID'), nullable=False)
    USER_ID = db.Column(db.String(50), db.ForeignKey('USERS.USER_ID'), nullable=False)
    CONTENT = db.Column(db.Text, nullable=False)
    LIKE_COUNT = db.Column(db.Integer, default=0)
    CREATED_AT = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    user = db.relationship('User', backref='comments')
    replies = db.relationship('Reply', backref='comment', cascade='all, delete-orphan')

    def __repr__(self):
        return f'<Comment {self.COMMENT_ID}: {self.CONTENT[:30]}...>'


class Reply(db.Model):
    __tablename__ = 'REPLIES'

    REPLY_ID = db.Column(db.String(50), primary_key=True)
    COMMENT_ID = db.Column(db.String(50), db.ForeignKey('COMMENTS.COMMENT_ID'), nullable=False)
    USER_ID = db.Column(db.String(50), db.ForeignKey('USERS.USER_ID'), nullable=False)
    CONTENT = db.Column(db.Text, nullable=False)
    LIKE_COUNT = db.Column(db.Integer, default=0)
    CREATED_AT = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    user = db.relationship('User', backref='replies')

    def __repr__(self):
        return f'<Reply {self.REPLY_ID}: {self.CONTENT[:30]}...>'