# models/contact.py
from extensions import db
from datetime import datetime


class ContactMessage(db.Model):
    __tablename__ = 'CONTACT_MESSAGES'

    ID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    FIRST_NAME = db.Column(db.String(50), nullable=False)
    LAST_NAME = db.Column(db.String(50), nullable=False)
    EMAIL = db.Column(db.String(255), nullable=False)
    CATEGORY = db.Column(db.Enum('security', 'bug', 'technical', 'account', 'feature', 'general'), nullable=False)
    SUBJECT = db.Column(db.String(200), nullable=False)
    MESSAGE = db.Column(db.Text, nullable=False)
    STATUS = db.Column(db.Enum('new', 'in_progress', 'resolved'), default='new')
    CREATED_AT = db.Column(db.DateTime, default=datetime.utcnow)
    UPDATED_AT = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<ContactMessage {self.ID}: {self.SUBJECT}>'

    def to_dict(self):
        """Convert to dictionary for easy serialization"""
        return {
            'id': self.ID,
            'first_name': self.FIRST_NAME,
            'last_name': self.LAST_NAME,
            'email': self.EMAIL,
            'category': self.CATEGORY,
            'subject': self.SUBJECT,
            'message': self.MESSAGE,
            'status': self.STATUS,
            'created_at': self.CREATED_AT.isoformat() if self.CREATED_AT else None,
            'updated_at': self.UPDATED_AT.isoformat() if self.UPDATED_AT else None
        }