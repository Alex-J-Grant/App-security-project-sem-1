from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash
from extensions import db
from datetime import datetime, timezone
from helperfuncs.uuidgen import gen_uuid
class User(db.Model, UserMixin):
    __tablename__ = 'USERS'
    id = db.Column('USER_ID', db.String(50), primary_key = True, unique = True, nullable = False, default= gen_uuid)
    username = db.Column('USERNAME', db.String(20), unique = True, nullable = False)
    password_hash = db.Column('PASSWORD_HASH', db.String(255), nullable = False)
    fname = db.Column('FNAME', db.String(15), nullable = False)
    lname = db.Column('LNAME', db.String(15), nullable = False)
    gender = db.Column('GENDER', db.String(20), nullable = False)
    dob = db.Column('DOB', db.Date, nullable = False)
    telno = db.Column('TEL_NO', db.String(20), nullable = False, unique = True)
    address = db.Column('ADDRESS', db.String(50))
    postal = db.Column('POSTAL_CODE', db.String(10))
    email = db.Column('EMAIL', db.String(255), unique = True, nullable = False)
    is_activeuser = db.Column('IS_ACTIVE', db.Boolean, default = True)
    is_verifieduser = db.Column('IS_VERIFIED', db.Boolean, default = False)
    created_at = db.Column('CREATED_AT', db.DateTime(timezone = True), default=lambda: datetime.now(timezone.utc), nullable = False)
    role = db.Column('ROLE', db.Enum('Admin', 'User', name='user_roles'), default = 'User', nullable = False)
    settings = db.Column('SETTINGS', db.JSON)
    userpfp = db.Column('USERPFP', db.String(255))

    @property
    def password(self):
        raise AttributeError('No permissions')

    @password.setter
    def password(self, plaintext):
        self.password_hash = generate_password_hash(plaintext)


    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
