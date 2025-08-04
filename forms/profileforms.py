from flask_login import current_user
from flask_wtf import FlaskForm
from wtforms import EmailField, PasswordField, StringField, SubmitField
from wtforms.validators import EqualTo, Length, Regexp,DataRequired,ValidationError, Email, Optional
from models.user import User




class Editprofile(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=5, max=20)])
    fname = StringField('First Name', validators=[DataRequired()])
    lname = StringField('Last Name', validators=[DataRequired()])
    email = EmailField('Email', validators=[DataRequired(), Email(message = 'Invalid Email Address'), Length(max=120)])
    telno = StringField('Phone Number', validators=[DataRequired(), Regexp(r'^\+?\d{7,15}$', message="Enter a valid phone number")])
    address = StringField('Address', validators=[DataRequired()])
    postal = StringField('Postal Code', validators=[DataRequired(), Regexp(r'^\d{6}$', message='Postal code must be 6 digits')])
    password = PasswordField('Change Password', validators=[Optional(), Length(min=10), Regexp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]+$',message='Password must include uppercase, lowercase, number, and special character (!@#$%^&*).')])
    confirm_pw = PasswordField('Confirm New Password', validators=[Optional(), EqualTo('password', message='Passwords must match')])
    curr_password = PasswordField('Current Password', validators=[Optional(), Length(min=10), Regexp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]+$',message='Password must include uppercase, lowercase, number, and special character (!@#$%^&*).')])
    submit = SubmitField('Edit Profile')
    # todo 
    # ensure no dupes for email and telno 
    def validate_username(self, field):
        existing = User.query.filter_by(username=field.data).first()
        if existing and existing.id != current_user.id:
            raise ValidationError('This is already taken')


class Delprofile(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=5, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=10), Regexp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]+$',message='Password must include uppercase, lowercase, number, and special character (!@#$%^&*).')])
    submit = SubmitField('Delete Account')
