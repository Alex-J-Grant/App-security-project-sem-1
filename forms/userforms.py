from flask_wtf import FlaskForm
from wtforms import BooleanField, DateField, EmailField, PasswordField, RadioField, StringField, SubmitField
from wtforms.validators import EqualTo, Length, Regexp,DataRequired,ValidationError, Email
from models.user import User




class Createuser(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=5, max=20)])
    fname = StringField('First Name', validators=[DataRequired()])
    lname = StringField('Last Name', validators=[DataRequired()])
    email = EmailField('Email', validators=[DataRequired(), Email(message = 'Invalid Email Address'), Length(max=120)])
    gender = RadioField('Gender', choices=[('M', 'Male'), ('F', 'Female'), ('O', 'Others')], validators=[DataRequired()])
    telno = StringField('Phone Number', validators=[DataRequired(), Regexp(r'^\+?\d{7,15}$', message="Enter a valid phone number")])
    dob = DateField('Date of Birth', format='%Y-%m-%d', validators=[DataRequired()])
    address = StringField('Address', validators=[DataRequired()])
    postal = StringField('Postal Code', validators=[DataRequired(), Regexp(r'^\d{6}$', message='Postal code must be 6 digits')])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=10), Regexp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]+$',message='Password must include uppercase, lowercase, number, and special character (!@#$%^&*).')])
    confirm_pw = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match')])

    submit = SubmitField('Register')
    # todo 
    # ensure no dupes for email and telno 
    def validate_username(self, field):
        existing = User.query.filter_by(username=field.data).first()
        if existing:
            raise ValidationError('This is already taken')


class Loginuser(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=5, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=10)])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')
