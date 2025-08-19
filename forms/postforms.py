


from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, FileField
from wtforms.validators import DataRequired, Length,ValidationError,Regexp
from helperfuncs.validation import allowed_mime_type, virus_check
from flask_wtf.file import FileField, FileAllowed, FileRequired
from flask_login import current_user
from helperfuncs.logger import main_logger

#done by alexander
from wtforms import SelectField

#make error messages vauge so attacker doesnt know whats happening
def MIME_CHECKER(form,field):
    file = field.data
    if field.data:
        if not allowed_mime_type(file):
            main_logger.warning(f"Attempt to bypass file restrictions on post upload by {current_user.username} {current_user.id}")
            raise ValidationError("Images only please (jpg, png, gif).")

def VIRUS_CHECKER(form,field):
    file = field.data
    if field.data:
        if virus_check(file) is not None:
            main_logger.warning(f"Attempt to upload file with virus signatures on post upload by {current_user.username} {current_user.id}")
            raise ValidationError("Images only please (jpg, png, gif).")

class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(min=1, max=255),Regexp(r"^[a-zA-Z0-9_() !?]+$", message="Only letters, Spaces, numbers, exclamation point, question mark, underscores and brackets allowed.")])
    description = TextAreaField('Description', validators=[DataRequired(), Length(min=1, max=255),Regexp(r"^[a-zA-Z0-9_()!?. \n\r]+$", message="Only letters, Spaces, numbers, exclamation point, question mark, underscores, full stop and brackets allowed.")])
    image = FileField('Upload Image', validators=[
        FileAllowed(['jpg', 'png', 'gif', 'jpeg'], 'Images only please (jpg, png, gif).'),
        MIME_CHECKER,
        VIRUS_CHECKER
    ])
    community = SelectField('Choose Community to upload to', validators=[DataRequired()], choices=[])  # choices will be filled in dynamically