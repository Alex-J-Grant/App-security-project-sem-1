


from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, FileField
from wtforms.validators import DataRequired, Length,ValidationError
from helperfuncs.validation import allowed_mime_type, virus_check
from flask_wtf.file import FileField, FileAllowed, FileRequired


#done by alexander
from wtforms import SelectField

#make error messages vauge so attacker doesnt know whats happening
def MIME_CHECKER(form,field):
    file = field.data
    if not allowed_mime_type(file):
        raise ValidationError("Images only please (jpg, png, gif).")

def VIRUS_CHECKER(form,field):
    file = field.data
    if virus_check(file) is not None:
        raise ValidationError("Images only please (jpg, png, gif).")

class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(min=1, max=255)])
    description = TextAreaField('Description', validators=[DataRequired(), Length(min=1, max=255)])
    image = FileField('Upload Image', validators=[
        FileRequired(),
        FileAllowed(['jpg', 'png', 'gif', 'jpeg'], 'Images only please (jpg, png, gif).'),
        MIME_CHECKER,
        VIRUS_CHECKER
    ])
    community = SelectField('Choose Community to upload to', validators=[DataRequired()], choices=[])  # choices will be filled in dynamically