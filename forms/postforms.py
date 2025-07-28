from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, FileField
from wtforms.validators import DataRequired, Length

from flask_wtf.file import FileField, FileAllowed, FileRequired

class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(min=1, max=255)])
    description = TextAreaField('Description', validators=[DataRequired(),Length(min=1,max=255)])
    image = FileField('Upload Image',validators=[FileRequired(), FileAllowed(['jpg', 'png','gif','jpeg'], 'Images only please(jpg,png,gif).')])