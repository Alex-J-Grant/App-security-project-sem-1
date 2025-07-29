
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, FileField,SelectField
from wtforms.validators import InputRequired, Length, Regexp,DataRequired,ValidationError
from sqlalchemy import text
from extensions import db
from helperfuncs.validation import allowed_mime_type, virus_check
#checks if there is already a community by that name
def Duplicte_Comm_Name(form,field):
    name = field.data
    stmt = text("SELECT * FROM SUBCOMMUNITY WHERE NAME = :name")
    with db.engine.connect() as conn:
        result = conn.execute(stmt, {"name": name}).fetchone()
    print(result)
    if result is not None:
        raise ValidationError("Community name already exists.")

def MIME_CHECKER(form,field):
    file = field.data
    if not allowed_mime_type(file):
        raise ValidationError("Images only please (jpg, png, gif).")

def VIRUS_CHECKER(form,field):
    file = field.data
    if virus_check(file) is not None:
        raise ValidationError("Images only please (jpg, png, gif).")

class CreateCommunityForm(FlaskForm):
    name = StringField("Community Name", validators=[
        InputRequired(),
        Length(min=3, max=25),
        Regexp(r"^[a-zA-Z0-9_]+$", message="Only letters, numbers, underscores allowed."),
        Duplicte_Comm_Name

    ])
    description = TextAreaField("Description", validators=[InputRequired(), Length(max=500)])
    # Dropdown for tags
    tag = SelectField(
        "Tag",
        choices=[
            ("tech", "Technology"),
            ("gaming", "Gaming"),
            ("art", "Art"),
            ("science", "Science"),
            ("music", "Music"),
            ("news", "News"),
            ("sports","Sports"),
            ("education","Education")
        ],
        validators=[DataRequired()]
    )
    banner_image = FileField("Banner Image", validators=[InputRequired(),MIME_CHECKER,VIRUS_CHECKER])
    icon_image = FileField("Icon Image", validators=[InputRequired(),MIME_CHECKER,VIRUS_CHECKER])