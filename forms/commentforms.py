# forms/commentforms.py
from flask_wtf import FlaskForm
from wtforms import TextAreaField, HiddenField, SubmitField
from wtforms.validators import DataRequired, Length

class CommentForm(FlaskForm):
    post_id = HiddenField('Post ID', validators=[DataRequired()])
    content = TextAreaField('Add a comment...',
                           validators=[DataRequired(), Length(min=1, max=500)],
                           render_kw={"placeholder": "Share your thoughts...", "rows": 3})
    submit = SubmitField('Post Comment')

class ReplyForm(FlaskForm):
    comment_id = HiddenField('Comment ID', validators=[DataRequired()])
    content = TextAreaField('Reply...',
                           validators=[DataRequired(), Length(min=1, max=500)],
                           render_kw={"placeholder": "Write a reply...", "rows": 2})
    submit = SubmitField('Reply')