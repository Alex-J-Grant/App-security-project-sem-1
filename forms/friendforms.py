# forms/friendforms.py
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField, HiddenField
from wtforms.validators import DataRequired, Length

class SendFriendRequestForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=5, max=20)])
    submit = SubmitField('Send Friend Request')

class RespondFriendRequestForm(FlaskForm):
    request_id = HiddenField('Request ID', validators=[DataRequired()])
    action = HiddenField('Action', validators=[DataRequired()])  # 'accept' or 'reject'
    submit = SubmitField('Respond')

class SendMessageForm(FlaskForm):
    friend_id = HiddenField('Friend ID', validators=[DataRequired()])
    content = TextAreaField('Message', validators=[DataRequired(), Length(min=1, max=1000)],
                           render_kw={"placeholder": "Type your message here...", "rows": 3})
    submit = SubmitField('Send Message')

class SearchUserForm(FlaskForm):
    search_term = StringField('Search Users', validators=[DataRequired(), Length(min=1, max=50)],
                             render_kw={"placeholder": "Search by username or name..."})
    submit = SubmitField('Search')