import shelve
import html
from flask import *
from functools import *
from flask_mail import Mail, Message
from ff3 import FF3Cipher
import os
import google.generativeai as genai
from datetime import datetime
import markdown
import bleach

app = Flask(__name__, static_folder="static")
app.secret_key = os.urandom(32).hex()


# Allow safe tags used by Markdown + code rendering
ALLOWED_TAGS = set(bleach.sanitizer.ALLOWED_TAGS).union({'p', 'br', 'pre', 'code', 'strong', 'em'})

# Allow specific attributes only for certain tags
ALLOWED_ATTRIBUTES = {
    'a': ['href', 'title', 'target'],
    'img': ['src', 'alt'],
    'code': ['class']
}

def get_role():
    user_id=session.get("user_id",{})
    with shelve.open('database/user_database/user.db') as db:
        users = db.get('Users', {})
        try:
            user = users[user_id]
            role = str(user.role)
        except TypeError:
            role = "not_signed_in"
    return role

# weifeng decorator for RBA
#done by weifeng
def role_required(required_role):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user_id = session.get('user_id', False)
            try:
                with shelve.open('database/user_database/user.db') as db:
                    users = db.get('Users', {})
                    user = users[user_id]
                    role = str(user.role)
                if user_id and not role == required_role:
                    return render_template('403.html')
                return func(*args, **kwargs)
            except (IOError, KeyError):
                return render_template('503.html')

        return wrapper

    return decorator

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404


# Error handler for 500 - Internal Server Error
#Done by Alexander
@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500


@app.route("/")
def home():
    for m in genai.list_models():
        print(m.name)
    return render_template('home.html')


@app.route('/chatbot', methods=['POST'])
def chatbot():
    if request.method == 'POST':
        # Step 1: Sanitize user input (redundant safety against XSS)
        user_input = request.form['user_input']
        user_input = html.escape(user_input.strip())

        print(f"User Input: {user_input}")

        # Step 2: Set up Gemini model
        model = genai.GenerativeModel('gemini-1.5-flash-latest')
        chat = model.start_chat(history=[])

        try:
            response = chat.send_message(user_input, stream=True)

            bot_response = ""
            for chunk in response:
                if chunk.text:
                    bot_response += chunk.text

            # Step 3: Convert Markdown to HTML
            raw_html = markdown.markdown(bot_response, extensions=["fenced_code", "codehilite"])

            # Step 4: Sanitize Markdown HTML to allow only safe tags
            safe_html = bleach.clean(raw_html, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES)

            print("Sanitized Bot Response:", safe_html)
            return jsonify({'response': safe_html})

        except Exception as e:
            print("Error in chatbot:", e)
            return jsonify({'response': "Sorry, I can't respond to that input."})





if __name__ == '__main__':
    app.run()









