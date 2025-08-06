from flask import Flask
import shelve
import html
from flask import *
from flask_mail import Mail, Message
import os
import google.generativeai as genai
from datetime import datetime
import markdown
import bleach
# from routes import
from flask_limiter import Limiter
from flask_login import login_required, current_user
from rate_limiter_config import limiter
#set max length for inputs
MAX_LENGTH = 255

genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))

#watch out for dangerous keywords
dangerous_patterns = ['system:', 'ignore previous', 'act as']


 # Allow safe tags used by Markdown + code rendering
ALLOWED_TAGS = set(bleach.sanitizer.ALLOWED_TAGS).union({'p', 'br', 'pre', 'code', 'strong', 'em'})
#
# # Allow specific attributes only for certain tags
ALLOWED_ATTRIBUTES = {
    'code': ['class']
}

chatbot = Blueprint('chatbot', __name__, url_prefix='')

@chatbot.route('/chatbot', methods=['POST'])
@limiter.limit("5 per minute")
def chatbot_route():
    if not current_user.is_authenticated:
        return jsonify({'response': 'Sorry please sign in first to use the chatbot.'})
    if request.method == 'POST':
        print("called chatbot")
        # Step 1: Sanitize user input (redundant safety against XSS)
        user_input = request.form['user_input']
        user_input = html.escape(user_input.strip())
        if len(user_input) > MAX_LENGTH:
            return jsonify({'response': "Sorry input is too long,Please shorten it."})

        if any(pat in user_input.lower() for pat in dangerous_patterns):
            return jsonify({'response': "Input contains restricted content."})

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