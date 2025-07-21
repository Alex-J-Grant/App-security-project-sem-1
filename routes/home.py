# auth.py

from flask import Blueprint, render_template

# Define the blueprint
homebp = Blueprint('home', __name__, url_prefix='')

# Routes
@homebp.route('/')
def home():
    return render_template('home.html')



