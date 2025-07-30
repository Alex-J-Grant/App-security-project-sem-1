from flask import Blueprint, render_template, request, redirect, url_for, flash
from sqlalchemy.engine import url
from helperfuncs.logger import main_logger
from flask_login import login_required, current_user

profile = Blueprint('profile', __name__, url_prefix= '/profile')

@profile.route('/', methods = ['GET', 'POST'])
@login_required
def view():
    main_logger.info('view profile')
    return render_template('viewprofile.html', user=current_user, vars = vars)
