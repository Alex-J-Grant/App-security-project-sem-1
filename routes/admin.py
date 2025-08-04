from flask import Blueprint, render_template, redirect, url_for, flash
from helperfuncs.logger import main_logger
from flask_login import login_required, current_user, logout_user
from forms.profileforms import Editprofile, Delprofile
from extensions import db
from models.user import User
from helperfuncs.rba import *

adminbp = Blueprint('admin', __name__, url_prefix='/admin')

@adminbp.route('/', methods = ['GET'])
@login_required
@admin_required
def dashboard():
    ...

@adminbp.route('/users', methods = ['GET'])
@login_required
@admin_required
def viewusers():
    ...

@adminbp.route('/')
