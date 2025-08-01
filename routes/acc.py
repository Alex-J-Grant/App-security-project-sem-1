from flask import Blueprint, render_template, request, redirect, url_for, flash
from sqlalchemy.engine import url
from helperfuncs.logger import main_logger
from flask_login import login_user, login_required, logout_user
from models.user import User
from extensions import db
from forms.userforms import Createuser, Loginuser

account = Blueprint('account', __name__, url_prefix= '/account')

@account.route('/create', methods = ['GET', 'POST'])
def create():
    main_logger.info('User creation accessed')
    #form goes here 
    form = Createuser()
    if form.validate_on_submit():
        user = User(username = form.username.data.strip(), 
                    # password is never stored in plaintext at all backend only handles hashed passwords
                    # this is a custom setter 
                    password = form.password.data,
                    fname = form.fname.data,
                    lname = form.lname.data,
                    gender = form.gender.data,
                    telno = form.telno.data,
                    dob = form.dob.data,
                    address = form.address.data,
                    postal = form.postal.data,
                    email = form.email.data

                    )
        db.session.add(user)
        db.session.commit()
        flash('Account Created')
        return redirect(url_for('account.login'))
    return render_template('createacc.html', form = form)
        

@account.route('/login', methods = ['GET', 'POST'])
def login():
    main_logger.info('User login accessed')
    form = Loginuser()

    if form.validate_on_submit():
        username = form.username.data.strip()
        user = User.query.filter_by(username = username).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember = form.remember.data)
            flash('Login successful', 'success')
            return redirect(url_for('home.home'))
        else:
            flash('Invalid Credentials', 'danger')
            return redirect(url_for('account.login'))
    
    return render_template('login.html', form=form)

@account.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out')
    return redirect(url_for('account.login'))
