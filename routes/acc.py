from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from itsdangerous import NoneAlgorithm
from helperfuncs.logger import main_logger
from flask_login import login_user, login_required, logout_user, current_user
from models import user
from models.user import User
from extensions import db
from forms.userforms import Createuser, Loginuser, Twofa, Forgetpw, Resetpw
from models.session import Usersession
from datetime import datetime, timezone, timedelta, tzinfo
from helperfuncs.email_sender import send_email
from helperfuncs.banneduser import *
import secrets
from flask import session

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
                    email = form.email.data,
                    country = form.country.data

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
            token = secrets.token_hex(3).upper()
            print(token)
            user.twofa_code = token
            user.twofa_exp = datetime.now(timezone.utc) + timedelta(minutes = 5)
            db.session.commit()
            print(user.email)
            send_email(token, user.email, user.username, '2FA')
            
            session['pending_2fa'] = user.id
            session['rememberme'] = form.remember.data
            return redirect(url_for('account.twofa'))
        else:
            flash('Invalid Credentials', 'danger')
            return redirect(url_for('account.login'))
    
    return render_template('login.html', form=form)


@account.route('/2fa', methods = ['GET', 'POST'])
def twofa():
    if current_user.is_authenticated:
        return redirect(url_for('home.home'))
    form = Twofa()
    user_id = session.get('pending_2fa', None)
    remember_me = session.get('rememberme', None)
    if not user_id:
        flash('Session expired. Please try again', 'danger')
        return redirect(url_for('account.login'))
    user = User.query.get(user_id)
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('account.login'))

    if form.validate_on_submit():
        token = form.token.data.strip().upper()
        twofa_exp = user.twofa_exp
        if twofa_exp and twofa_exp.tzinfo is None:
            twofa_exp = twofa_exp.replace(tzinfo=timezone.utc)
        if user.twofa_exp and datetime.now(timezone.utc) < twofa_exp and token == user.twofa_code:
            login_user(user, remember = remember_me)
            session.pop('pending_2fa', None)
            session.pop('rememberme', None)
            user.twofa_code = None
            user.twofa_exp = None
            db.session.commit()
            cookie_name = current_app.config.get('SESSION_COOKIE_NAME', 'session')
            sess_id = request.cookies.get(cookie_name)
            user_sess = Usersession.query.get(sess_id)
            time = datetime.now(timezone.utc)
            if not user_sess:
                user_sess = Usersession(session_id = sess_id, user_id = str(user.id), created_at = time, last_active = time)
                db.session.add(user_sess)

            else:
                user_sess.user_id = str(user.id)
                user_sess.last_active = time
            db.session.commit()
            if user.role == 'Admin':
                return redirect(url_for('admin.dashboard'))
            flash('Login successful', 'success')
            return redirect(url_for('home.home'))
        else:
            flash('Invalid or Expired Token', 'danger')
            user.twofa_code = None
            user.twofa_exp = None
            db.session.commit()
            return redirect(url_for('account.login'))
    
    return render_template('twofa.html', form=form)



@account.route('/logout')
@login_required
def logout():
    cookie_name = current_app.config.get('SESSION_COOKIE_NAME', 'session')
    sess_id = request.cookies.get(cookie_name)
    user_sess = Usersession.query.get(sess_id)
    if user_sess:
        db.session.delete(user_sess)
        db.session.commit()
    session.clear()
    logout_user()
    flash('You have been logged out')
    return redirect(url_for('account.login'))


@account.route('/forgetpw', methods = ['GET', 'POST'])
def forgetpw():
    form = Forgetpw()
    if form.validate_on_submit():
        email = form.email.data.strip()
        user = User.query.filter_by(email=email).first()
        if user:
            token = user.get_reset_token()
            reset_url = url_for('account.reset_token', token = token, _external = True)
            send_email(reset_url, email, '', 'forgetpw')
            print(reset_url)
            flash('If that email exists, a reset link has been sent')
            return redirect(url_for('account.login'))
    return render_template('forgetpw.html', form = form)

@account.route('/reset/<token>', methods = ['GET', 'POST'])
def reset_token(token):
    user = User.verify_reset_token(token)
    if not user:
        flash('Invalid or Expired token', 'danger')
        return redirect(url_for('account.forgetpw'))
    
    form = Resetpw()
    if form.validate_on_submit():
        user.password = form.password.data.strip()
        db.session.commit()
        flash('Password successfully changd', 'success')
        return redirect(url_for('account.login'))
    return render_template('resetpw.html', form = form)





