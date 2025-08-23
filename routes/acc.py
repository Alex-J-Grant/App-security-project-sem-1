from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app, make_response
from itsdangerous import NoneAlgorithm, URLSafeSerializer,URLSafeTimedSerializer
from sqlalchemy.engine import url
from sqlalchemy.sql.elements import ExpressionClauseList
from helperfuncs.logger import main_logger
from helperfuncs.location_checker import compare_country,get_country_from_ip
from flask_login import login_user, login_required, logout_user, current_user
from models import user
from models.user import User
from extensions import db
from forms.userforms import Createuser, Loginuser, Twofa, Forgetpw, Resetpw,ConfirmUntrustForm
from models.session import Usersession
from datetime import datetime, timezone, timedelta, tzinfo
from helperfuncs.email_sender import send_email
from helperfuncs.banneduser import *
import secrets
from flask import session
from sqlalchemy import text
from helperfuncs.trusted_devices import generate_device_token, save_trusted_device, is_trusted_device, \
    mark_device_verified,temp_cookie_name,trusted_cookie_name,rotate_trusted_device
from models.trusted_device import UserTrustedDevice,TrustedDevice

from helperfuncs.local_url_check import is_local_url
from rate_limiter_config import limiter
account = Blueprint('account', __name__, url_prefix= '/account')

@account.route('/create', methods = ['GET', 'POST'])
@limiter.limit('5 per minute')
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

        # Trust the device that created the account (server-side verified)
        device_token = generate_device_token()
        save_trusted_device(user.id, device_token, verified=True)
        mark_device_verified(device_token)


        cname = trusted_cookie_name(user.id)
        resp = make_response(redirect(url_for('account.login')))
        resp.set_cookie(
            cname,
            device_token,  # store token directly; server validates it
            max_age=90 * 24 * 3600,
            secure=True,
            httponly=True,
            samesite='Strict'
        )
        flash('Account Created')
        return resp
    return render_template('createacc.html', form = form)
        

@account.route('/login', methods = ['GET', 'POST'])
@limiter.limit('10 per minute')
def login():
    main_logger.info('User login accessed')
    form = Loginuser()

    if form.validate_on_submit():
        username = form.username.data.strip()
        user = User.query.filter_by(username = username).first()
        if user and user.lockout_until:
            lockout_until = user.lockout_until.replace(tzinfo=timezone.utc)
        else:
            lockout_until = None
        if user and lockout_until and lockout_until > datetime.now(timezone.utc):
            remaining = lockout_until - datetime.now(timezone.utc)
            minutes = int(remaining.total_seconds()//60) + 1
            main_logger.info('Account is locked out')
            flash(f'Account locked. Please try again in {minutes} minutes', 'danger')
            return render_template('login.html', form=form)
        elif user and lockout_until and lockout_until <= datetime.now(timezone.utc):
            user.failed_attempts = 0
            user.lockout_until = None
            db.session.commit()

        if user and user.check_password(form.password.data):
            next_page = request.args.get('next')
            if next_page and is_local_url(next_page):
                session['next_page'] = next_page
            token = secrets.token_hex(3).upper()
            print(token)
            user.twofa_code = token
            user.twofa_exp = datetime.now(timezone.utc) + timedelta(minutes = 5)
            db.session.commit()
            print(user.email)

            if compare_country(user.country,request.remote_addr) != "match":
                location = get_country_from_ip(request.remote_addr)
                main_logger.warning(f"Log in from new location ({"Unknown" if location is None else location}) on account:{user.id}")
                send_email("",user.email,f"{user.fname} {user.lname}","warning_new_country",get_country_from_ip(request.remote_addr))



            # get device trust cookies
            tname = trusted_cookie_name(user.id)
            current_trusted_token = request.cookies.get(tname)



            #see if any pending requests to get the device trusted has been verified
            temp_name = temp_cookie_name(user.id)
            temp_token = request.cookies.get(temp_name)
            if temp_token and is_trusted_device(user.id, temp_token):
                #change to persistent cookie if verified
                resp = make_response(redirect(url_for('account.twofa')))
                resp.set_cookie(
                    tname,
                    temp_token,
                    max_age=90 * 24 * 3600,
                    secure=True,
                    httponly=True,
                    samesite='Strict'
                )
                resp.delete_cookie(temp_name)
                flash('This device is now trusted!', 'success')
                session['pending_2fa'] = user.id
                return resp

            #if not currently trusted with account then start new verification
            if not current_trusted_token or not is_trusted_device(user.id, current_trusted_token):
                temp_token = generate_device_token()
                save_trusted_device(user.id, temp_token, verified=False)

                # 1-hr temp cookie for THIS user only
                resp = make_response(render_template('verify_device.html'))
                resp.set_cookie(
                    temp_name,
                    temp_token,
                    max_age=3600,
                    secure=True,
                    httponly=True,
                    samesite='Strict'
                )

                # Email verification link (contains user_id + device_token)
                serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
                signed_token = serializer.dumps({'user_id': user.id, 'device_token': temp_token})
                verify_link = url_for('account.verify_new_device', token=signed_token, _external=True)
                send_email(verify_link, user.email, f"{user.fname} {user.lname}",
                           "verify_new_device", device=request.user_agent)

                flash("New device detected. Please verify via the email we sent you.", "warning")
                return resp

            send_email(token, user.email, user.username, '2FA')
            
            session['pending_2fa'] = user.id
            user.failed_attempts = 0
            db.session.commit()

            return redirect(url_for('account.twofa'))
        else:

            if not user:
                flash('Invalid credentials', 'danger')
                return redirect(url_for('account.login'))
            user.failed_attempts += 1
            if user.failed_attempts >= 5:
                user.lockout_until = datetime.now(timezone.utc) + timedelta(minutes=60)
                flash('Too many failed attempts. Your account is now locked for 1 hour', 'danger')

            else:
                flash(f'Invalid credentials.', 'danger')
            db.session.commit()
            return render_template('login.html', form=form)
    
    return render_template('login.html', form=form)


@account.route('/2fa', methods = ['GET', 'POST'])
@limiter.limit('5 per minute')
def twofa():
    main_logger.info('2fa accessed')
    if current_user.is_authenticated:
        return redirect(url_for('home.home'))
    form = Twofa()
    user_id = session.get('pending_2fa', None)
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
            login_user(user, remember = False)
            session.pop('pending_2fa', None)
            user.twofa_code = None
            user.twofa_exp = None
            db.session.commit()
            cookie_name = current_app.config.get('SESSION_COOKIE_NAME', 'session')
            sess_id = request.cookies.get(cookie_name)
            user_sess = Usersession.query.get(sess_id)
            time = datetime.now(timezone.utc)

            #get device trust cookies
            tname = trusted_cookie_name(user.id)
            current_trusted_token = request.cookies.get(tname)
            # if passed 2fa then rotate the token
            if current_trusted_token and is_trusted_device(user.id, current_trusted_token):
                # Rotate the token
                new_token = rotate_trusted_device(user.id, current_trusted_token)
                if new_token:
                    resp = make_response(redirect(url_for('account.twofa')))
                    resp.set_cookie(
                        tname,
                        new_token,
                        max_age=90 * 24 * 3600,
                        secure=True,
                        httponly=True,
                        samesite='Strict'
                    )
                    session['pending_2fa'] = user.id
                    return resp

            if not user_sess:
                user_sess = Usersession(session_id = sess_id, user_id = str(user.id), created_at = time, last_active = time)
                db.session.add(user_sess)

            else:
                user_sess.user_id = str(user.id)
                user_sess.last_active = time
            db.session.commit()
            next_page = session.pop('next_page', None)
            if next_page:
                return redirect(next_page)
            elif user.role == 'Admin':
                return redirect(url_for('admin.dashboard'))
            else:
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
    resp = make_response(redirect(url_for('home.home')))
    resp.delete_cookie('remember_token')
    flash('You have been logged out')
    return resp

@account.route('/forgetpw', methods = ['GET', 'POST'])
@limiter.limit('5 per minute')
def forgetpw():
    main_logger.info('Forget password accessed')
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
@limiter.limit('5 per minute')
def reset_token(token):
    main_logger.info('Password reset accessed')
    user = User.verify_reset_token(token)
    if not user:
        flash('Invalid or Expired token', 'danger')
        return redirect(url_for('account.forgetpw'))
    
    form = Resetpw()
    if form.validate_on_submit():
        user.password = form.password.data.strip()
        db.session.commit()
        flash('Password successfully changed', 'success')
        return redirect(url_for('account.login'))
    return render_template('resetpw.html', form = form)





@account.route('/verify_device/<token>', methods=['GET'])
def verify_new_device(token):
    s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        # 15 minutes expiry
        data = s.loads(token, max_age=15*60)
        user_id = data['user_id']
        device_token = data['device_token']
    except Exception:
        flash("Invalid or expired verification link.", "danger")
        return redirect(url_for('account.login'))

    user = User.query.get(user_id)
    if not user:
        flash("Invalid or expired verification link.", "danger")
        return redirect(url_for('account.login'))

    # Ensure the device token exists AND is linked to user before verifying
    device = TrustedDevice.query.filter_by(device_token=device_token).first()
    if not device:
        flash("Invalid or expired verification link.", "danger")
        return redirect(url_for('account.login'))

    link = UserTrustedDevice.query.filter_by(user_id=user_id, device_id=device.id).first()
    if not link:
        flash("Invalid or expired verification link.", "danger")
        return redirect(url_for('account.login'))

    if not device.verified:
        device.verified = True
        device.verified_at = datetime.now(timezone.utc)
        db.session.commit()

    return render_template("trust_device_success.html")



@account.route('/untrust_all_devices', methods=['GET', 'POST'])
@login_required
def untrust_all_devices():
    form = ConfirmUntrustForm()

    if form.validate_on_submit():
        # Check credentials
        email = form.email.data.strip()
        password = form.password.data.strip()

        if email != current_user.email or not current_user.check_password(password):
            flash("Incorrect email or password. Cannot untrust devices.", "danger")
            return redirect(url_for('profile.view'))


        user_devices = UserTrustedDevice.query.filter_by(user_id=current_user.id).all()

        device_id = [d.device_id for d in user_devices]

        UserTrustedDevice.query.filter_by(user_id=current_user.id).delete()


        if device_id:

            TrustedDevice.query.filter(TrustedDevice.id.in_(device_id)).delete(
                synchronize_session=False)
        db.session.commit()

        # Clear trusted_devices cookie on this browser
        resp = make_response(redirect(url_for('profile.view')))
        resp.delete_cookie(trusted_cookie_name(current_user.id))
        flash("All devices have been untrusted. You will need to trust them again next log in.", "warning")
        return resp

    return render_template("untrust_devices.html", form=form)
