from flask import Blueprint, render_template, redirect, url_for, flash
from helperfuncs.logger import main_logger
from flask_login import login_required, current_user, logout_user
from forms.profileforms import Editprofile, Delprofile
from extensions import db
from models.user import User
from helperfuncs.rba import *


profile = Blueprint('profile', __name__, url_prefix= '/profile')

@profile.route('/', methods = ['GET', 'POST'])
@login_required
def view():
    main_logger.info('view profile')
    return render_template('viewprofile.html', username = current_user.username, fname = current_user.fname, lname = current_user.lname, gender = current_user.gender, telno = current_user.telno, postal = current_user.postal, address = current_user.address, email = current_user.email)

# to be deleted
@profile.route('/testing', methods = ['GET', 'POST'])
@login_required
def dump():
    return render_template('profiletest.html', user=current_user, vars=vars)

@profile.route('/edit', methods = ['GET', 'POST'])
@login_required
def edit():
    user = db.session.query(User).filter_by(id=current_user.id).first()
    form = Editprofile(obj = user)
    if form.validate_on_submit():
        user.username = form.username.data.strip()
        user.fname = form.fname.data
        user.lname = form.lname.data
        user.email = form.email.data
        user.telno = form.telno.data
        user.address = form.address.data
        user.postal = form.postal.data

        if form.curr_password.data and form.password.data and form.confirm_pw.data:
            if not user.check_password(form.curr_password.data):
                flash('Current Password is wrong.', 'danger')
                return render_template('editprofile.html', form=form)
            user.password = form.password.data

        db.session.commit()
        flash('Profile Updated Successfully')
        return redirect(url_for('profile.edit'))


    return render_template('editprofile.html', form=form)

# consider adding a confirmation checkbox and maybe a grace period if free
@profile.route('/delete', methods=['GET', 'POST'])
@login_required
def delete():
    form = Delprofile()
    if form.validate_on_submit():
        if not current_user.check_password(form.password.data):
            flash('Password is wrong', 'danger')
            return render_template('delprofile.html', form=form)
        db.session.delete(current_user)
        db.session.commit()
        logout_user()
        flash('Accounted Deleted')
        return redirect(url_for('account.login'))
    return render_template('delprofile.html', form=form)




@profile.route('/reset', methods = ['GET', 'POST'])
@login_required
def forgetpw():
    return redirect(url_for('profile.view'))


# to be deleted
@profile.route('/admintest', methods = ['GET', 'POST'])
@login_required
@admin_required
def admin():
    return render_template('home.html')

