from flask import Blueprint, render_template, redirect, url_for, flash
from helperfuncs.email_sender import send_email
from helperfuncs.logger import main_logger
from flask_login import login_required, current_user, logout_user
from forms.profileforms import Editprofile, Delprofile
from forms.userforms import Report
from extensions import db
from helperfuncs.uuidgen import gen_uuid
from models.user import User
from models.banreq import BanReq
from helperfuncs.rba import *
from helperfuncs.banneduser import banneduser
import os
from PIL import Image
import uuid
profile = Blueprint('profile', __name__, url_prefix= '/profile')
profile_picture_path = 'static/images/profile_pictures'

@profile.route('/', methods = ['GET', 'POST'])
@login_required
def view():
    main_logger.info('view profile')
    return render_template('viewprofile.html', username = current_user.username, fname = current_user.fname, lname = current_user.lname, gender = current_user.gender, telno = current_user.telno, postal = current_user.postal, address = current_user.address, email = current_user.email, userpfp = current_user.userpfp)

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
        filepath = None
        if form.pfp.data:
            #get the file extension
            file = form.pfp.data
            orig_filename = file.filename
            ext = os.path.splitext(orig_filename)[1].lower()  # e.g., '.png'

            #if somehow got past everything else
            if ext not in ['.png', '.jpg', '.jpeg', '.gif']:
                flash('Please upload image files only', 'danger')
                return render_template('editprofile.html', form=form)

            # Strip metadata in-memory

            filename = gen_uuid() + ext
            filepath = os.path.join(profile_picture_path, filename)
            try:
                with Image.open(file.stream) as img:
                    data = img.getdata()
                    clean_img = Image.new(img.mode, img.size)
                    clean_img.putdata(data)

                    # Ensure correct format when saving
                    format_map = {
                        '.jpg': 'JPEG',
                        '.jpeg': 'JPEG',
                        '.png': 'PNG',
                        '.gif': 'GIF'
                    }

                    clean_img.save(filepath, format=format_map[ext])
                old_file = getattr(user, 'userpfp', None)
                if old_file:
                    old_path = os.path.join(profile_picture_path, old_file)
                    if os.path.exists(old_path):
                        os.remove(old_path)
                user.userpfp = filename
            except Exception:
                # Delete saved files if exists, if an exception occurs
                if filepath and os.path.exists(filepath):
                    os.remove(filepath)
                flash("Sorry something went wrong please try again later.", "danger")


 

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

@profile.route('/reqban/<user_id>', methods = ['GET', 'POST'])
@login_required
def requestban(user_id):
    form = Report()
    if form.validate_on_submit():
        banrequest = BanReq(
        userid = user_id,
        reason = form.reason.data.strip()
        )
        db.session.add(banrequest)
        db.session.commit()
        flash('Ban request submitted')
        return redirect(url_for('home.home'))
    return render_template('requestban.html', form = form)



# to be deleted
@profile.route('/admintest', methods = ['GET', 'POST'])
@login_required
@admin_required
def admin():
    return render_template('home.html')


@profile.route('/bantest', methods = ['GET', 'POST'])
@login_required
@banneduser
def bantest():
    return redirect(url_for('account.create'))

