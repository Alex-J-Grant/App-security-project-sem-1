from flask import Blueprint, render_template, redirect, url_for, flash
from helperfuncs.logger import main_logger
from flask_login import login_required, current_user
from extensions import db
from models.user import User
from helperfuncs.rba import *
from models.banreq import BanReq
from sqlalchemy import text
from sqlalchemy.orm import aliased
from forms.userforms import Emptyform

adminbp = Blueprint('admin', __name__, url_prefix='/admin')

@adminbp.route('/', methods = ['GET'])
@login_required
@admin_required
def dashboard():
    return render_template('dashboard.html')

@adminbp.route('/users', methods = ['GET'])
@login_required
@admin_required
def viewusers():
    form = Emptyform()
    users = User.query.with_entities(User.id, User.username, User.email, User.fname, User.lname, User.gender, User.dob, User.telno, User.address, User.postal, User.role, User.is_activeuser, User.is_verifieduser).all()
    return render_template('viewusers.html', users = users, form = form)

@adminbp.route('/users/<user_id>/posts')
@login_required
@admin_required
def userposts(user_id):
    user = User.query.get_or_404(user_id)
    query = text(
        """
        SELECT POST_ID, USER_ID, COMM_ID, TITLE, IMAGE, DESCRIPT, LIKE_COUNT, COMMENT_COUNT, created_at
        FROM app_sec_db.POST
        WHERE USER_ID = :user_id
        ORDER BY created_at DESC;
        """
    )
    result = db.session.execute(query, {'user_id': user_id})
    posts = result.fetchall()
    return render_template('specificuserposts.html', posts = posts, user = user)
    

@adminbp.route('/users/delete/<user_id>', methods = ['POST'])
@login_required
@admin_required
def delete(user_id):
    user = User.query.get_or_404(user_id)
    if user.role == 'Admin':
        flash('You cannot delete an admin', 'danger')
        return redirect(url_for('admin.viewusers'))

    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('admin.viewusers'))

@adminbp.route('/users/promote/<user_id>', methods = ['POST'])
@login_required
@admin_required
def promote(user_id):
    user = User.query.get_or_404(user_id)
    user.role = 'Admin'
    db.session.commit()
    return redirect(url_for('admin.viewusers'))


@adminbp.route('/ban', methods = ['GET', 'POST'])
@login_required
@admin_required
def banreq():
    form = Emptyform()
    requests = BanReq.query.join(User).all()
    return render_template('banreq.html', requests = requests, form = form)


@adminbp.route('/users/ban/<banreq_id>', methods = ['POST'])
@login_required
@admin_required
def banuser(banreq_id):
    print(banreq_id)
    banreq = BanReq.query.get_or_404(banreq_id)
    user = User.query.get_or_404(banreq.userid)
    user.is_activeuser = False
    banreq.handled = True
    db.session.commit()
    flash(f'User {user.username} has been banned', 'success')
    return redirect(url_for('admin.banreq'))


@adminbp.route('/users/noban/<banreq_id>', methods = ['POST'])
@login_required
@admin_required
def nobanuser(banreq_id):
    print(banreq_id)
    banreq = BanReq.query.get_or_404(banreq_id)
    user = User.query.get_or_404(banreq.userid)
    banreq.handled = True
    db.session.commit()
    flash(f'User {user.username} not banned', 'success')
    return redirect(url_for('admin.banreq'))


@adminbp.route('/posts', methods = ['GET'])
@login_required
@admin_required
def viewposts():
    form = Emptyform()
    query = text( """
        SELECT *
        FROM POST
 """)
    result = db.session.execute(query)
    posts = []
    for row in result:
        posts.append({
            'id': row.POST_ID,
            'title': row.TITLE,
            'description': row.DESCRIPT,
            'image_url':  url_for('static', filename=f'images/post_images/{row.IMAGE}') if row.IMAGE else None,
            'created_at': row.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'likes': row.LIKE_COUNT
        })

 
    return render_template('adminposts.html', posts = posts, form = form)


@adminbp.route('/posts/delete/<post_id>', methods = ['POST'])
@login_required
@admin_required
def delpost(post_id):
    query = text('DELETE FROM POST WHERE POST_ID = :post_id')
    db.session.execute(query, {'post_id': post_id})
    db.session.commit()
    flash('Post deleted successfully', 'success')
    return redirect(url_for('admin.viewposts'))




