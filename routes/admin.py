import re
from flask import Blueprint, render_template, redirect, url_for, flash
from helperfuncs.logger import main_logger
from flask_login import login_required, current_user
from extensions import db
from models.user import User
from helperfuncs.rba import *
from models.banreq import BanReq
from sqlalchemy import text
from sqlalchemy.orm import aliased

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
    users = User.query.with_entities(User.id, User.username, User.email, User.fname, User.lname, User.gender, User.dob, User.telno, User.address, User.postal, User.role).all()
    return render_template('viewusers.html', users = users)

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
    if current_user.role == 'Admin':
        user = User.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        return redirect(url_for('admin.viewusers'))
    else:
        return render_template('403.html')

@adminbp.route('/users/promote/<user_id>', methods = ['POST'])
@login_required
@admin_required
def promote(user_id):
    if current_user.role == 'Admin':
        user = User.query.get_or_404(user_id)
        user.role = 'Admin'
        db.session.commit()
        return redirect(url_for('admin.viewusers'))
    else:
        return render_template('403.html')


@adminbp.route('/ban', methods = ['GET', 'POST'])
@login_required
@admin_required
def banreq():
    requests = BanReq.query.join(User).all()
    return render_template('banreq.html', requests = requests)


@adminbp.route('/users/ban/<banreq_id>', methods = ['POST'])
@login_required
@admin_required
def banuser(banreq_id):
    if current_user.role == 'Admin':
        banreq = BanReq.query.get_or_404(banreq_id)
        user = User.query.get_or_404(banreq.user_id)
        user.is_active = False
        banreq.handled = True
        db.session.commit()
        flash(f'User {user.username} has been banned', 'success')
        return redirect(url_for('admin.banreq'))
    else:
        return render_template('403.html')


@adminbp.route('/users/noban/<banreq_id>', methods = ['POST'])
@login_required
@admin_required
def nobanuser(banreq_id):
    if current_user.role == 'Admin':
        banreq = BanReq.query.get_or_404(banreq_id)
        user = User.query.get_or_404(banreq.user_id)
        banreq.handled = True
        db.session.commit()
        flash(f'User {user.username} not banned', 'success')
        return redirect(url_for('admin.banreq'))
    else:
        return render_template('403.html')


@adminbp.route('/posts', methods = ['GET'])
@login_required
@admin_required
def viewposts():
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
            'image_url':  url_for('static', filename=f'images/post_images/{row.image_url}') if row.image_url else None,
            'created_at': row.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'likes': row.LIKES,
            'comments': row.COMMENTS,
        })

 
    return render_template('adminposts.html', posts = posts)


@adminbp.route('/posts/delete/<post_id>', methods = ['POST'])
@login_required
@admin_required
def delpost(post_id):
    if current_user.role == 'Admin':
        query = text('DELETE FROM POST WHERE POST_ID = :post_id')
        db.session.execute(query, {'post_id': post_id})
        db.session.commit()
        flash('Post deleted successfully', 'success')
    return redirect(url_for('admin.viewposts'))




