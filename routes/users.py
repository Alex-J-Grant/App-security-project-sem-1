# routes/users.py
from flask import Blueprint, render_template, request, redirect, url_for, flash, abort
from flask_login import login_required, current_user
from sqlalchemy import text, or_, and_
from extensions import db
from models.user import User
from models.friend import Friend, FriendRequest
from helperfuncs.logger import main_logger
from helperfuncs.post_likes import has_liked_post
users = Blueprint('users', __name__, url_prefix='/users')


@users.route('/<username>')
def user_profile(username):
    """Display user profile with posts and friend status"""
    try:
        main_logger.info(f'Viewing profile for user: {username}')

        # Get user by username
        user = User.query.filter_by(username=username).first()
        if not user:
            abort(404)

        # Get user's posts
        posts_query = text("""
            SELECT 
                p.POST_ID AS id,
                p.TITLE AS title,
                p.IMAGE AS image_url,
                p.DESCRIPT,
                p.CREATED_AT AS created_at,
                p.LIKE_COUNT AS likes,
                p.COMMENT_COUNT AS comments,
                s.NAME AS subcommunity_name,
                s.COMM_PFP AS subcommunity_pfp
            FROM POST p
            JOIN SUBCOMMUNITY s ON p.COMM_ID = s.ID
            WHERE p.USER_ID = :user_id
            ORDER BY p.CREATED_AT DESC
            LIMIT 20
        """)

        posts_result = db.session.execute(posts_query, {"user_id": user.id}).fetchall()

        posts = []
        for post in posts_result:
            posts.append({
                'id': post.id,
                'title': post.title,
                'description': post.DESCRIPT,
                'image_url': url_for('static',
                                     filename=f'images/post_images/{post.image_url}') if post.image_url else None,
                'subcommunity_name': post.subcommunity_name,
                'subcommunity_pfp': url_for('static',
                                            filename=f'images/profile_pictures/{post.subcommunity_pfp}') if post.subcommunity_pfp else '/static/images/SC_logo.png',
                'created_at': post.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'likes': post.likes,
                'comments': post.comments,
                'user_liked': has_liked_post(post.id)
            })

        # Determine friendship status if user is logged in
        friendship_status = 'none'
        can_message = False

        if current_user.is_authenticated and current_user.id != user.id:
            friendship_status = get_friendship_status(current_user.id, user.id)
            can_message = (friendship_status == 'friends')
        elif current_user.is_authenticated and current_user.id == user.id:
            friendship_status = 'self'
            can_message = False

        # Calculate some stats
        total_posts = len(posts)
        total_likes = sum(post['likes'] for post in posts)

        # Get friend count
        friend_count_result = db.session.execute(
            text("SELECT COUNT(*) FROM FRIENDS WHERE USER_ID = :user_id"),
            {"user_id": user.id}
        ).scalar()

        user_profile_data = {
            'id': user.id,
            'username': user.username,
            'fname': user.fname,
            'lname': user.lname,
            'userpfp': user.userpfp if user.userpfp else '/static/images/2903-default-blue.jpg',
            'created_at': user.created_at.strftime('%B %Y') if hasattr(user, 'created_at') else 'Unknown',
            'total_posts': total_posts,
            'total_likes': total_likes,
            'friend_count': friend_count_result or 0,
            'friendship_status': friendship_status,
            'can_message': can_message
        }

        return render_template('user_profile.html',
                               user=user_profile_data,
                               posts=posts)

    except Exception as e:
        main_logger.error(f'Error loading user profile {username}: {str(e)}')
        abort(500)


def get_friendship_status(current_user_id, target_user_id):
    """Get friendship status between current user and target user"""
    try:
        # Check if they're friends
        friendship = Friend.query.filter(
            or_(
                and_(Friend.USER_ID == current_user_id, Friend.FRIEND_ID == target_user_id),
                and_(Friend.USER_ID == target_user_id, Friend.FRIEND_ID == current_user_id)
            )
        ).first()

        if friendship:
            return 'friends'

        # Check if there's a pending request
        pending_request = FriendRequest.query.filter(
            or_(
                and_(FriendRequest.SENDER_ID == current_user_id, FriendRequest.RECV_ID == target_user_id),
                and_(FriendRequest.SENDER_ID == target_user_id, FriendRequest.RECV_ID == current_user_id)
            ),
            FriendRequest.STATUS == 'pending'
        ).first()

        if pending_request:
            if pending_request.SENDER_ID == current_user_id:
                return 'request_sent'
            else:
                return 'request_received'

        return 'none'

    except Exception as e:
        main_logger.error(f'Error getting friendship status: {str(e)}')
        return 'none'







