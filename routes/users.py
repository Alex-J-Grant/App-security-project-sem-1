# routes/users.py - Enhanced with OWASP security and communities feature
from flask import Blueprint, render_template, request, redirect, url_for, flash, abort
from flask_login import login_required, current_user
from sqlalchemy import text, or_, and_
from extensions import db
from models.user import User
from models.friend import Friend, FriendRequest
from helperfuncs.logger import main_logger
from helperfuncs.post_likes import has_liked_post

# Import security functions from your OWASP module
from security.friends_owasp_security import (
    require_authentication, sanitize_message_content,
    validate_search_input, rate_limit, secure_headers, log_security_event,
    validate_uuid
)

users = Blueprint('users', __name__, url_prefix='/users')


@users.route('/<username>')
@rate_limit('profile_view', limit=50, window=60)
@secure_headers
def user_profile(username):
    """Display user profile with posts, communities, and friend status"""
    try:
        # Enhanced input validation for username
        if not username:
            log_security_event('empty_username_profile_access', {
                'attempted_username': username
            })
            abort(400, "Username is required")

        # Sanitize username to prevent injection
        clean_username = validate_search_input(username)
        if not clean_username or clean_username != username:
            log_security_event('invalid_username_profile_access', {
                'original_username': username,
                'sanitized_username': clean_username
            })
            abort(400, "Invalid username format")

        # Additional username validation
        if len(username) > 50 or len(username) < 3:
            log_security_event('username_length_violation', {
                'username': username,
                'length': len(username)
            })
            abort(400, "Invalid username length")

        main_logger.info(f'Viewing profile for user: {username}')

        # Get user by username with enhanced error handling
        try:
            user = User.query.filter_by(username=username).first()
        except Exception as e:
            log_security_event('database_error_user_profile', {
                'error': str(e),
                'username': username
            }, level='ERROR')
            abort(500, "Database error occurred")

        if not user:
            log_security_event('nonexistent_user_profile_access', {
                'username': username
            })
            abort(404)

        # Get communities the user has joined with enhanced security
        joined_comm_query = text("""
            SELECT s.ID, s.NAME, s.COMM_PFP, s.TAG
            FROM COMMUNITY_MEMBERS cm
            JOIN SUBCOMMUNITY s ON cm.COMMUNITY_ID = s.ID
            WHERE cm.USER_ID = :user_id
            ORDER BY s.NAME
            LIMIT 50
        """)

        try:
            joined_communities = db.session.execute(joined_comm_query, {"user_id": user.id}).fetchall()
        except Exception as e:
            log_security_event('database_error_user_communities', {
                'error': str(e),
                'user_id': user.id
            }, level='ERROR')
            joined_communities = []

        # Format community data for template with security checks
        joined_community_data = []
        for comm in joined_communities:
            try:
                # Validate community data
                community_name = sanitize_message_content(comm.NAME) if comm.NAME else "Unknown Community"
                community_tag = sanitize_message_content(comm.TAG) if comm.TAG else ""

                # Security check for community ID
                if not validate_uuid(str(comm.ID)):
                    log_security_event('invalid_community_id_in_profile', {
                        'community_id': comm.ID,
                        'user_id': user.id
                    })
                    continue

                joined_community_data.append({
                    "id": comm.ID,
                    "name": community_name,
                    "tag": community_tag,
                    "icon": url_for('static',
                                    filename=f'images/profile_pictures/{comm.COMM_PFP}') if comm.COMM_PFP else '/static/images/SC_logo.png'
                })
            except Exception as e:
                # Log error but continue processing other communities
                log_security_event('community_processing_error', {
                    'error': str(e),
                    'community_id': getattr(comm, 'ID', 'unknown'),
                    'user_id': user.id
                })
                continue

        # Get user's posts with enhanced security
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

        try:
            posts_result = db.session.execute(posts_query, {"user_id": user.id}).fetchall()
        except Exception as e:
            log_security_event('database_error_user_posts', {
                'error': str(e),
                'user_id': user.id
            }, level='ERROR')
            posts_result = []

        posts = []
        for post in posts_result:
            try:
                # Validate post ID
                if not validate_uuid(str(post.id)):
                    log_security_event('invalid_post_id_in_profile', {
                        'post_id': post.id,
                        'user_id': user.id
                    })
                    continue

                # Sanitize post content
                post_title = sanitize_message_content(post.title) if post.title else "Untitled"
                post_description = sanitize_message_content(post.DESCRIPT) if post.DESCRIPT else ""
                subcommunity_name = sanitize_message_content(
                    post.subcommunity_name) if post.subcommunity_name else "Unknown"

                posts.append({
                    'id': post.id,
                    'title': post_title,
                    'description': post_description,
                    'image_url': url_for('static',
                                         filename=f'images/post_images/{post.image_url}') if post.image_url else None,
                    'subcommunity_name': subcommunity_name,
                    'subcommunity_pfp': url_for('static',
                                                filename=f'images/profile_pictures/{post.subcommunity_pfp}') if post.subcommunity_pfp else '/static/images/SC_logo.png',
                    'created_at': post.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                    'likes': post.likes,
                    'comments': post.comments,
                    'user_liked': has_liked_post(post.id)
                })
            except Exception as e:
                # Log error but continue processing other posts
                log_security_event('post_processing_error', {
                    'error': str(e),
                    'post_id': getattr(post, 'id', 'unknown'),
                    'user_id': user.id
                })
                continue

        # Determine friendship status if user is logged in
        friendship_status = 'none'
        can_message = False

        if current_user.is_authenticated and current_user.id != user.id:
            try:
                friendship_status = get_friendship_status(current_user.id, user.id)
                can_message = (friendship_status == 'friends')
            except Exception as e:
                log_security_event('friendship_status_error', {
                    'error': str(e),
                    'current_user': current_user.id,
                    'target_user': user.id
                })
                friendship_status = 'none'
                can_message = False
        elif current_user.is_authenticated and current_user.id == user.id:
            friendship_status = 'self'
            can_message = False

        # Calculate some stats
        total_posts = len(posts)
        total_likes = sum(post['likes'] for post in posts)
        total_communities = len(joined_community_data)

        # Get friend count with error handling
        try:
            friend_count_result = db.session.execute(
                text("SELECT COUNT(*) FROM FRIENDS WHERE USER_ID = :user_id"),
                {"user_id": user.id}
            ).scalar()
        except Exception as e:
            log_security_event('friend_count_error', {
                'error': str(e),
                'user_id': user.id
            })
            friend_count_result = 0

        # Sanitize user profile data
        try:
            sanitized_fname = sanitize_message_content(user.fname) if user.fname else ""
            sanitized_lname = sanitize_message_content(user.lname) if user.lname else ""
            sanitized_username = sanitize_message_content(user.username) if user.username else "Unknown"
        except Exception as e:
            log_security_event('user_data_sanitization_error', {
                'error': str(e),
                'user_id': user.id
            })
            sanitized_fname = "Unknown"
            sanitized_lname = ""
            sanitized_username = "Unknown"

        user_profile_data = {
            'id': user.id,
            'username': sanitized_username,
            'fname': sanitized_fname,
            'lname': sanitized_lname,
            'userpfp': "/static/images/profile_pictures/" + user.userpfp if user.userpfp else "/static/images/default_pfp.jpg",
            'created_at': user.created_at.strftime('%B %Y') if hasattr(user, 'created_at') else 'Unknown',
            'total_posts': total_posts,
            'total_likes': total_likes,
            'total_communities': total_communities,
            'friend_count': friend_count_result or 0,
            'friendship_status': friendship_status,
            'can_message': can_message
        }

        # Enhanced security logging for profile views
        log_security_event('user_profile_viewed', {
            'viewed_user': username,
            'viewer_authenticated': current_user.is_authenticated,
            'viewer_id': current_user.id if current_user.is_authenticated else 'anonymous',
            'posts_count': total_posts,
            'communities_count': total_communities,
            'friendship_status': friendship_status,
            'user_agent': request.user_agent.string,
            'ip_address': request.remote_addr
        }, level='INFO')

        return render_template('user_profile.html',
                               user=user_profile_data,
                               posts=posts,
                               joined_communities=joined_community_data)

    except Exception as e:
        main_logger.error(f'Error loading user profile {username}: {str(e)}')
        log_security_event('user_profile_critical_error', {
            'error': str(e),
            'username': username,
            'user_agent': request.user_agent.string
        }, level='ERROR')
        abort(500)


def get_friendship_status(current_user_id, target_user_id):
    """Get friendship status between current user and target user with enhanced security"""
    try:
        # Enhanced input validation
        if not validate_uuid(current_user_id) or not validate_uuid(target_user_id):
            log_security_event('invalid_uuid_friendship_status', {
                'current_user_id': current_user_id,
                'target_user_id': target_user_id
            })
            return 'none'

        # Prevent checking friendship status for other users (access control)
        if current_user.is_authenticated and current_user_id != current_user.id:
            log_security_event('unauthorized_friendship_status_check', {
                'requested_user_id': current_user_id,
                'actual_user_id': current_user.id
            })
            return 'none'

        # Check if they're friends with enhanced error handling
        try:
            friendship = Friend.query.filter(
                or_(
                    and_(Friend.USER_ID == current_user_id, Friend.FRIEND_ID == target_user_id),
                    and_(Friend.USER_ID == target_user_id, Friend.FRIEND_ID == current_user_id)
                )
            ).first()
        except Exception as e:
            log_security_event('friendship_query_error', {
                'error': str(e),
                'current_user_id': current_user_id,
                'target_user_id': target_user_id
            })
            return 'none'

        if friendship:
            return 'friends'

        # Check if there's a pending request with enhanced error handling
        try:
            pending_request = FriendRequest.query.filter(
                or_(
                    and_(FriendRequest.SENDER_ID == current_user_id, FriendRequest.RECV_ID == target_user_id),
                    and_(FriendRequest.SENDER_ID == target_user_id, FriendRequest.RECV_ID == current_user_id)
                ),
                FriendRequest.STATUS == 'pending'
            ).first()
        except Exception as e:
            log_security_event('friend_request_query_error', {
                'error': str(e),
                'current_user_id': current_user_id,
                'target_user_id': target_user_id
            })
            return 'none'

        if pending_request:
            if pending_request.SENDER_ID == current_user_id:
                return 'request_sent'
            else:
                return 'request_received'

        return 'none'

    except Exception as e:
        main_logger.error(f'Error getting friendship status: {str(e)}')
        log_security_event('friendship_status_critical_error', {
            'error': str(e),
            'current_user_id': current_user_id,
            'target_user_id': target_user_id
        }, level='ERROR')
        return 'none'