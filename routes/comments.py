# routes/comments.py - Enhanced with OWASP security
from flask import Blueprint, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from extensions import db
from models.comment import Comment, Reply
from helperfuncs.uuidgen import gen_uuid
from helperfuncs.logger import main_logger
import bleach
from sqlalchemy import text

# Import security functions from your OWASP module
from security.friends_owasp_security import (
    require_authentication, sanitize_message_content,
    validate_uuid, rate_limit, secure_headers, log_security_event
)

comments = Blueprint('comments', __name__, url_prefix='/comments')


@comments.route('/add_comment', methods=['POST'])
@login_required
@require_authentication
@rate_limit('comment', limit=10, window=60)
@secure_headers
def add_comment():
    """Add a new comment to a post"""
    try:
        # Debug: Print form data
        print("=== DEBUG: Add Comment ===")
        print(f"Form data: {request.form}")
        print(f"Current user: {current_user.username}")

        # Get form data directly with enhanced validation
        post_id = request.form.get('post_id')
        content = request.form.get('content')

        print(f"Post ID: {post_id}")
        print(f"Content: {content}")

        # Enhanced validation
        if not post_id or not validate_uuid(post_id):
            log_security_event('invalid_post_id_comment', {
                'post_id': post_id
            }, level='ERROR')
            flash('Invalid post ID', 'danger')
            return redirect(request.referrer or url_for('home.home'))

        if not content:
            flash('Missing post ID or content', 'danger')
            return redirect(request.referrer or url_for('home.home'))

        # Enhanced content sanitization using OWASP security
        content = sanitize_message_content(content)

        if not content:
            flash('Comment cannot be empty', 'danger')
            return redirect(request.referrer or url_for('home.home'))

        # Additional length check
        if len(content) > 500:
            log_security_event('comment_too_long', {
                'content_length': len(content),
                'post_id': post_id
            })
            flash('Comment too long (max 500 characters)', 'danger')
            return redirect(request.referrer or url_for('home.home'))

        # Validate post exists
        post_check = db.session.execute(
            text("SELECT POST_ID FROM POST WHERE POST_ID = :post_id"),
            {"post_id": post_id}
        ).fetchone()

        if not post_check:
            log_security_event('comment_on_nonexistent_post', {
                'post_id': post_id
            })
            flash('Post not found', 'danger')
            return redirect(url_for('home.home'))

        print("Post exists, creating comment...")

        # Create comment
        comment_id = gen_uuid()

        # Insert using raw SQL to avoid model issues
        insert_sql = text("""
            INSERT INTO COMMENTS (COMMENT_ID, POST_ID, USER_ID, CONTENT, LIKE_COUNT, CREATED_AT)
            VALUES (:comment_id, :post_id, :user_id, :content, 0, NOW())
        """)

        db.session.execute(insert_sql, {
            'comment_id': comment_id,
            'post_id': post_id,
            'user_id': current_user.id,
            'content': content
        })

        # Update comment count in post
        update_sql = text("UPDATE POST SET COMMENT_COUNT = COMMENT_COUNT + 1 WHERE POST_ID = :post_id")
        db.session.execute(update_sql, {"post_id": post_id})

        db.session.commit()

        print("Comment created successfully!")
        main_logger.info(f'User {current_user.username} added comment to post {post_id}')

        # Security logging
        log_security_event('comment_added', {
            'post_id': post_id,
            'comment_id': comment_id,
            'content_length': len(content)
        }, level='INFO')

        flash('Comment added successfully!', 'success')

    except Exception as e:
        db.session.rollback()
        print(f"ERROR: {str(e)}")
        main_logger.error(f'Error adding comment: {str(e)}')
        log_security_event('comment_creation_error', {
            'error': str(e),
            'post_id': post_id
        }, level='ERROR')
        flash('Failed to add comment. Please try again.', 'danger')

    # Redirect back to the post
    return redirect(url_for('view_post.view_post_route', post_id=post_id))


@comments.route('/add_reply', methods=['POST'])
@login_required
@require_authentication
@rate_limit('reply', limit=15, window=60)
@secure_headers
def add_reply():
    """Add a reply to a comment"""
    try:
        print("=== DEBUG: Add Reply ===")
        print(f"Form data: {request.form}")

        # Get form data directly with enhanced validation
        comment_id = request.form.get('comment_id')
        content = request.form.get('content')

        # Enhanced validation
        if not comment_id or not validate_uuid(comment_id):
            log_security_event('invalid_comment_id_reply', {
                'comment_id': comment_id
            }, level='ERROR')
            flash('Invalid comment ID', 'danger')
            return redirect(request.referrer or url_for('home.home'))

        if not content:
            flash('Missing comment ID or content', 'danger')
            return redirect(request.referrer or url_for('home.home'))

        # Enhanced content sanitization using OWASP security
        content = sanitize_message_content(content)

        if not content:
            flash('Reply cannot be empty', 'danger')
            return redirect(request.referrer or url_for('home.home'))

        # Additional length check
        if len(content) > 500:
            log_security_event('reply_too_long', {
                'content_length': len(content),
                'comment_id': comment_id
            })
            flash('Reply too long (max 500 characters)', 'danger')
            return redirect(request.referrer or url_for('home.home'))

        # Validate comment exists and get post_id
        comment_check = db.session.execute(
            text("SELECT COMMENT_ID, POST_ID FROM COMMENTS WHERE COMMENT_ID = :comment_id"),
            {"comment_id": comment_id}
        ).fetchone()

        if not comment_check:
            log_security_event('reply_to_nonexistent_comment', {
                'comment_id': comment_id
            })
            flash('Comment not found', 'danger')
            return redirect(url_for('home.home'))

        post_id = comment_check[1]  # Get POST_ID from the query result

        # Create reply using raw SQL
        reply_id = gen_uuid()

        insert_sql = text("""
            INSERT INTO REPLIES (REPLY_ID, COMMENT_ID, USER_ID, CONTENT, LIKE_COUNT, CREATED_AT)
            VALUES (:reply_id, :comment_id, :user_id, :content, 0, NOW())
        """)

        db.session.execute(insert_sql, {
            'reply_id': reply_id,
            'comment_id': comment_id,
            'user_id': current_user.id,
            'content': content
        })

        db.session.commit()

        main_logger.info(f'User {current_user.username} added reply to comment {comment_id}')

        # Security logging
        log_security_event('reply_added', {
            'comment_id': comment_id,
            'reply_id': reply_id,
            'post_id': post_id,
            'content_length': len(content)
        }, level='INFO')

        flash('Reply added successfully!', 'success')

        # Redirect back to the post
        return redirect(url_for('view_post.view_post_route', post_id=post_id))

    except Exception as e:
        db.session.rollback()
        print(f"ERROR: {str(e)}")
        main_logger.error(f'Error adding reply: {str(e)}')
        log_security_event('reply_creation_error', {
            'error': str(e),
            'comment_id': comment_id
        }, level='ERROR')
        flash('Failed to add reply. Please try again.', 'danger')
        return redirect(request.referrer or url_for('home.home'))


@comments.route('/get_comments/<post_id>')
@rate_limit('get_comments', limit=30, window=60)
@secure_headers
def get_comments(post_id):
    """API endpoint to get comments for a post (for AJAX loading)"""
    try:
        # Enhanced validation
        if not validate_uuid(post_id):
            log_security_event('invalid_post_id_get_comments', {
                'post_id': post_id
            }, level='ERROR')
            return jsonify({'success': False, 'error': 'Invalid post ID'}), 400

        # Get comments with user info
        comments_query = text("""
            SELECT 
                c.COMMENT_ID, c.CONTENT, c.LIKE_COUNT, c.CREATED_AT,
                u.USERNAME, u.USERPFP
            FROM COMMENTS c
            JOIN USERS u ON c.USER_ID = u.USER_ID
            WHERE c.POST_ID = :post_id
            ORDER BY c.CREATED_AT ASC
        """)

        comments_result = db.session.execute(comments_query, {"post_id": post_id}).fetchall()

        comments_data = []
        for comment in comments_result:
            # Get replies for this comment
            replies_query = text("""
                SELECT 
                    r.REPLY_ID, r.CONTENT, r.LIKE_COUNT, r.CREATED_AT,
                    u.USERNAME, u.USERPFP
                FROM REPLIES r
                JOIN USERS u ON r.USER_ID = u.USER_ID
                WHERE r.COMMENT_ID = :comment_id
                ORDER BY r.CREATED_AT ASC
            """)

            replies_result = db.session.execute(replies_query, {"comment_id": comment.COMMENT_ID}).fetchall()

            replies_data = [{
                'reply_id': reply.REPLY_ID,
                'content': reply.CONTENT,
                'username': reply.USERNAME,
                'userpfp': "/static/images/profile_pictures/" + reply.USERPFP if reply.USERPFP else "/static/images/default_pfp.jpg",
                'created_at': reply.CREATED_AT.strftime('%Y-%m-%d %H:%M:%S'),
                'like_count': reply.LIKE_COUNT
            } for reply in replies_result]

            comments_data.append({
                'comment_id': comment.COMMENT_ID,
                'content': comment.CONTENT,
                'username': comment.USERNAME,
                'userpfp': "/static/images/profile_pictures/" + comment.USERPFP if comment.USERPFP else "/static/images/default_pfp.jpg",
                'created_at': comment.CREATED_AT.strftime('%Y-%m-%d %H:%M:%S'),
                'like_count': comment.LIKE_COUNT,
                'replies': replies_data
            })

        # Security logging for API access
        log_security_event('comments_retrieved', {
            'post_id': post_id,
            'comments_count': len(comments_data)
        }, level='INFO')

        return jsonify({'success': True, 'comments': comments_data})

    except Exception as e:
        print(f"ERROR getting comments: {str(e)}")
        main_logger.error(f'Error getting comments: {str(e)}')
        log_security_event('get_comments_error', {
            'error': str(e),
            'post_id': post_id
        }, level='ERROR')
        return jsonify({'success': False, 'error': 'Failed to load comments'})