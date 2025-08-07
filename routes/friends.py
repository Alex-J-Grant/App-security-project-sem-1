# routes/friends.py - Complete OWASP Top 10 Security Implementation
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, abort
from flask_login import login_required, current_user
from sqlalchemy import or_, and_
from extensions import db
from models.user import User
from models.friend import FriendRequest, Friend, Message
from forms.friendforms import SendMessageForm, SearchUserForm
from helperfuncs.logger import main_logger
from helperfuncs.uuidgen import gen_uuid
from datetime import datetime
from rate_limiter_config import limiter
# Import all OWASP security features
from security.friends_owasp_security import (
    # A01: Access Control
    require_authentication, require_friendship, validate_resource_ownership,
    prevent_self_interaction,

    # A02: Cryptographic Failures
    # A03: Injection Prevention
    sanitize_message_content, validate_uuid, validate_search_input,

    # A04: Insecure Design
    rate_limit, validate_business_logic,

    # A05: Security Misconfiguration
    secure_headers,  # A06: Vulnerable Components
    # A07: Authentication Failures
    enhance_session_security,

    # A08: Data Integrity
    validate_message_integrity, generate_integrity_hash,

    # A09: Security Logging
    log_security_event, SecurityMonitor,

    # A10: SSRF Prevention
    validate_internal_request, prevent_url_manipulation
)

friends = Blueprint('friends', __name__, url_prefix='/friends')


# Apply global security decorators to all routes
@friends.before_request
@enhance_session_security()
@prevent_url_manipulation()
def before_request():
    """Apply security checks to all friends routes"""
    pass


@friends.route('/search', methods=['GET', 'POST'])
@login_required
@require_authentication
@rate_limit('search', limit=10, window=60)
@secure_headers
def search_users():
    """OWASP-secured user search functionality"""
    main_logger.info(f'User {current_user.username} accessing user search')
    form = SearchUserForm()
    users = []

    if form.validate_on_submit():
        # A03: Input validation and sanitization
        search_term = validate_search_input(form.search_term.data)

        if not search_term:
            flash('Invalid search term', 'danger')
            log_security_event('invalid_search_input', {
                'original_input': form.search_term.data,
                'sanitized_input': search_term
            })
            return render_template('search_users.html', form=form, users=users)

        try:
            # A03: Parameterized queries to prevent SQL injection
            users = User.query.filter(
                or_(
                    User.username.ilike(f'%{search_term}%'),
                    User.fname.ilike(f'%{search_term}%'),
                    User.lname.ilike(f'%{search_term}%')
                ),
                User.id != current_user.id  # A01: Access control
            ).limit(20).all()

            # Check friendship status with integrity validation
            for user in users:
                user.friendship_status = get_friendship_status(current_user.id, user.id)

            # A09: Log successful search
            log_security_event('user_search_performed', {
                'search_term': search_term,
                'results_count': len(users)
            }, level='INFO')

        except Exception as e:
            # A09: Security logging for errors
            log_security_event('search_error', {
                'error': str(e),
                'search_term': search_term
            }, level='ERROR')
            flash('Search failed due to a system error', 'danger')

    return render_template('search_users.html', form=form, users=users)


@friends.route('/send_request/<user_id>')
@login_required
@require_authentication
@prevent_self_interaction
@rate_limit('friend_request', limit=5, window=300)
@validate_business_logic
@secure_headers
def send_friend_request(user_id):
    """OWASP-secured friend request sending"""
    try:
        # A03 & A05: Input validation
        if not validate_uuid(user_id):
            log_security_event('invalid_uuid_friend_request', {
                'invalid_user_id': user_id
            }, level='ERROR')
            abort(400, "Invalid user ID format")

        main_logger.info(f'User {current_user.username} sending friend request to {user_id}')

        # A01: Verify target user exists
        target_user = User.query.get(user_id)
        if not target_user:
            flash('User not found', 'danger')
            return redirect(url_for('friends.search_users'))

        # A04: Business logic validation - check for existing requests
        existing_request = FriendRequest.query.filter(
            or_(
                and_(FriendRequest.SENDER_ID == current_user.id, FriendRequest.RECV_ID == user_id),
                and_(FriendRequest.SENDER_ID == user_id, FriendRequest.RECV_ID == current_user.id)
            ),
            FriendRequest.STATUS == 'pending'
        ).first()

        if existing_request:
            flash('Friend request already pending', 'info')
            return redirect(url_for('friends.search_users'))

        # A08: Data integrity - create request with validation
        request_data = {
            'sender_id': current_user.id,
            'receiver_id': user_id,
            'timestamp': datetime.utcnow().isoformat()
        }

        integrity_hash = generate_integrity_hash(request_data)

        friend_request = FriendRequest(
            SENDER_ID=current_user.id,
            RECV_ID=user_id
        )

        db.session.add(friend_request)
        db.session.commit()

        # A09: Security monitoring
        SecurityMonitor.log_friend_request(current_user.id, user_id, 'sent')

        flash(f'Friend request sent to {target_user.username}', 'success')
        return redirect(url_for('friends.search_users'))

    except Exception as e:
        db.session.rollback()
        log_security_event('friend_request_error', {
            'error': str(e),
            'target_user': user_id
        }, level='ERROR')
        flash('Failed to send friend request', 'danger')
        return redirect(url_for('friends.search_users'))


@friends.route('/requests')
@login_required
@require_authentication
@secure_headers
def view_requests():
    """OWASP-secured friend requests viewing"""
    try:
        main_logger.info(f'User {current_user.username} viewing friend requests')

        # A01: Access control - only show user's own requests
        pending_requests = FriendRequest.query.filter_by(
            RECV_ID=current_user.id,
            STATUS='pending'
        ).all()

        sent_requests = FriendRequest.query.filter_by(
            SENDER_ID=current_user.id,
            STATUS='pending'
        ).all()

        # A09: Log request viewing
        log_security_event('friend_requests_viewed', {
            'pending_count': len(pending_requests),
            'sent_count': len(sent_requests)
        }, level='INFO')

        return render_template('friend_requests.html',
                               pending_requests=pending_requests,
                               sent_requests=sent_requests)
    except Exception as e:
        log_security_event('view_requests_error', {
            'error': str(e)
        }, level='ERROR')
        flash('Error loading requests', 'danger')
        return redirect(url_for('friends.search_users'))


@friends.route('/respond_request/<int:request_id>/<action>')
@login_required
@require_authentication
@validate_resource_ownership
@rate_limit('respond_request', limit=10, window=60)
@secure_headers
def respond_request(request_id, action):
    """OWASP-secured friend request response"""
    # A05: Input validation
    if action not in ['accept', 'reject']:
        log_security_event('invalid_friend_request_action', {
            'action': action,
            'request_id': request_id
        }, level='ERROR')
        abort(400, "Invalid action")

    try:
        main_logger.info(f'User {current_user.username} responding to friend request {request_id} with {action}')

        # A01: Access control validation
        friend_request = FriendRequest.query.get(request_id)
        if not friend_request or friend_request.RECV_ID != current_user.id:
            log_security_event('unauthorized_friend_request_response', {
                'request_id': request_id,
                'action': action
            }, level='ERROR')
            abort(403, "Unauthorized access to friend request")

        # A08: Data integrity validation
        if friend_request.STATUS != 'pending':
            flash('Friend request is no longer pending', 'info')
            return redirect(url_for('friends.view_requests'))

        if action == 'accept':
            friend_request.STATUS = 'accepted'

            # A04: Business logic - create bidirectional friendship
            friendship1 = Friend(USER_ID=current_user.id, FRIEND_ID=friend_request.SENDER_ID)
            friendship2 = Friend(USER_ID=friend_request.SENDER_ID, FRIEND_ID=current_user.id)

            db.session.add(friendship1)
            db.session.add(friendship2)
            flash('Friend request accepted!', 'success')
        else:
            friend_request.STATUS = 'rejected'
            flash('Friend request rejected', 'info')

        db.session.commit()

        # A09: Security monitoring
        SecurityMonitor.log_friend_request(friend_request.SENDER_ID, current_user.id, action)

    except Exception as e:
        db.session.rollback()
        log_security_event('respond_request_error', {
            'error': str(e),
            'request_id': request_id,
            'action': action
        }, level='ERROR')
        flash('Failed to process request', 'danger')

    return redirect(url_for('friends.view_requests'))


@friends.route('/list')
@login_required
@require_authentication
@secure_headers
def friends_list():
    """OWASP-secured friends list viewing"""
    try:
        main_logger.info(f'User {current_user.username} viewing friends list')

        # A01: Access control - only show user's own friends
        friends_data = []
        friend_relationships = Friend.query.filter_by(USER_ID=current_user.id).all()

        for friendship in friend_relationships:
            friend_user = User.query.get(friendship.FRIEND_ID)
            if friend_user:
                friends_data.append((friendship, friend_user))

        # A09: Log friends list access
        log_security_event('friends_list_viewed', {
            'friends_count': len(friends_data)
        }, level='INFO')

        return render_template('friends_list.html', friends_data=friends_data)

    except Exception as e:
        log_security_event('friends_list_error', {
            'error': str(e)
        }, level='ERROR')
        flash('Error loading friends', 'danger')
        return redirect(url_for('friends.search_users'))


@friends.route('/messages')
@login_required
@require_authentication
@secure_headers
def messages_overview():
    """OWASP-secured messages overview"""
    try:
        main_logger.info(f'User {current_user.username} viewing messages overview')

        # A01: Access control - only show user's own messages
        recent_messages = db.session.query(Message).filter(
            or_(Message.SENDER_ID == current_user.id, Message.RECV_ID == current_user.id)
        ).order_by(Message.CREATED_AT.desc()).limit(50).all()

        # Group by conversation partner
        conversations = {}
        for msg in recent_messages:
            partner_id = msg.RECV_ID if msg.SENDER_ID == current_user.id else msg.SENDER_ID
            if partner_id not in conversations:
                partner = User.query.get(partner_id)
                if partner:
                    conversations[partner_id] = {
                        'partner': partner,
                        'last_message': msg,
                        'unread_count': 0
                    }

            # Count unread messages from this partner
            if msg.RECV_ID == current_user.id and not msg.IS_READ:
                conversations[partner_id]['unread_count'] += 1

        # A09: Log messages overview access
        log_security_event('messages_overview_viewed', {
            'conversations_count': len(conversations),
            'total_recent_messages': len(recent_messages)
        }, level='INFO')

        return render_template('messages_overview.html', conversations=conversations)

    except Exception as e:
        log_security_event('messages_overview_error', {
            'error': str(e)
        }, level='ERROR')
        flash('Error loading messages', 'danger')
        return redirect(url_for('friends.friends_list'))


@friends.route('/chat/<friend_id>')
@login_required
@require_authentication
@require_friendship
@secure_headers
@limiter.limit("1000 per minute")
def chat(friend_id):
    """OWASP-secured chat interface"""
    # A03 & A05: Input validation
    if not validate_uuid(friend_id):
        log_security_event('invalid_uuid_chat_access', {
            'invalid_friend_id': friend_id
        }, level='ERROR')
        abort(400, "Invalid user ID format")

    try:
        main_logger.info(f'User {current_user.username} chatting with {friend_id}')

        # A01: Verify friend exists and friendship
        friend = User.query.get(friend_id)
        if not friend:
            flash('User not found', 'danger')
            return redirect(url_for('friends.friends_list'))

        # Get chat history with limit for performance (A05: Resource management)
        messages = Message.query.filter(
            or_(
                and_(Message.SENDER_ID == current_user.id, Message.RECV_ID == friend_id),
                and_(Message.SENDER_ID == friend_id, Message.RECV_ID == current_user.id)
            )
        ).order_by(Message.CREATED_AT.asc()).limit(100).all()

        # Mark messages as read
        try:
            Message.query.filter_by(
                SENDER_ID=friend_id,
                RECV_ID=current_user.id,
                IS_READ=False
            ).update({'IS_READ': True})
            db.session.commit()
        except Exception as e:
            main_logger.error(f'Failed to mark messages as read: {str(e)}')

        form = SendMessageForm()
        form.friend_id.data = friend_id

        # A09: Log chat access
        log_security_event('chat_accessed', {
            'friend_id': friend_id,
            'messages_count': len(messages)
        }, level='INFO')

        return render_template('chat.html', friend=friend, messages=messages, form=form)

    except Exception as e:
        log_security_event('chat_error', {
            'error': str(e),
            'friend_id': friend_id
        }, level='ERROR')
        flash('Error loading chat', 'danger')
        return redirect(url_for('friends.friends_list'))


@friends.route('/send_message', methods=['POST'])
@login_required
@require_authentication
@rate_limit('send_message', limit=20, window=60)
@secure_headers
def send_message():
    """OWASP-secured message sending"""
    try:
        form = SendMessageForm()

        if form.validate_on_submit():
            friend_id = form.friend_id.data
            content = form.content.data

            # A08: Data integrity validation
            message_data = {'friend_id': friend_id, 'content': content}
            is_valid, error_msg = validate_message_integrity(message_data)

            if not is_valid:
                log_security_event('invalid_message_data', {
                    'error': error_msg,
                    'friend_id': friend_id
                }, level='ERROR')
                return jsonify({'success': False, 'error': error_msg}), 400

            # A01: Access control - verify friendship
            friendship = Friend.query.filter_by(USER_ID=current_user.id, FRIEND_ID=friend_id).first()
            if not friendship:
                log_security_event('unauthorized_message_attempt', {
                    'friend_id': friend_id
                }, level='ERROR')
                return jsonify({'success': False, 'error': 'Unauthorized'}), 403

            # A03: Sanitize message content
            clean_content = sanitize_message_content(content)

            # A08: Generate message with integrity
            message = Message(
                ID=gen_uuid(),
                SENDER_ID=current_user.id,
                RECV_ID=friend_id,
                CONTENT=clean_content
            )

            db.session.add(message)
            db.session.commit()

            # A09: Security monitoring
            SecurityMonitor.log_message_sent(current_user.id, friend_id, len(clean_content))

            return jsonify({'success': True, 'message': 'Message sent'})

        return jsonify({'success': False, 'error': 'Invalid form data'}), 400

    except Exception as e:
        db.session.rollback()
        log_security_event('send_message_error', {
            'error': str(e)
        }, level='ERROR')
        return jsonify({'success': False, 'error': 'Failed to send message'}), 500


@friends.route('/api/messages/<friend_id>')
@login_required
@require_authentication
@require_friendship
@validate_internal_request()
@secure_headers
@limiter.limit("1000 per minute")
def get_messages_api(friend_id):
    """OWASP-secured messages API for real-time chat"""
    try:
        # A03 & A05: Input validation
        if not validate_uuid(friend_id):
            return jsonify({'success': False, 'error': 'Invalid ID format'}), 400

        since_timestamp = request.args.get('since_time', '', type=str)

        # A03: Build query with parameterized inputs
        query = Message.query.filter(
            or_(
                and_(Message.SENDER_ID == current_user.id, Message.RECV_ID == friend_id),
                and_(Message.SENDER_ID == friend_id, Message.RECV_ID == current_user.id)
            )
        )

        # Filter by timestamp if provided
        if since_timestamp:
            try:
                since_dt = datetime.fromisoformat(since_timestamp.replace('Z', '+00:00'))
                query = query.filter(Message.CREATED_AT > since_dt)
            except Exception as e:
                # A09: Log invalid timestamp attempts
                log_security_event('invalid_timestamp_api', {
                    'timestamp': since_timestamp,
                    'error': str(e)
                })

        # A05: Limit results for performance
        messages = query.order_by(Message.CREATED_AT.asc()).limit(50).all()

        # Mark messages as read
        try:
            Message.query.filter_by(
                SENDER_ID=friend_id,
                RECV_ID=current_user.id,
                IS_READ=False
            ).update({'IS_READ': True})
            db.session.commit()
        except Exception as e:
            main_logger.error(f'Failed to mark messages as read: {str(e)}')

        # Convert to JSON with sanitized content
        messages_data = []
        for msg in messages:
            messages_data.append({
                'id': msg.ID,
                'sender_id': msg.SENDER_ID,
                'receiver_id': msg.RECV_ID,
                'content': msg.CONTENT,  # Already sanitized when saved
                'created_at': msg.CREATED_AT.isoformat(),
                'is_read': msg.IS_READ
            })

        return jsonify({'success': True, 'messages': messages_data})

    except Exception as e:
        log_security_event('get_messages_error', {
            'error': str(e),
            'friend_id': friend_id
        }, level='ERROR')
        return jsonify({'success': False, 'error': 'Failed to get messages'}), 500


def get_friendship_status(user_id, target_id):
    """Helper function to get friendship status between two users"""
    try:
        # A01: Access control - only check relationships involving current user
        if user_id != current_user.id:
            return 'none'

        # Check if they're friends
        friendship = Friend.query.filter(
            or_(
                and_(Friend.USER_ID == user_id, Friend.FRIEND_ID == target_id),
                and_(Friend.USER_ID == target_id, Friend.FRIEND_ID == user_id)
            )
        ).first()

        if friendship:
            return 'friends'

        # Check if there's a pending request
        pending_request = FriendRequest.query.filter(
            or_(
                and_(FriendRequest.SENDER_ID == user_id, FriendRequest.RECV_ID == target_id),
                and_(FriendRequest.SENDER_ID == target_id, FriendRequest.RECV_ID == user_id)
            ),
            FriendRequest.STATUS == 'pending'
        ).first()

        if pending_request:
            if pending_request.SENDER_ID == user_id:
                return 'request_sent'
            else:
                return 'request_received'

        return 'none'

    except Exception as e:
        log_security_event('friendship_status_error', {
            'error': str(e),
            'user_id': user_id,
            'target_id': target_id
        }, level='ERROR')
        return 'none'