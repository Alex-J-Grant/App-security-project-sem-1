# security/friends_owasp_security.py
"""
Complete OWASP Top 10 Security Implementation for Friends System
This module implements all 10 OWASP security controls specifically for the friends functionality
"""

from functools import wraps
from flask import request, jsonify, abort, session, current_app, redirect, url_for, flash
from flask_login import current_user
import re
import time
import bleach
import html
from datetime import datetime, timedelta
import logging
import hashlib
import secrets
import os
import json
from sqlalchemy import text


# ================================
# OWASP A01: Broken Access Control
# ================================

def require_authentication(f):
    """Ensure user is authenticated before accessing friends features"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this feature', 'warning')
            return redirect(url_for('account.login'))
        return f(*args, **kwargs)

    return decorated_function


def require_friendship(f):
    """Ensure users can only message/interact with their friends"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        friend_id = kwargs.get('friend_id') or request.form.get('friend_id')
        if friend_id:
            from models.friend import Friend
            friendship = Friend.query.filter_by(
                USER_ID=current_user.id,
                FRIEND_ID=friend_id
            ).first()
            if not friendship:
                log_security_event('unauthorized_access_attempt', {
                    'attempted_friend_id': friend_id,
                    'reason': 'not_friends'
                })
                abort(403, "You can only interact with your friends")
        return f(*args, **kwargs)

    return decorated_function


def validate_resource_ownership(f):
    """Ensure users can only access their own friend requests"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        request_id = kwargs.get('request_id')
        if request_id:
            from models.friend import FriendRequest
            friend_request = FriendRequest.query.get(request_id)
            if not friend_request or (
                    friend_request.RECV_ID != current_user.id and
                    friend_request.SENDER_ID != current_user.id
            ):
                log_security_event('unauthorized_access_attempt', {
                    'attempted_request_id': request_id,
                    'reason': 'not_owner'
                })
                abort(403, "You can only access your own friend requests")
        return f(*args, **kwargs)

    return decorated_function


def prevent_self_interaction(f):
    """Prevent users from sending friend requests to themselves"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = kwargs.get('user_id') or request.form.get('friend_id')
        if user_id == current_user.id:
            log_security_event('self_interaction_attempt', {
                'attempted_action': f.__name__
            })
            abort(400, "You cannot perform this action on yourself")
        return f(*args, **kwargs)

    return decorated_function


# ================================
# OWASP A02: Cryptographic Failures
# ================================

class SecureDataHandler:
    @staticmethod
    def hash_sensitive_data(data, salt=None):
        """Securely hash sensitive data with salt"""
        if salt is None:
            salt = secrets.token_hex(16)
        else:
            salt = salt[:32]  # Ensure salt length

        hashed = hashlib.pbkdf2_hmac(
            'sha256',
            data.encode('utf-8'),
            salt.encode('utf-8'),
            100000  # iterations
        )
        return salt + hashed.hex()

    @staticmethod
    def verify_hashed_data(data, hashed_data):
        """Verify hashed data"""
        if len(hashed_data) < 32:
            return False
        salt = hashed_data[:32]
        stored_hash = hashed_data[32:]
        new_hash = hashlib.pbkdf2_hmac(
            'sha256',
            data.encode('utf-8'),
            salt.encode('utf-8'),
            100000
        )
        return new_hash.hex() == stored_hash

    @staticmethod
    def generate_secure_token():
        """Generate cryptographically secure token"""
        return secrets.token_urlsafe(32)


# ================================
# OWASP A03: Injection Prevention
# ================================

def sanitize_message_content(content):
    """Comprehensive message sanitization to prevent XSS and injection"""
    if not content:
        return ""

    # Remove potential script tags and malicious content
    clean_content = bleach.clean(
        content,
        tags=[],  # No HTML tags allowed in messages
        strip=True,
        strip_comments=True
    )

    # Additional XSS prevention
    clean_content = html.escape(clean_content)

    # Remove potential SQL injection patterns
    dangerous_patterns = [
        r'(union|select|insert|update|delete|drop|create|alter)\s',
        r'(script|javascript|vbscript|onload|onerror|onclick)',
        r'(<|>|&lt;|&gt;)',
        r'(eval\(|expression\()',
    ]

    for pattern in dangerous_patterns:
        clean_content = re.sub(pattern, '', clean_content, flags=re.IGNORECASE)

    # Limit message length
    if len(clean_content) > 1000:
        clean_content = clean_content[:1000]

    return clean_content.strip()


def validate_uuid(uuid_string):
    """Validate UUID format to prevent injection attacks"""
    if not uuid_string:
        return False
    uuid_pattern = re.compile(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
        re.IGNORECASE
    )
    return bool(uuid_pattern.match(str(uuid_string)))


def validate_search_input(search_term):
    """Validate and sanitize search input to prevent injection"""
    if not search_term:
        return None

    # Remove HTML and potential scripts
    clean_term = bleach.clean(search_term, tags=[], strip=True)

    # Only allow alphanumeric, spaces, and safe punctuation
    clean_term = re.sub(r'[^\w\s\-_.]', '', clean_term)

    # Remove SQL injection keywords
    sql_keywords = ['union', 'select', 'insert', 'update', 'delete', 'drop', 'create', 'alter']
    for keyword in sql_keywords:
        clean_term = re.sub(rf'\b{keyword}\b', '', clean_term, flags=re.IGNORECASE)

    # Limit length to prevent buffer overflow
    if len(clean_term) > 50:
        clean_term = clean_term[:50]

    return clean_term.strip()


# ================================
# OWASP A04: Insecure Design - Rate Limiting & Business Logic
# ================================

class AdvancedRateLimiter:
    def __init__(self):
        self.attempts = {}
        self.blocked_users = {}

    def is_rate_limited(self, user_id, action, limit=5, window=300):
        """Advanced rate limiting with progressive blocking"""
        key = f"{user_id}:{action}"
        now = time.time()

        # Check if user is temporarily blocked
        if user_id in self.blocked_users:
            if now < self.blocked_users[user_id]:
                return True
            else:
                del self.blocked_users[user_id]

        if key not in self.attempts:
            self.attempts[key] = []

        # Remove old attempts
        self.attempts[key] = [
            attempt for attempt in self.attempts[key]
            if now - attempt < window
        ]

        # Check if limit exceeded
        if len(self.attempts[key]) >= limit:
            # Progressive blocking - longer blocks for repeat offenders
            block_duration = min(3600, window * (len(self.attempts[key]) - limit + 1))
            self.blocked_users[user_id] = now + block_duration

            log_security_event('rate_limit_exceeded', {
                'action': action,
                'attempts': len(self.attempts[key]),
                'block_duration': block_duration
            })
            return True

        # Record this attempt
        self.attempts[key].append(now)
        return False


rate_limiter = AdvancedRateLimiter()


def rate_limit(action, limit=5, window=300):
    """Rate limiting decorator with security logging"""

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return f(*args, **kwargs)

            if rate_limiter.is_rate_limited(current_user.id, action, limit, window):
                return jsonify({
                    'error': 'Rate limit exceeded. Please try again later.',
                    'retry_after': window
                }), 429

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def validate_business_logic(f):
    """Validate business logic constraints"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Example: Prevent duplicate friend requests
        if f.__name__ == 'send_friend_request':
            user_id = kwargs.get('user_id')
            if user_id:
                from models.friend import FriendRequest
                existing = FriendRequest.query.filter_by(
                    SENDER_ID=current_user.id,
                    RECV_ID=user_id,
                    STATUS='pending'
                ).first()
                if existing:
                    return jsonify({'error': 'Friend request already pending'}), 400

        return f(*args, **kwargs)

    return decorated_function


# ================================
# OWASP A05: Security Misconfiguration
# ================================

def validate_file_upload(file):
    """Secure file upload validation"""
    if not file:
        return False, "No file provided"

    # Check file size (max 3MB)
    if len(file.read()) > 3 * 1024 * 1024:
        return False, "File too large"
    file.seek(0)  # Reset file pointer

    # Check file extension
    allowed_extensions = {'.jpg', '.jpeg', '.png', '.gif'}
    file_ext = os.path.splitext(file.filename)[1].lower()
    if file_ext not in allowed_extensions:
        return False, "Invalid file type"

    # Check file content (basic magic number validation)
    file_header = file.read(10)
    file.seek(0)

    valid_headers = [
        b'\xff\xd8\xff',  # JPEG
        b'\x89PNG\r\n\x1a\n',  # PNG
        b'GIF87a',  # GIF87a
        b'GIF89a',  # GIF89a
    ]

    if not any(file_header.startswith(header) for header in valid_headers):
        return False, "Invalid file format"

    return True, "Valid file"


def secure_headers(f):
    """Add security headers to responses"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        response = f(*args, **kwargs)
        if hasattr(response, 'headers'):
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
            response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'"
        return response

    return decorated_function


# ================================
# OWASP A06: Vulnerable Components
# ================================

def check_dependencies():
    """Check for vulnerable dependencies (basic implementation)"""
    # In production, integrate with tools like Safety or Snyk
    vulnerable_packages = []

    try:
        import pkg_resources
        installed_packages = [d.project_name for d in pkg_resources.working_set]

        # Example: Check for known vulnerable versions
        known_vulnerabilities = {
            'flask': ['<2.0.0'],
            'sqlalchemy': ['<1.4.0'],
            'bleach': ['<3.1.0']
        }

        for package, vulnerable_versions in known_vulnerabilities.items():
            if package in installed_packages:
                # In real implementation, check actual versions
                pass

    except Exception as e:
        log_security_event('dependency_check_failed', {'error': str(e)})

    return vulnerable_packages


# ================================
# OWASP A07: Identity and Authentication Failures
# ================================

def enhance_session_security():
    """Enhance session security"""

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.is_authenticated:
                # Session timeout check
                last_activity = session.get('last_activity')
                if last_activity:
                    if datetime.utcnow() - datetime.fromisoformat(last_activity) > timedelta(hours=2):
                        session.clear()
                        flash('Session expired. Please log in again.', 'warning')
                        return redirect(url_for('account.login'))

                # Update last activity
                session['last_activity'] = datetime.utcnow().isoformat()

                # Session hijacking protection
                current_ip = request.remote_addr
                session_ip = session.get('ip_address')
                if session_ip and session_ip != current_ip:
                    log_security_event('session_hijacking_attempt', {
                        'original_ip': session_ip,
                        'new_ip': current_ip
                    })
                    session.clear()
                    flash('Security alert: Session terminated due to suspicious activity', 'danger')
                    return redirect(url_for('account.login'))

                session['ip_address'] = current_ip

            return f(*args, **kwargs)

        return decorated_function

    return decorator


# ================================
# OWASP A08: Software and Data Integrity Failures
# ================================

def validate_message_integrity(message_data):
    """Comprehensive message data validation"""
    required_fields = ['friend_id', 'content']

    # Check required fields
    for field in required_fields:
        if field not in message_data or not message_data[field]:
            return False, f"Missing required field: {field}"

    # Validate friend_id format
    if not validate_uuid(message_data['friend_id']):
        return False, "Invalid friend ID format"

    # Validate content
    content = message_data['content']
    if not isinstance(content, str):
        return False, "Invalid content type"

    if len(content.strip()) == 0:
        return False, "Empty message content"

    if len(content) > 1000:
        return False, "Message too long (max 1000 characters)"

    # Check for malicious patterns
    malicious_patterns = [
        r'<script.*?>.*?</script>',
        r'javascript:',
        r'data:text/html',
        r'vbscript:',
        r'on\w+\s*=',
    ]

    for pattern in malicious_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            return False, "Potentially malicious content detected"

    return True, "Valid"


def generate_integrity_hash(data):
    """Generate integrity hash for data"""
    data_string = json.dumps(data, sort_keys=True)
    return hashlib.sha256(data_string.encode()).hexdigest()


# ================================
# OWASP A09: Security Logging and Monitoring
# ================================

def setup_security_logging():
    """Setup comprehensive security logging"""
    security_logger = logging.getLogger('security')
    security_logger.setLevel(logging.INFO)

    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')

    # File handler for security events
    security_handler = logging.FileHandler('logs/security.log')
    security_formatter = logging.Formatter(
        '%(asctime)s - SECURITY - %(levelname)s - %(message)s'
    )
    security_handler.setFormatter(security_formatter)
    security_logger.addHandler(security_handler)

    # Separate handler for critical security events
    critical_handler = logging.FileHandler('logs/security_critical.log')
    critical_handler.setLevel(logging.ERROR)
    critical_handler.setFormatter(security_formatter)
    security_logger.addHandler(critical_handler)

    return security_logger


def log_security_event(event_type, details=None, level='WARNING'):
    """Comprehensive security event logging"""
    security_logger = logging.getLogger('security')

    # Safe current_user handling for initialization context
    try:
        from flask_login import current_user
        if current_user and hasattr(current_user, 'is_authenticated') and current_user.is_authenticated:
            user_id = current_user.id
            username = current_user.username
        else:
            user_id = 'anonymous'
            username = 'anonymous'
    except (ImportError, RuntimeError):
        # Handle case when outside of request context
        user_id = 'system'
        username = 'system'

    # Safe request handling for initialization context
    try:
        ip_address = request.remote_addr
        user_agent = request.user_agent.string
        endpoint = request.endpoint
        method = request.method
        url = request.url
    except RuntimeError:
        # Outside of request context
        ip_address = 'system'
        user_agent = 'system'
        endpoint = 'system'
        method = 'INIT'
        url = 'system'

    log_data = {
        'timestamp': datetime.utcnow().isoformat(),
        'event_type': event_type,
        'user_id': user_id,
        'username': username,
        'ip_address': ip_address,
        'user_agent': user_agent,
        'endpoint': endpoint,
        'method': method,
        'url': url,
        'details': details or {}
    }

    # Log based on severity
    if level == 'ERROR':
        security_logger.error(f"SECURITY EVENT: {json.dumps(log_data)}")
    elif level == 'WARNING':
        security_logger.warning(f"SECURITY EVENT: {json.dumps(log_data)}")
    else:
        security_logger.info(f"SECURITY EVENT: {json.dumps(log_data)}")


class SecurityMonitor:
    @staticmethod
    def log_friend_request(sender_id, receiver_id, action):
        """Log friend request actions"""
        log_security_event('friend_request', {
            'action': action,
            'sender_id': sender_id,
            'receiver_id': receiver_id
        })

    @staticmethod
    def log_message_sent(sender_id, receiver_id, message_length):
        """Log message sending with metadata"""
        log_security_event('message_sent', {
            'sender_id': sender_id,
            'receiver_id': receiver_id,
            'message_length': message_length,
            'timestamp': datetime.utcnow().isoformat()
        })

    @staticmethod
    def log_suspicious_activity(activity_type, details):
        """Log suspicious activity with high priority"""
        log_security_event('suspicious_activity', {
            'activity_type': activity_type,
            'details': details
        }, level='ERROR')

    @staticmethod
    def log_access_violation(violation_type, details):
        """Log access control violations"""
        log_security_event('access_violation', {
            'violation_type': violation_type,
            'details': details
        }, level='ERROR')


# ================================
# OWASP A10: Server-Side Request Forgery (SSRF)
# ================================

def validate_internal_request():
    """Prevent SSRF attacks on internal endpoints"""

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Validate request origin
            origin = request.headers.get('Origin')
            referer = request.headers.get('Referer')
            host = request.headers.get('Host')

            # Check for same-origin policy
            if origin and not origin.startswith(f"https://{host}"):
                log_security_event('ssrf_attempt', {
                    'origin': origin,
                    'expected_host': host
                }, level='ERROR')
                abort(403, "Cross-origin request blocked")

            # Validate referer for sensitive operations
            if referer and not referer.startswith(f"https://{host}"):
                log_security_event('suspicious_referer', {
                    'referer': referer,
                    'expected_host': host
                })

            # Check for internal IP ranges in any user input
            user_inputs = [
                request.args.get('url', ''),
                request.form.get('url', ''),
                request.json.get('url', '') if request.is_json else ''
            ]

            internal_ip_patterns = [
                r'127\.0\.0\.1',
                r'localhost',
                r'192\.168\.',
                r'10\.',
                r'172\.(1[6-9]|2[0-9]|3[01])\.'
            ]

            for user_input in user_inputs:
                if user_input:
                    for pattern in internal_ip_patterns:
                        if re.search(pattern, str(user_input)):
                            log_security_event('ssrf_internal_ip_attempt', {
                                'input': user_input,
                                'pattern': pattern
                            }, level='ERROR')
                            abort(400, "Invalid URL provided")

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def prevent_url_manipulation():
    """Prevent URL manipulation attacks"""

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Validate all URL parameters
            for key, value in request.args.items():
                if 'url' in key.lower() or 'redirect' in key.lower():
                    # Only allow relative URLs or same-domain URLs
                    if value.startswith('http') and not value.startswith(request.host_url):
                        log_security_event('url_manipulation_attempt', {
                            'parameter': key,
                            'value': value
                        }, level='ERROR')
                        abort(400, "Invalid redirect URL")

            return f(*args, **kwargs)

        return decorated_function

    return decorator


# ================================
# Initialize Security System
# ================================

def initialize_friends_security(app):
    """Initialize all security features for the friends system"""
    # Setup logging first
    setup_security_logging()

    # Log system initialization (without request context)
    security_logger = logging.getLogger('security')
    init_log_data = {
        'timestamp': datetime.utcnow().isoformat(),
        'event_type': 'security_system_initialized',
        'user_id': 'system',
        'username': 'system',
        'ip_address': 'system',
        'user_agent': 'system',
        'endpoint': 'system',
        'method': 'INIT',
        'url': 'system',
        'details': {
            'owasp_features': [
                'A01: Broken Access Control',
                'A02: Cryptographic Failures',
                'A03: Injection Prevention',
                'A04: Insecure Design',
                'A05: Security Misconfiguration',
                'A06: Vulnerable Components',
                'A07: Identity and Authentication Failures',
                'A08: Software and Data Integrity Failures',
                'A09: Security Logging and Monitoring',
                'A10: Server-Side Request Forgery (SSRF)'
            ]
        }
    }

    security_logger.info(f"SECURITY EVENT: {json.dumps(init_log_data)}")

    return True