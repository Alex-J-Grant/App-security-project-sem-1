# forms/friendforms.py - Enhanced with OWASP security
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField, HiddenField
from wtforms.validators import DataRequired, Length, ValidationError
import re

# Import security functions
from security.friends_owasp_security import (
    sanitize_message_content, validate_uuid, validate_search_input, log_security_event
)


class SecurityValidationMixin:
    """Mixin class to add security validation to forms"""

    def validate_username_security(self, field):
        """Custom validator for username security"""
        if not field.data:
            return

        # Sanitize and validate username
        clean_username = validate_search_input(field.data)
        if not clean_username or clean_username != field.data:
            log_security_event('invalid_username_in_form', {
                'original': field.data,
                'sanitized': clean_username
            }, level='ERROR')
            raise ValidationError('Username contains invalid characters.')

        # Additional username pattern validation
        username_pattern = r'^[a-zA-Z0-9_-]+$'
        if not re.match(username_pattern, field.data):
            log_security_event('username_pattern_violation', {
                'username': field.data
            })
            raise ValidationError('Username can only contain letters, numbers, underscores, and hyphens.')

        # Check for suspicious username patterns
        suspicious_patterns = [
            r'admin',
            r'root',
            r'system',
            r'test',
            r'(script|hack|bot)',
            r'(.)\1{5,}',  # Repeated characters
        ]

        for pattern in suspicious_patterns:
            if re.search(pattern, field.data.lower()):
                log_security_event('suspicious_username_pattern', {
                    'username': field.data,
                    'pattern': pattern
                })
                # Don't block, just log for monitoring
                break

    def validate_content_security(self, field):
        """Custom validator for message content security"""
        if not field.data:
            return

        # Check for potential XSS patterns
        xss_patterns = [
            r'<script.*?>.*?</script>',
            r'javascript:',
            r'vbscript:',
            r'on\w+\s*=',
            r'data:text/html',
        ]

        for pattern in xss_patterns:
            if re.search(pattern, field.data, re.IGNORECASE):
                log_security_event('xss_attempt_in_message', {
                    'pattern': pattern,
                    'content_preview': field.data[:100]
                }, level='ERROR')
                raise ValidationError('Message contains potentially dangerous elements.')

        # Check for excessive length
        if len(field.data) > 2000:
            log_security_event('message_length_violation', {
                'length': len(field.data)
            })
            raise ValidationError('Message exceeds maximum allowed length.')

    def validate_uuid_field(self, field):
        """Custom validator for UUID fields"""
        if field.data and not validate_uuid(field.data):
            log_security_event('invalid_uuid_in_friend_form', {
                'field': field.name,
                'value': field.data
            }, level='ERROR')
            raise ValidationError('Invalid ID format provided.')


class SendFriendRequestForm(FlaskForm, SecurityValidationMixin):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=5, max=20, message="Username must be between 5 and 20 characters")
    ])
    submit = SubmitField('Send Friend Request')

    def validate_username(self, field):
        """Enhanced username validation"""
        self.validate_username_security(field)

        # Additional checks for friend requests
        if field.data:
            # Check for self-referencing attempts (basic check)
            try:
                from flask_login import current_user
                if current_user.is_authenticated and field.data.lower() == current_user.username.lower():
                    log_security_event('self_friend_request_attempt', {
                        'username': field.data
                    })
                    raise ValidationError('You cannot send a friend request to yourself.')
            except:
                pass  # Handle case where current_user is not available

            # Check for common spam usernames
            spam_patterns = [
                r'(spam|bot|fake)',
                r'[0-9]{8,}',  # Too many numbers
                r'(test|admin|system)\d*$'
            ]

            for pattern in spam_patterns:
                if re.search(pattern, field.data.lower()):
                    log_security_event('potential_spam_username', {
                        'username': field.data,
                        'pattern': pattern
                    })
                    break


class RespondFriendRequestForm(FlaskForm, SecurityValidationMixin):
    request_id = HiddenField('Request ID', validators=[DataRequired()])
    action = HiddenField('Action', validators=[DataRequired()])  # 'accept' or 'reject'
    submit = SubmitField('Respond')

    def validate_request_id(self, field):
        """Validate request_id format"""
        if field.data and not field.data.isdigit():
            log_security_event('invalid_request_id_format', {
                'request_id': field.data
            }, level='ERROR')
            raise ValidationError('Invalid request ID format.')

        # Additional validation for request ID range
        if field.data and int(field.data) <= 0:
            log_security_event('invalid_request_id_value', {
                'request_id': field.data
            })
            raise ValidationError('Invalid request ID value.')

    def validate_action(self, field):
        """Validate action field"""
        valid_actions = ['accept', 'reject']
        if field.data not in valid_actions:
            log_security_event('invalid_friend_request_action', {
                'action': field.data
            }, level='ERROR')
            raise ValidationError('Invalid action specified.')


class SendMessageForm(FlaskForm, SecurityValidationMixin):
    friend_id = HiddenField('Friend ID', validators=[DataRequired()])
    content = TextAreaField('Message', validators=[
        DataRequired(),
        Length(min=1, max=1000, message="Message must be between 1 and 1000 characters")
    ], render_kw={"placeholder": "Type your message here...", "rows": 3})
    submit = SubmitField('Send Message')

    def validate_friend_id(self, field):
        """Validate friend_id format"""
        self.validate_uuid_field(field)

    def validate_content(self, field):
        """Enhanced content validation"""
        self.validate_content_security(field)

        if field.data:
            # Sanitize content and check if it's still meaningful
            clean_content = sanitize_message_content(field.data)
            if len(clean_content.strip()) < 1:
                log_security_event('empty_message_after_sanitization', {
                    'original_content': field.data,
                    'sanitized_content': clean_content
                })
                raise ValidationError('Message content is empty or contains only invalid characters.')

            # Check for spam patterns
            spam_patterns = [
                r'(buy now|click here|free money|lottery|casino)',
                r'(www\.|http://|https://){2,}',  # Multiple URLs
                r'(.)\1{10,}',  # Repeated characters (like aaaaaaaaaa)
                r'(urgent|immediate|act now){2,}',  # Spam urgency words
            ]

            for pattern in spam_patterns:
                if re.search(pattern, field.data.lower()):
                    log_security_event('spam_message_detected', {
                        'pattern': pattern,
                        'content_preview': field.data[:50]
                    })
                    raise ValidationError('Message appears to contain spam content.')

            # Check for potential phishing attempts
            phishing_patterns = [
                r'(password|login|account).*(expired|suspended|verify)',
                r'(click|visit).*(link|url).*(urgent|immediate)',
                r'(confirm|update).*(identity|information|details)',
            ]

            for pattern in phishing_patterns:
                if re.search(pattern, field.data.lower()):
                    log_security_event('potential_phishing_message', {
                        'pattern': pattern,
                        'content_preview': field.data[:50]
                    }, level='ERROR')
                    raise ValidationError('Message contains suspicious content that may be harmful.')


class SearchUserForm(FlaskForm, SecurityValidationMixin):
    search_term = StringField('Search Users', validators=[
        DataRequired(),
        Length(min=1, max=50, message="Search term must be between 1 and 50 characters")
    ], render_kw={"placeholder": "Search by username or name..."})
    submit = SubmitField('Search')

    def validate_search_term(self, field):
        """Enhanced search term validation"""
        if field.data:
            # Sanitize search input
            clean_search = validate_search_input(field.data)
            if not clean_search:
                log_security_event('invalid_search_term', {
                    'original': field.data,
                    'sanitized': clean_search
                })
                raise ValidationError('Search term contains invalid characters.')

            # Update field data with sanitized version
            field.data = clean_search

            # Check for SQL injection patterns in search
            sql_patterns = [
                r'(union|select|insert|update|delete|drop)\s+',
                r'(or|and)\s+\d+\s*=\s*\d+',
                r'[\'"]\s*(or|and)\s+[\'"]\w+[\'"]\s*=\s*[\'"]\w+[\'"]\s*',
            ]

            for pattern in sql_patterns:
                if re.search(pattern, field.data, re.IGNORECASE):
                    log_security_event('sql_injection_in_search', {
                        'pattern': pattern,
                        'search_term': field.data
                    }, level='ERROR')
                    raise ValidationError('Search term contains invalid patterns.')

            # Check for excessive special characters
            special_char_count = len(re.findall(r'[^a-zA-Z0-9\s]', field.data))
            if special_char_count > len(field.data) * 0.3:  # More than 30% special chars
                log_security_event('excessive_special_chars_search', {
                    'search_term': field.data,
                    'special_char_ratio': special_char_count / len(field.data)
                })
                raise ValidationError('Search term contains too many special characters.')


# Additional security form for advanced friend management
class BlockUserForm(FlaskForm, SecurityValidationMixin):
    """Form for blocking users"""
    user_id = HiddenField('User ID', validators=[DataRequired()])
    reason = TextAreaField('Reason', validators=[Length(max=200)])
    submit = SubmitField('Block User')

    def validate_user_id(self, field):
        """Validate user_id format"""
        self.validate_uuid_field(field)

    def validate_reason(self, field):
        """Validate blocking reason"""
        if field.data:
            self.validate_content_security(field)


class ReportUserForm(FlaskForm, SecurityValidationMixin):
    """Form for reporting users"""
    user_id = HiddenField('User ID', validators=[DataRequired()])
    category = StringField('Category', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[
        DataRequired(),
        Length(min=10, max=500, message="Description must be between 10 and 500 characters")
    ])
    submit = SubmitField('Report User')

    def validate_user_id(self, field):
        """Validate user_id format"""
        self.validate_uuid_field(field)

    def validate_category(self, field):
        """Validate report category"""
        valid_categories = ['spam', 'harassment', 'inappropriate_content', 'fake_account', 'other']
        if field.data not in valid_categories:
            log_security_event('invalid_report_category', {
                'category': field.data
            })
            raise ValidationError('Invalid report category.')

    def validate_description(self, field):
        """Validate report description"""
        self.validate_content_security(field)

        # Check for false reporting patterns
        false_report_patterns = [
            r'(fake|false|lie).*(report|claim)',
            r'(revenge|angry|mad).*(report)',
            r'(hate|dislike).*(person|user)',
        ]

        for pattern in false_report_patterns:
            if re.search(pattern, field.data.lower()):
                log_security_event('potential_false_report', {
                    'pattern': pattern,
                    'description_preview': field.data[:50]
                })
                # Log but don't block - let moderators decide
                break


# Rate limiting mixin for friend forms
class FriendFormRateLimitMixin:
    """Mixin to add rate limiting to friend forms"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._rate_limit_key = None

    def set_rate_limit_key(self, user_id, form_type):
        """Set rate limiting key for this form submission"""
        self._rate_limit_key = f"{user_id}:{form_type}"

    def check_rate_limit(self):
        """Check if rate limit is exceeded for friend actions"""
        if not self._rate_limit_key:
            return True

        from security.friends_owasp_security import rate_limiter

        action_type = self._rate_limit_key.split(':')[1]
        user_id = self._rate_limit_key.split(':')[0]

        # Different limits for different friend actions
        limits = {
            'friend_request': (5, 300),  # 5 friend requests per 5 minutes
            'message': (20, 60),  # 20 messages per minute
            'search': (10, 60),  # 10 searches per minute
            'block': (3, 600),  # 3 blocks per 10 minutes
            'report': (2, 1800),  # 2 reports per 30 minutes
        }

        limit, window = limits.get(action_type, (5, 300))

        if rate_limiter.is_rate_limited(user_id, action_type, limit, window):
            log_security_event('friend_form_rate_limit_exceeded', {
                'user_id': user_id,
                'form_type': action_type,
                'limit': limit,
                'window': window
            })
            return False

        return True


# Enhanced versions of existing forms with rate limiting
class EnhancedSendFriendRequestForm(SendFriendRequestForm, FriendFormRateLimitMixin):
    """Friend request form with rate limiting"""

    def validate(self, extra_validators=None):
        """Override validate to add rate limiting check"""
        initial_validation = super().validate(extra_validators)

        if not initial_validation:
            return False

        # Check rate limit if user is set
        if hasattr(self, '_rate_limit_key') and self._rate_limit_key:
            if not self.check_rate_limit():
                self.username.errors.append('Too many friend requests sent. Please wait before trying again.')
                return False

        return True


class EnhancedSendMessageForm(SendMessageForm, FriendFormRateLimitMixin):
    """Message form with rate limiting"""

    def validate(self, extra_validators=None):
        """Override validate to add rate limiting and additional security checks"""
        initial_validation = super().validate(extra_validators)

        if not initial_validation:
            return False

        # Check rate limit
        if hasattr(self, '_rate_limit_key') and self._rate_limit_key:
            if not self.check_rate_limit():
                self.content.errors.append('Too many messages sent. Please wait before sending another message.')
                return False

        # Additional cross-field validation
        if self.content.data and self.friend_id.data:
            # Check if message contains the friend ID (potential attack)
            if self.friend_id.data in self.content.data:
                log_security_event('suspicious_message_content', {
                    'friend_id': self.friend_id.data,
                    'content_preview': self.content.data[:50]
                })
                self.content.errors.append('Message content appears suspicious.')
                return False

        return True


class EnhancedSearchUserForm(SearchUserForm, FriendFormRateLimitMixin):
    """Search form with rate limiting"""

    def validate(self, extra_validators=None):
        """Override validate to add rate limiting check"""
        initial_validation = super().validate(extra_validators)

        if not initial_validation:
            return False

        # Check rate limit
        if hasattr(self, '_rate_limit_key') and self._rate_limit_key:
            if not self.check_rate_limit():
                self.search_term.errors.append('Too many searches performed. Please wait before searching again.')
                return False

        return True


# Security monitoring form
class SecurityReportForm(FlaskForm, SecurityValidationMixin):
    """Form for reporting security issues"""
    issue_type = StringField('Issue Type', validators=[DataRequired()])
    severity = StringField('Severity', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[
        DataRequired(),
        Length(min=20, max=1000, message="Description must be between 20 and 1000 characters")
    ])
    steps_to_reproduce = TextAreaField('Steps to Reproduce', validators=[Length(max=2000)])
    submit = SubmitField('Report Security Issue')

    def validate_issue_type(self, field):
        """Validate security issue type"""
        valid_types = [
            'xss', 'sql_injection', 'csrf', 'access_control',
            'authentication', 'data_exposure', 'other'
        ]
        if field.data not in valid_types:
            raise ValidationError('Invalid security issue type.')

    def validate_severity(self, field):
        """Validate severity level"""
        valid_severities = ['low', 'medium', 'high', 'critical']
        if field.data not in valid_severities:
            raise ValidationError('Invalid severity level.')

    def validate_description(self, field):
        """Validate security report description"""
        self.validate_content_security(field)

        # Log all security reports for immediate attention
        if field.data:
            log_security_event('security_issue_reported', {
                'issue_type': getattr(self.issue_type, 'data', 'unknown'),
                'severity': getattr(self.severity, 'data', 'unknown'),
                'description_preview': field.data[:100]
            }, level='ERROR')

    def validate_steps_to_reproduce(self, field):
        """Validate steps to reproduce"""
        if field.data:
            self.validate_content_security(field)


# Form for admin friend management
class AdminFriendActionForm(FlaskForm, SecurityValidationMixin):
    """Form for admin friend management actions"""
    user_id = HiddenField('User ID', validators=[DataRequired()])
    action = StringField('Action', validators=[DataRequired()])
    reason = TextAreaField('Admin Reason', validators=[Length(max=500)])
    submit = SubmitField('Execute Action')

    def validate_user_id(self, field):
        """Validate user_id format"""
        self.validate_uuid_field(field)

    def validate_action(self, field):
        """Validate admin action"""
        valid_actions = [
            'suspend_messaging', 'ban_friend_requests', 'review_account',
            'reset_friendships', 'flag_for_review'
        ]
        if field.data not in valid_actions:
            log_security_event('invalid_admin_friend_action', {
                'action': field.data
            }, level='ERROR')
            raise ValidationError('Invalid admin action specified.')

    def validate_reason(self, field):
        """Validate admin reason"""
        if field.data:
            self.validate_content_security(field)

            # Log all admin actions
            log_security_event('admin_friend_action_attempted', {
                'action': getattr(self.action, 'data', 'unknown'),
                'reason_preview': field.data[:100]
            }, level='INFO')

# hi