# forms/commentforms.py - Enhanced with OWASP security
from flask_wtf import FlaskForm
from wtforms import TextAreaField, HiddenField, SubmitField
from wtforms.validators import DataRequired, Length, ValidationError
import re
import bleach

# Import security functions
from security.friends_owasp_security import sanitize_message_content, validate_uuid, log_security_event


class SecurityValidationMixin:
    """Mixin class to add security validation to forms"""

    def validate_content_security(self, field):
        """Custom validator for content security"""
        if not field.data:
            return

        # Check for potential XSS patterns
        xss_patterns = [
            r'<script.*?>.*?</script>',
            r'javascript:',
            r'vbscript:',
            r'on\w+\s*=',
            r'data:text/html',
            r'<iframe.*?>',
            r'<object.*?>',
            r'<embed.*?>'
        ]

        for pattern in xss_patterns:
            if re.search(pattern, field.data, re.IGNORECASE):
                log_security_event('xss_attempt_in_form', {
                    'field': field.name,
                    'pattern': pattern,
                    'content_preview': field.data[:100]
                }, level='ERROR')
                raise ValidationError('Content contains potentially dangerous elements.')

        # Check for SQL injection patterns
        sql_patterns = [
            r'(union|select|insert|update|delete|drop|create|alter)\s+',
            r'(or|and)\s+\d+\s*=\s*\d+',
            r'[\'"]\s*(or|and)\s+[\'"]\w+[\'"]\s*=\s*[\'"]\w+[\'"]\s*',
            r';\s*(drop|delete|update|insert)',
        ]

        for pattern in sql_patterns:
            if re.search(pattern, field.data, re.IGNORECASE):
                log_security_event('sql_injection_attempt_in_form', {
                    'field': field.name,
                    'pattern': pattern,
                    'content_preview': field.data[:100]
                }, level='ERROR')
                raise ValidationError('Content contains potentially malicious SQL patterns.')

        # Check for excessive length (additional protection)
        if len(field.data) > 1000:
            log_security_event('content_length_violation', {
                'field': field.name,
                'length': len(field.data)
            })
            raise ValidationError('Content exceeds maximum allowed length.')

    def validate_uuid_field(self, field):
        """Custom validator for UUID fields"""
        if field.data and not validate_uuid(field.data):
            log_security_event('invalid_uuid_in_form', {
                'field': field.name,
                'value': field.data
            }, level='ERROR')
            raise ValidationError('Invalid ID format provided.')


class CommentForm(FlaskForm, SecurityValidationMixin):
    post_id = HiddenField('Post ID', validators=[DataRequired()])
    content = TextAreaField('Add a comment...',
                            validators=[
                                DataRequired(),
                                Length(min=1, max=500, message="Comment must be between 1 and 500 characters")
                            ],
                            render_kw={"placeholder": "Share your thoughts...", "rows": 3})
    submit = SubmitField('Post Comment')

    def validate_post_id(self, field):
        """Validate post_id format and security"""
        self.validate_uuid_field(field)

    def validate_content(self, field):
        """Validate content security"""
        self.validate_content_security(field)

        # Additional content validation
        if field.data:
            # Remove any HTML tags and check if content is still meaningful
            clean_content = bleach.clean(field.data, tags=[], strip=True)
            if len(clean_content.strip()) < 1:
                log_security_event('empty_content_after_sanitization', {
                    'original_content': field.data,
                    'sanitized_content': clean_content
                })
                raise ValidationError('Comment content is empty or contains only invalid characters.')

            # Check for spam patterns
            spam_patterns = [
                r'(buy now|click here|free money|viagra|casino)',
                r'(www\.|http://|https://){2,}',  # Multiple URLs
                r'(.)\1{10,}',  # Repeated characters
            ]

            for pattern in spam_patterns:
                if re.search(pattern, field.data.lower()):
                    log_security_event('spam_pattern_detected', {
                        'pattern': pattern,
                        'content_preview': field.data[:50]
                    })
                    raise ValidationError('Comment appears to contain spam content.')


class ReplyForm(FlaskForm, SecurityValidationMixin):
    comment_id = HiddenField('Comment ID', validators=[DataRequired()])
    content = TextAreaField('Reply...',
                            validators=[
                                DataRequired(),
                                Length(min=1, max=500, message="Reply must be between 1 and 500 characters")
                            ],
                            render_kw={"placeholder": "Write a reply...", "rows": 2})
    submit = SubmitField('Reply')

    def validate_comment_id(self, field):
        """Validate comment_id format and security"""
        self.validate_uuid_field(field)

    def validate_content(self, field):
        """Validate content security"""
        self.validate_content_security(field)

        # Additional content validation for replies
        if field.data:
            # Remove any HTML tags and check if content is still meaningful
            clean_content = bleach.clean(field.data, tags=[], strip=True)
            if len(clean_content.strip()) < 1:
                log_security_event('empty_reply_after_sanitization', {
                    'original_content': field.data,
                    'sanitized_content': clean_content
                })
                raise ValidationError('Reply content is empty or contains only invalid characters.')

            # Check for inappropriate reply patterns
            inappropriate_patterns = [
                r'(kill yourself|kys)',
                r'(f[u\*]ck|sh[i\*]t|damn){3,}',  # Excessive profanity
                r'(hate|stupid|idiot){2,}',  # Repeated negative words
            ]

            for pattern in inappropriate_patterns:
                if re.search(pattern, field.data.lower()):
                    log_security_event('inappropriate_content_detected', {
                        'pattern': pattern,
                        'content_preview': field.data[:50]
                    })
                    raise ValidationError('Reply contains inappropriate content.')

    def validate(self, extra_validators=None):
        """Override validate to add additional security checks"""
        initial_validation = super().validate(extra_validators)

        if not initial_validation:
            return False

        # Cross-field validation
        if self.content.data and self.comment_id.data:
            # Check if reply is too similar to comment ID (potential attack)
            if self.comment_id.data.lower() in self.content.data.lower():
                log_security_event('suspicious_reply_content', {
                    'comment_id': self.comment_id.data,
                    'content_preview': self.content.data[:50]
                })
                self.content.errors.append('Reply content appears suspicious.')
                return False

        return True


# Additional security form for admin actions
class AdminCommentActionForm(FlaskForm, SecurityValidationMixin):
    """Form for admin actions on comments"""
    comment_id = HiddenField('Comment ID', validators=[DataRequired()])
    action = HiddenField('Action', validators=[DataRequired()])
    reason = TextAreaField('Reason', validators=[Length(max=200)])
    submit = SubmitField('Confirm Action')

    def validate_comment_id(self, field):
        """Validate comment_id format"""
        self.validate_uuid_field(field)

    def validate_action(self, field):
        """Validate admin action"""
        valid_actions = ['delete', 'hide', 'flag', 'approve']
        if field.data not in valid_actions:
            log_security_event('invalid_admin_action', {
                'action': field.data
            }, level='ERROR')
            raise ValidationError('Invalid admin action specified.')

    def validate_reason(self, field):
        """Validate admin reason"""
        if field.data:
            self.validate_content_security(field)


# Rate limiting form validation
class RateLimitedFormMixin:
    """Mixin to add rate limiting to forms"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._submission_key = None

    def set_rate_limit_key(self, user_id, form_type):
        """Set rate limiting key for this form submission"""
        self._submission_key = f"{user_id}:{form_type}"

    def check_rate_limit(self):
        """Check if rate limit is exceeded"""
        if not self._submission_key:
            return True

        # This would integrate with your existing rate limiter
        from security.friends_owasp_security import rate_limiter

        action_type = self._submission_key.split(':')[1]
        user_id = self._submission_key.split(':')[0]

        # Different limits for different form types
        limits = {
            'comment': (10, 300),  # 10 comments per 5 minutes
            'reply': (15, 300),  # 15 replies per 5 minutes
            'admin': (20, 60)  # 20 admin actions per minute
        }

        limit, window = limits.get(action_type, (5, 300))

        if rate_limiter.is_rate_limited(user_id, action_type, limit, window):
            log_security_event('form_rate_limit_exceeded', {
                'user_id': user_id,
                'form_type': action_type,
                'limit': limit,
                'window': window
            })
            return False

        return True


# Enhanced versions of existing forms with rate limiting
class EnhancedCommentForm(CommentForm, RateLimitedFormMixin):
    """Comment form with rate limiting"""
    pass


class EnhancedReplyForm(ReplyForm, RateLimitedFormMixin):
    """Reply form with rate limiting"""
    pass