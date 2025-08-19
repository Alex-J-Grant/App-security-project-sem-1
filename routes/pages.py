from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Email, Length
from flask_mail import Message
from models.contact import ContactMessage
from extensions import db, mail
from helperfuncs.logger import main_logger
from datetime import datetime, timedelta
import bleach

# Import security functions from your OWASP module
from security.friends_owasp_security import (
    sanitize_message_content, rate_limit, secure_headers,
    log_security_event, validate_search_input
)

from helperfuncs.rba import *

pages = Blueprint('pages', __name__)


class ContactForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(min=2, max=50)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(min=2, max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    category = SelectField('Category', choices=[
        ('', 'Choose...'),
        ('security', '🔒 Security Issue (URGENT)'),
        ('bug', '🐛 Bug Report'),
        ('technical', '⚙️ Technical Support'),
        ('account', '👤 Account Issues'),
        ('feature', '💡 Feature Request'),
        ('general', '💬 General Inquiry')
    ], validators=[DataRequired()])
    subject = StringField('Subject', validators=[DataRequired(), Length(min=5, max=200)])
    message = TextAreaField('Message', validators=[DataRequired(), Length(min=10, max=2000)])


def send_contact_notification(contact_msg):
    """Send email notification for contact form submission"""
    try:
        # Determine recipient based on category
        recipients = {
            'security': ['security@yourapp.com'],
            'bug': ['bugs@yourapp.com'],
            'technical': ['tech@yourapp.com'],
            'account': ['support@yourapp.com'],
            'feature': ['support@yourapp.com'],
            'general': ['support@yourapp.com']
        }

        recipient_list = recipients.get(contact_msg.CATEGORY, ['support@yourapp.com'])

        # Create email subject with priority indicator
        priority = "[URGENT] " if contact_msg.CATEGORY == 'security' else ""
        subject = f"{priority}Contact Form: {contact_msg.SUBJECT}"

        # Create email message
        msg = Message(
            subject=subject,
            sender=current_app.config.get('MAIL_DEFAULT_SENDER', 'noreply@yourapp.com'),
            recipients=recipient_list
        )

        # Email body
        msg.body = f"""
New Contact Form Submission

From: {contact_msg.FIRST_NAME} {contact_msg.LAST_NAME}
Email: {contact_msg.EMAIL}
Category: {contact_msg.CATEGORY}
Subject: {contact_msg.SUBJECT}
Message ID: {contact_msg.ID}

Message:
{contact_msg.MESSAGE}

---
Submitted: {contact_msg.CREATED_AT}
Status: {contact_msg.STATUS}

To respond or manage this message, please log into the admin panel.
        """

        # Send the email
        mail.send(msg)

        main_logger.info(f"Contact notification email sent for message ID {contact_msg.ID} to {recipient_list}")

        # Security logging for email notifications
        log_security_event('contact_notification_sent', {
            'message_id': contact_msg.ID,
            'category': contact_msg.CATEGORY,
            'recipients': recipient_list
        }, level='INFO')

        return True

    except Exception as e:
        main_logger.error(f"Error sending contact notification email: {str(e)}")
        log_security_event('contact_notification_error', {
            'error': str(e),
            'message_id': getattr(contact_msg, 'ID', 'unknown')
        }, level='ERROR')
        return False


@pages.route('/faq')
@rate_limit('faq_access', limit=20, window=60)
@secure_headers
def faq():
    """FAQ page with security-focused content"""
    main_logger.info('FAQ page accessed')

    # Security logging for page access
    log_security_event('faq_page_accessed', {
        'user_agent': request.user_agent.string,
        'referrer': request.referrer
    }, level='INFO')

    return render_template('faq.html')


@pages.route('/contact', methods=['GET', 'POST'])
@rate_limit('contact_form', limit=3, window=300)  # 3 submissions per 5 minutes
@secure_headers
def contact():
    """Contact page with secure form handling and database storage"""
    form = ContactForm()

    if form.validate_on_submit():
        try:
            # Enhanced input validation and sanitization
            first_name = validate_search_input(form.first_name.data.strip())
            last_name = validate_search_input(form.last_name.data.strip())
            email = form.email.data.lower().strip()
            category = form.category.data
            subject = validate_search_input(form.subject.data.strip())
            message_content = sanitize_message_content(form.message.data.strip())

            # Additional validation checks
            if not first_name or not last_name:
                log_security_event('invalid_name_contact_form', {
                    'original_first': form.first_name.data,
                    'original_last': form.last_name.data,
                    'sanitized_first': first_name,
                    'sanitized_last': last_name
                })
                flash('Invalid name provided. Please use only letters and spaces.', 'danger')
                return render_template('contact.html', form=form)

            if not subject:
                log_security_event('invalid_subject_contact_form', {
                    'original_subject': form.subject.data,
                    'sanitized_subject': subject
                })
                flash('Invalid subject provided. Please avoid special characters.', 'danger')
                return render_template('contact.html', form=form)

            if not message_content or len(message_content.strip()) < 10:
                log_security_event('invalid_message_contact_form', {
                    'original_length': len(form.message.data),
                    'sanitized_length': len(message_content) if message_content else 0
                })
                flash('Message content is too short or contains invalid characters.', 'danger')
                return render_template('contact.html', form=form)

            # Email format validation (additional check)
            import re
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, email):
                log_security_event('invalid_email_format_contact', {
                    'email': email
                })
                flash('Invalid email format provided.', 'danger')
                return render_template('contact.html', form=form)

            # Check for spam patterns
            spam_indicators = ['viagra', 'casino', 'lottery', 'click here', 'free money']
            content_lower = (subject + ' ' + message_content).lower()
            if any(indicator in content_lower for indicator in spam_indicators):
                log_security_event('spam_detected_contact_form', {
                    'email': email,
                    'subject': subject
                }, level='ERROR')
                flash('Your message has been flagged as potential spam. Please contact us directly.', 'danger')
                return render_template('contact.html', form=form)

            # Create contact message record with sanitized data
            contact_msg = ContactMessage(
                FIRST_NAME=first_name,
                LAST_NAME=last_name,
                EMAIL=email,
                CATEGORY=category,
                SUBJECT=subject,
                MESSAGE=message_content
            )

            # Save to database
            db.session.add(contact_msg)
            db.session.commit()

            # Send email notification
            email_sent = send_contact_notification(contact_msg)

            # Enhanced logging with security details
            log_data = {
                'message_id': contact_msg.ID,
                'category': contact_msg.CATEGORY,
                'email': contact_msg.EMAIL,
                'email_sent': email_sent,
                'user_agent': request.user_agent.string,
                'ip_address': request.remote_addr,
                'message_length': len(message_content)
            }

            if contact_msg.CATEGORY == 'security':
                main_logger.error(f"SECURITY ISSUE REPORTED: Contact message ID {contact_msg.ID} - {log_data}")
                log_security_event('security_issue_reported', log_data, level='ERROR')
            else:
                main_logger.info(f"Contact message saved: {log_data}")
                log_security_event('contact_message_submitted', log_data, level='INFO')

            # Success message with different text for security issues
            if contact_msg.CATEGORY == 'security':
                flash(
                    'Security issue reported successfully! Our security team has been notified and will respond immediately.',
                    'success')
            else:
                flash('Message sent successfully! We\'ll get back to you within our stated response time.', 'success')

            return redirect(url_for('pages.contact'))

        except Exception as e:
            db.session.rollback()
            main_logger.error(f"Error saving contact message: {str(e)}")
            log_security_event('contact_form_error', {
                'error': str(e),
                'form_data': {
                    'category': form.category.data,
                    'email': form.email.data
                }
            }, level='ERROR')
            flash('Error sending message. Please try again or contact us directly at support@yourapp.com', 'danger')

    # Log form access attempts
    if request.method == 'GET':
        log_security_event('contact_form_accessed', {
            'user_agent': request.user_agent.string,
            'referrer': request.referrer
        }, level='INFO')

    return render_template('contact.html', form=form)


@pages.route('/admin/contact-messages')
@admin_required
@rate_limit('admin_contact_access', limit=20, window=60)
@secure_headers
def admin_contact_messages():
    """Admin view for contact messages with enhanced security"""
    try:
        main_logger.info("Accessing contact messages admin panel")

        # Security logging for admin access
        log_security_event('admin_contact_messages_accessed', {
            'admin_user': getattr(current_user, 'username', 'unknown') if hasattr(current_user,
                                                                                  'username') else 'unknown',
            'user_agent': request.user_agent.string
        }, level='INFO')

        # Get filter parameters with validation
        status_filter = request.args.get('status', 'all')
        category_filter = request.args.get('category', 'all')

        # Validate filter parameters to prevent injection
        valid_statuses = ['all', 'new', 'in_progress', 'resolved']
        valid_categories = ['all', 'security', 'bug', 'technical', 'account', 'feature', 'general']

        if status_filter not in valid_statuses:
            log_security_event('invalid_status_filter_admin', {
                'invalid_status': status_filter
            })
            status_filter = 'all'

        if category_filter not in valid_categories:
            log_security_event('invalid_category_filter_admin', {
                'invalid_category': category_filter
            })
            category_filter = 'all'

        # Check if ContactMessage table exists
        try:
            total_count = ContactMessage.query.count()
            print(f"DEBUG: Total contact messages: {total_count}")
        except Exception as e:
            log_security_event('contact_messages_table_error', {
                'error': str(e)
            }, level='ERROR')
            return f"Database Error: {str(e)}. Make sure the CONTACT_MESSAGES table exists and ContactMessage model is imported correctly."

        # Build query with enhanced security
        query = ContactMessage.query

        if status_filter != 'all':
            query = query.filter(ContactMessage.STATUS == status_filter)

        if category_filter != 'all':
            query = query.filter(ContactMessage.CATEGORY == category_filter)

        # Get messages ordered by creation date (newest first) with limit for security
        messages = query.order_by(ContactMessage.CREATED_AT.desc()).limit(500).all()

        # Get summary statistics with error handling
        try:
            stats = {
                'total': ContactMessage.query.count(),
                'new': ContactMessage.query.filter_by(STATUS='new').count(),
                'in_progress': ContactMessage.query.filter_by(STATUS='in_progress').count(),
                'resolved': ContactMessage.query.filter_by(STATUS='resolved').count(),
                'security': ContactMessage.query.filter_by(CATEGORY='security').count()
            }
        except Exception as e:
            log_security_event('contact_stats_error', {
                'error': str(e)
            }, level='ERROR')
            stats = {'total': 0, 'new': 0, 'in_progress': 0, 'resolved': 0, 'security': 0}

        print(f"DEBUG: Messages found: {len(messages)}")
        print(f"DEBUG: Stats: {stats}")

        # Log admin panel statistics access
        log_security_event('admin_contact_stats_viewed', {
            'stats': stats,
            'filter_status': status_filter,
            'filter_category': category_filter,
            'messages_returned': len(messages)
        }, level='INFO')

        # Check if template exists
        try:
            return render_template('contact_admin.html',
                                   messages=messages,
                                   stats=stats,
                                   current_status=status_filter,
                                   current_category=category_filter)
        except Exception as template_error:
            log_security_event('admin_template_error', {
                'error': str(template_error)
            }, level='ERROR')
            return f"Template Error: {str(template_error)}. Make sure contact_admin.html exists in templates folder."

    except Exception as e:
        error_msg = f"Error in admin_contact_messages: {str(e)}"
        print(f"DEBUG: {error_msg}")
        main_logger.error(error_msg)
        log_security_event('admin_contact_critical_error', {
            'error': str(e)
        }, level='ERROR')
        return error_msg


@pages.route('/admin/test')
@rate_limit('admin_test', limit=10, window=60)
@secure_headers
def admin_test():
    """Simple test route with enhanced security logging"""
    log_security_event('admin_test_accessed', {
        'user_agent': request.user_agent.string,
        'referrer': request.referrer
    }, level='INFO')

    return "Admin test route working - no authentication required for testing"


# Additional security route for monitoring
@pages.route('/security/health')
@rate_limit('security_health', limit=5, window=60)
@secure_headers
def security_health():
    """Security health check endpoint"""
    try:
        # Basic security health checks
        health_status = {
            'timestamp': datetime.utcnow().isoformat(),
            'database_connection': 'ok',
            'security_logging': 'active',
            'rate_limiting': 'active'
        }

        # Test database connection
        try:
            db.session.execute(text("SELECT 1")).fetchone()
        except Exception as e:
            health_status['database_connection'] = 'error'
            log_security_event('security_health_db_error', {
                'error': str(e)
            }, level='ERROR')

        log_security_event('security_health_check', health_status, level='INFO')

        return jsonify(health_status)

    except Exception as e:
        log_security_event('security_health_check_error', {
            'error': str(e)
        }, level='ERROR')
        return jsonify({'status': 'error', 'message': 'Health check failed'}), 500