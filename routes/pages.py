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
        return True

    except Exception as e:
        main_logger.error(f"Error sending contact notification email: {str(e)}")
        return False


@pages.route('/faq')
def faq():
    """FAQ page with security-focused content"""
    main_logger.info('FAQ page accessed')
    return render_template('faq.html')


@pages.route('/contact', methods=['GET', 'POST'])
def contact():
    """Contact page with secure form handling and database storage"""
    form = ContactForm()

    if form.validate_on_submit():
        try:
            # Create contact message record with sanitized data
            contact_msg = ContactMessage(
                FIRST_NAME=bleach.clean(form.first_name.data.strip()),
                LAST_NAME=bleach.clean(form.last_name.data.strip()),
                EMAIL=form.email.data.lower().strip(),
                CATEGORY=form.category.data,
                SUBJECT=bleach.clean(form.subject.data.strip()),
                MESSAGE=bleach.clean(form.message.data.strip())
            )

            # Save to database
            db.session.add(contact_msg)
            db.session.commit()

            # Send email notification
            email_sent = send_contact_notification(contact_msg)

            # Log the contact form submission with details
            log_data = {
                'message_id': contact_msg.ID,
                'category': contact_msg.CATEGORY,
                'email': contact_msg.EMAIL,
                'email_sent': email_sent
            }

            if contact_msg.CATEGORY == 'security':
                main_logger.error(f"SECURITY ISSUE REPORTED: Contact message ID {contact_msg.ID} - {log_data}")
            else:
                main_logger.info(f"Contact message saved: {log_data}")

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
            flash('Error sending message. Please try again or contact us directly at support@yourapp.com', 'danger')

    return render_template('contact.html', form=form)


@pages.route('/admin/contact-messages')
@admin_required
def admin_contact_messages():
    """Admin view for contact messages - no admin requirement for testing"""
    try:
        main_logger.info("Accessing contact messages admin panel")

        # Get filter parameters
        status_filter = request.args.get('status', 'all')
        category_filter = request.args.get('category', 'all')

        # Check if ContactMessage table exists
        try:
            total_count = ContactMessage.query.count()
            print(f"DEBUG: Total contact messages: {total_count}")
        except Exception as e:
            return f"Database Error: {str(e)}. Make sure the CONTACT_MESSAGES table exists and ContactMessage model is imported correctly."

        # Build query
        query = ContactMessage.query

        if status_filter != 'all':
            query = query.filter(ContactMessage.STATUS == status_filter)

        if category_filter != 'all':
            query = query.filter(ContactMessage.CATEGORY == category_filter)

        # Get messages ordered by creation date (newest first)
        messages = query.order_by(ContactMessage.CREATED_AT.desc()).all()

        # Get summary statistics
        stats = {
            'total': ContactMessage.query.count(),
            'new': ContactMessage.query.filter_by(STATUS='new').count(),
            'in_progress': ContactMessage.query.filter_by(STATUS='in_progress').count(),
            'resolved': ContactMessage.query.filter_by(STATUS='resolved').count(),
            'security': ContactMessage.query.filter_by(CATEGORY='security').count()
        }

        print(f"DEBUG: Messages found: {len(messages)}")
        print(f"DEBUG: Stats: {stats}")

        # Check if template exists
        try:
            return render_template('contact_admin.html',
                                   messages=messages,
                                   stats=stats,
                                   current_status=status_filter,
                                   current_category=category_filter)
        except Exception as template_error:
            return f"Template Error: {str(template_error)}. Make sure contact_admin.html exists in templates folder."

    except Exception as e:
        error_msg = f"Error in admin_contact_messages: {str(e)}"
        print(f"DEBUG: {error_msg}")
        main_logger.error(error_msg)
        return error_msg



@pages.route('/admin/test')
def admin_test():
    """Simple test route"""
    return "Admin test route working - no authentication required for testing"