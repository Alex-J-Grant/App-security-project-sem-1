from flask import flash, redirect, request, url_for,render_template
from werkzeug.exceptions import RequestEntityTooLarge
from flask_wtf.csrf import CSRFError

def register_error_handlers(app):

    @app.errorhandler(RequestEntityTooLarge)
    def handle_large_file(e):
        flash('File too large. Maximum upload size is 16 MB.', 'danger')
        return redirect(request.referrer or url_for('create_post.upload_post'))

    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        return render_template('500.html'), 500

    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        flash('Sorry error occurred when submitting, Please try again.', 'danger')
        return redirect(request.referrer or url_for('home.home'))