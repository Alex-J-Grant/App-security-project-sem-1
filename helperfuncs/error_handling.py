from flask import flash, redirect, request, url_for
from werkzeug.exceptions import RequestEntityTooLarge

def register_error_handlers(app):

    @app.errorhandler(RequestEntityTooLarge)
    def handle_large_file(e):
        flash('File too large. Maximum upload size is 1 MB.', 'danger')
        return redirect(request.referrer or url_for('create_post.upload_post'))