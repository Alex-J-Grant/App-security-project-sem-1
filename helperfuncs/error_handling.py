from flask import flash, redirect, request, url_for,render_template,jsonify
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

    @app.errorhandler(429)
    def ratelimit_handler(e):
        if request.path == "/chatbot":
            # Return JSON in same shape your frontend expects
            return jsonify({'response': "Please slow down, too many requests."}), 429
        if request.path.startswith("/like") and (request.path.endswith("/like") or request.path.endswith("/unlike")):
            return jsonify({'response': "Please slow down, too many requests."}), 429
        if request.path.startswith("/join_community") and (request.path.endswith("/join") or request.path.endswith("/leave")):
            return jsonify({'response': "Please slow down, too many requests."}), 429
        else:
            flash('Submitting requests too fast please slow down', 'danger')
            return redirect(request.referrer or url_for('home.home'))

    