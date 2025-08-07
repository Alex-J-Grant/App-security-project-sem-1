
    app.register_blueprint(users)  # ADD THIS LINE
    app.register_blueprint(pages)
    app.register_blueprint(comments)
    app.register_blueprint(like_bp)
    register_error_handlers(app)
