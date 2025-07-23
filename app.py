from flask import Flask
from extensions import db
# from routes import
from routes.test import testbp

def create_app():
    app =Flask(__name__)

    app.config.from_mapping(
        # need to change key very important 
        SECRET_KEY="SECRET",
        SQLALCHEMY_DATABASE_URI="mysql+pymysql://developer:temppassword@localhost:3306/app_sec_db",
        SQLALCHEMY_TRACK_MODIFICATIONS=False

    )
    db.init_app(app)
    app.register_blueprint(testbp)
    return app


if __name__ == '__main__':
    app = create_app()
    app.run()
