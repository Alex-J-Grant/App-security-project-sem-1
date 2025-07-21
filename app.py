from flask import Flask
# from routes import
def create_app():
    app =Flask(__name__)

    app.config.from_mapping(
        # NEEDS TO BE CHANGED VERY IMPORTANT 
        SECRET_KEY = "SECRET"
    #     U GUYS NEED TO SET YOUR OWN DATABASE LINK SINCE WE ARE ALL USING A LOCAL SQL SERVER
    #     DATABASE = 
    )
