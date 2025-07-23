from flask import Blueprint, render_template
from helperfuncs.logger import main_logger
account = Blueprint('account', __name__, url_prefix= '/account')

@account.route('/create')
def create():
    main_logger.info('User creation accessed')
    #form goes here 
    if request.method == 'POST' and form.validate():


