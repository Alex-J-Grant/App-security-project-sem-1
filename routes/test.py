from flask import Blueprint, jsonify
from sqlalchemy import text
from extensions import db


testbp = Blueprint('test', __name__)

@testbp.route('/testdb')
def test():
    try:
        result = db.session.execute(text('SELECT 1')).scalar()
        if result == 1:
            return jsonify({'status': 'success', 'message': 'database connected'})
        else:
            return jsonify({'status': 'failure', 'message': 'fail'})
    except Exception as e:
        return f'{e}'
