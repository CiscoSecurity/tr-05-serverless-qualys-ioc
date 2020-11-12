from flask import Blueprint

from api.utils import jsonify_data

api = Blueprint('respond', __name__)


@api.route('/respond/observables', methods=['POST'])
def observables():
    return jsonify_data([])


@api.route('/respond/trigger', methods=['POST'])
def trigger():
    return jsonify_data({'status': 'failure'})
