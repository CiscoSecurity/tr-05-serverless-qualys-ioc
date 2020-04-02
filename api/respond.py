from flask import Blueprint, jsonify

api = Blueprint('respond', __name__)


@api.route('/respond/observables', methods=['POST'])
def observables():
    return jsonify({'data': []})


@api.route('/respond/trigger', methods=['POST'])
def trigger():
    return jsonify({'data': {'status': 'failure'}})
