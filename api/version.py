from flask import Blueprint, current_app, jsonify


api = Blueprint('version', __name__)


@api.route('/version', methods=['POST'])
def version():
    return jsonify({'version': current_app.config['VERSION']})
