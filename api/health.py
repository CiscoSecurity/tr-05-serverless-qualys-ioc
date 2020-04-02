from flask import Blueprint, jsonify

api = Blueprint('health', __name__)


@api.route('/health', methods=['POST'])
def health():
    return jsonify({'data': {'status': 'ok'}})
