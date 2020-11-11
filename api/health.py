from flask import Blueprint

from api.client import events
from api.utils import jsonify_data

api = Blueprint('health', __name__)


@api.route('/health', methods=['POST'])
def health():
    _ = events(True, 1)
    return jsonify_data({'status': 'ok'})
