from flask import Blueprint

from api.client import events
from api.utils import jsonify_data
from api.utils import get_credentials

api = Blueprint('health', __name__)


@api.route('/health', methods=['POST'])
def health():
    creds = get_credentials()
    _ = events(True, 1, creds)
    return jsonify_data({'status': 'ok'})
