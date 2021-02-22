from flask import request, Blueprint
from api.errors import WatchdogError
from api.utils import jsonify_data

api = Blueprint('watchdog', __name__)


@api.route('/watchdog', methods=['GET'])
def watchdog():
    try:
        watchdog_key = request.headers['Health-Check']
        return jsonify_data(watchdog_key)
    except KeyError:
        raise WatchdogError
