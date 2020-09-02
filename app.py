from http import HTTPStatus

from flask import Flask, jsonify
from requests import HTTPError
from requests.exceptions import SSLError

from api import health, enrich, respond

app = Flask(__name__)
app.config.from_object('config.Config')

app.register_blueprint(health.api)
app.register_blueprint(enrich.api)
app.register_blueprint(respond.api)


@app.errorhandler(HTTPError)
def handle_http(ex: HTTPError):
    code = ex.response.status_code

    def empty():
        return jsonify({})

    def error(**kwargs):
        payload = {'errors': [{'type': 'fatal', **kwargs}]}

        if hasattr(ex, 'data'):
            payload.update(ex.data)

        return jsonify(payload)

    if code == HTTPStatus.BAD_REQUEST:
        return empty()
    if code == HTTPStatus.NOT_FOUND:
        return empty()
    if code == HTTPStatus.TOO_MANY_REQUESTS:
        return error(code='too many requests',
                     message='Too many requests to Qualys IOC '
                             'have been made. '
                             'Please try again later.')
    if code == HTTPStatus.UNAUTHORIZED:
        return error(code='access denied',
                     message='Access to Qualys IOC denied.')
    if code == HTTPStatus.SERVICE_UNAVAILABLE:
        return error(code='service unavailable',
                     message='Service temporarily unavailable. '
                             'Please try again later.')

    return handle_any(ex)


@app.errorhandler(SSLError)
def handle_ssl(ex: SSLError):
    error = ex.args[0].reason.args[0]
    message = getattr(error, 'verify_message', error.args[0]).capitalize()

    payload = {
        'errors': [
            {
                'type': 'fatal',
                'code': 'unknown',
                'message': f'Unable to verify SSL certificate: {message}'
            }
        ]
    }

    return jsonify(payload)


@app.errorhandler(Exception)
def handle_any(ex: Exception):
    payload = {
        'errors': [
            {
                'type': 'fatal',
                'code': 'oops',
                'message': 'Something went wrong.'
            }
        ]
    }

    if hasattr(ex, 'data'):
        payload.update(ex.data)

    return jsonify(payload)


if __name__ == '__main__':
    app.run()
