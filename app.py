from http import HTTPStatus

from flask import Flask, jsonify
from requests import HTTPError

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
        return jsonify({'errors': [{'type': 'fatal', **kwargs}]})

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

    return error(code='oops',
                 message='Something went wrong.')


@app.errorhandler(Exception)
def handle_any(ex: Exception):
    code = getattr(ex, 'code', 500)
    message = getattr(ex, 'description', 'Something went wrong.')
    reason = '.'.join([
        ex.__class__.__module__,
        ex.__class__.__name__
    ])

    return jsonify(code=code, message=message, reason=reason), code


if __name__ == '__main__':
    app.run()
