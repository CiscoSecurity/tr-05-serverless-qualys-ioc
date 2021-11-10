from flask import Flask, jsonify

from api import health, enrich, version, watchdog
from api.errors import TRFormattedError
from api.utils import add_error, jsonify_result

app = Flask(__name__)
app.config.from_object('config.Config')

app.register_blueprint(health.api)
app.register_blueprint(enrich.api)
app.register_blueprint(version.api)
app.register_blueprint(watchdog.api)


@app.errorhandler(TRFormattedError)
def handle_tr_formatted_error(error):
    app.logger.error(error.json)
    add_error(error)
    return jsonify_result()


@app.errorhandler(Exception)
def handle_error(exception):
    app.logger.error(exception)
    code = getattr(exception, 'code', 500)
    message = getattr(exception, 'description', 'Something went wrong.')
    reason = '.'.join([
        exception.__class__.__module__,
        exception.__class__.__name__,
    ])

    response = jsonify(code=code, message=message, reason=reason)
    return response, code


if __name__ == '__main__':
    app.run()
