from flask import Flask, jsonify

from api import health, enrich, respond


app = Flask(__name__)
app.config.from_object('config.Config')

app.register_blueprint(health.api)
app.register_blueprint(enrich.api)
app.register_blueprint(respond.api)


@app.errorhandler(Exception)
def error(ex):
    code = getattr(ex, 'code', 500)
    message = getattr(ex, 'description', 'Something went wrong.')
    reason = '.'.join([
        ex.__class__.__module__,
        ex.__class__.__name__
    ])

    return jsonify(code=code, message=message, reason=reason), code


if __name__ == '__main__':
    app.run()
