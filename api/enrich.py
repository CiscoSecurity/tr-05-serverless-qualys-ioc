from urllib.parse import quote

from flask import Blueprint, request, jsonify, current_app
from werkzeug.exceptions import BadRequest

from . import schema
from .observables import Observable

api = Blueprint('enrich', __name__)


@api.route('/observe/observables', methods=['POST'])
def observe():
    observables = json(request, schema.observables)

    url = current_app.config['API_URL']
    data = {}

    for pair in observables:
        type_ = pair['type']
        value = pair['value']

        observable = Observable.of(type_)
        if observable is None:
            continue

        observed = observable.observe(url, value)

        for obj, docs in observed.items():
            if docs:
                data.setdefault(obj, {})
                data[obj]['docs'] = data[obj].get('docs', []) + docs
                data[obj]['count'] = len(data[obj]['docs'])

    return jsonify({'data': data})


@api.route('/deliberate/observables', methods=['POST'])
def deliberate():
    return jsonify({'data': {}})


@api.route('/refer/observables', methods=['POST'])
def refer():
    observables = json(request, schema.observables)
    result = []

    for pair in observables:
        type_ = pair['type']
        value = pair['value']

        observable = Observable.of(type_)
        if observable is None:
            continue

        result.append({
            'id': f'ref-qualys-search-{type_}-{quote(value, safe="")}',
            'title':
                f'Search for this {observable.name()}',
            'description':
                f'Check this {observable.name()} status with Qualys',
            'url': observable.refer(current_app.config['PLATFORM_URL'], value),
            'categories': ['Search', 'Qualys']
        })

    return jsonify({'data': result})


def json(request_, schema_):
    """Parses the body of a request as JSON according to a provided schema."""

    body = request_.get_json(force=True, silent=True, cache=False)
    error = schema_.validate(body) or None

    if error is not None:
        raise BadRequest('Invalid JSON format.')

    return body
