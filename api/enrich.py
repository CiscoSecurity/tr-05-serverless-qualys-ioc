from urllib.parse import quote

from flask import Blueprint, request, jsonify, current_app
from werkzeug.exceptions import BadRequest

from . import schema
from .observables import Observable

api = Blueprint('enrich', __name__)


@api.route('/observe/observables', methods=['POST'])
def observe():
    observables = json(request, schema.observables)

    data = {}
    limit = current_app.config['CTR_ENTITIES_LIMIT']

    try:
        for pair in observables:
            type_ = pair['type']
            value = pair['value']

            observable = Observable.of(type_)
            if observable is None:
                continue

            for name, objects in observable.observe(value, limit).items():
                if objects['count'] == 0:
                    continue

                data.setdefault(name, {})
                data[name]['docs'] = data[name].get('docs', []) + objects['docs']
                data[name]['count'] = data[name].get('count', 0) + objects['count']
    except Exception as exception:
        if data:
            setattr(exception, 'data', {'data': data})

        raise

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
