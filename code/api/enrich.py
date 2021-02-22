from functools import partial
from urllib.parse import quote

from flask import Blueprint, current_app, g

from .observables import Observable
from .schema import ObservableSchema
from .utils import get_json, jsonify_result, jsonify_data, get_credentials

api = Blueprint('enrich', __name__)

get_observables = partial(get_json, schema=ObservableSchema(many=True))


@api.route('/observe/observables', methods=['POST'])
def observe():
    observables = get_observables()
    creds = get_credentials()
    limit = current_app.config['CTR_ENTITIES_LIMIT']

    g.sightings = []
    g.indicators = []
    g.judgements = []
    g.relationships = []

    for pair in observables:
        type_ = pair['type']
        value = pair['value']

        observable = Observable.of(type_)
        if observable is None:
            continue

        observed_data = observable.observe(value, limit, creds)
        g.sightings.extend(observed_data["sightings"])
        g.indicators.extend(observed_data["indicators"])
        g.judgements.extend(observed_data["judgements"])
        g.relationships.extend(observed_data["relationships"])

    return jsonify_result()


@api.route('/deliberate/observables', methods=['POST'])
def deliberate():
    return jsonify_data({})


@api.route('/refer/observables', methods=['POST'])
def refer():
    observables = get_observables()
    get_credentials()
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

    return jsonify_data(result)
