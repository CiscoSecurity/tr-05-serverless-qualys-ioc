from http import HTTPStatus

import requests
from flask import current_app

from .token import headers


def events(filter_: str, active: bool, amount: int):
    """Performs a request to Qualys to search
    for events with the specified filter."""

    # Do not make requests if `amount` is non-positive.
    if amount <= 0:
        return []

    api = current_app.config['API_URL']
    url = f'{api}/ioc/events' \
          f'?filter={filter_}' \
          f'&pageSize={amount}'
    if active:
        url += '&state=true'

    response = requests.get(url, headers=headers())

    # Refresh the token if expired.
    if response.status_code == HTTPStatus.UNAUTHORIZED.value:
        response = requests.get(url, headers=headers(fresh=True))

    response.raise_for_status()

    return response.json()
