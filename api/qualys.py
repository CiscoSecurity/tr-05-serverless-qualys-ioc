from http import HTTPStatus
from typing import Dict

import requests
from authlib.jose import jwt
from flask import session, current_app, request

from .url import join

agent = ('Cisco Threat Response Integrations '
         '<tr-integrations-support@cisco.com>')


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


def token(fresh: bool = False) -> str:
    """Returns an authorization token."""

    if fresh or 'token' not in session:
        scheme, payload = request.headers['Authorization'].split(None, 1)

        if scheme.lower() != 'bearer':
            raise ValueError('Expected the scheme to be "Bearer".')

        credentials = jwt.decode(payload, current_app.config['SECRET_KEY'])

        username = credentials['user']
        password = credentials['pass']

        url = join(current_app.config['API_URL'], '/auth')
        content = 'application/x-www-form-urlencoded'

        response = requests.post(url,
                                 data=b'username=' + username.encode() + b'&'
                                      b'password=' + password.encode() + b'&'
                                      b'token=true',
                                 headers={'Content-Type': content,
                                          'User-Agent': agent})
        response.raise_for_status()

        session['token'] = response.text

    return session['token']


def headers(fresh: bool = False) -> Dict[str, str]:
    """Returns headers with an authorization token."""
    return {
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + token(fresh),
        'Content-Type': 'application/json',
        'User-Agent': agent
    }
