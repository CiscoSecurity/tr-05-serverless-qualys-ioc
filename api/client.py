from http import HTTPStatus
from typing import Dict

import requests
from flask import session, current_app
from requests.exceptions import SSLError

from api.errors import (
    CriticalResponseError,
    QualysConnectionError,
    QualysSSLError
)
from api.utils import url_join, get_credentials

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

    return get_data(url)


def token(fresh: bool = False) -> str:
    """Returns an authorization token for Qualys."""

    if fresh or 'token' not in session:
        credentials = get_credentials()

        username = credentials['user']
        password = credentials['pass']

        url = url_join(current_app.config['API_URL'], '/auth')
        content = 'application/x-www-form-urlencoded'

        response = requests.post(url,
                                 data=b'username=' + username.encode() + b'&'
                                      b'password=' + password.encode() + b'&'
                                      b'token=true',
                                 headers={'Content-Type': content,
                                          'User-Agent': agent})

        if not response.ok:
            raise CriticalResponseError(response)

        session['token'] = response.text

    return session['token']


def headers(fresh: bool = False) -> Dict[str, str]:
    """Returns headers with an authorization token for Qualys."""
    return {
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + token(fresh),
        'Content-Type': 'application/json',
        'User-Agent': agent
    }


def get_data(url):
    try:
        response = requests.get(url, headers=headers())

        # Refresh the token if expired.
        if response.status_code == HTTPStatus.UNAUTHORIZED:
            response = requests.get(url, headers=headers(fresh=True))

        if response.ok:
            return response.json()

        if response.status_code in (
                HTTPStatus.NOT_FOUND, HTTPStatus.BAD_REQUEST
        ):
            return {}

        raise CriticalResponseError(response)

    except SSLError as error:
        raise QualysSSLError(error)
    except ConnectionError:
        raise QualysConnectionError(current_app.config['API_URL'])
