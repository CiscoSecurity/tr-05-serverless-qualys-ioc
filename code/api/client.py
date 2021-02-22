import requests

from typing import Dict
from http import HTTPStatus
from flask import session, current_app
from requests.exceptions import SSLError, ConnectionError, MissingSchema

from api.errors import (
    CriticalResponseError,
    QualysConnectionError,
    QualysSSLError
)
from api.utils import url_join

agent = ('SecureX Threat Response Integrations '
         '<tr-integrations-support@cisco.com>')


def events(active: bool, amount: int, credentials: dict, filter_: str = None):
    """Performs a request to Qualys to search
    for events with the specified filter."""

    # Do not make requests if `amount` is non-positive.
    if amount <= 0:
        return []

    api = current_app.config['API_URL']
    url = f'{api}/ioc/events?pageSize={amount}'

    if filter_:
        url += f'&filter={filter_}'
    if active:
        url += '&state=true'

    return get_data(url, credentials)


def get_data(url, credentials):
    try:
        response = requests.get(url, headers=headers(credentials))

        # Refresh the token if expired.
        if response.status_code == HTTPStatus.UNAUTHORIZED:
            response = requests.get(url, headers=headers(credentials,
                                                         fresh=True))

        if response.ok:
            return response.json()

        if response.status_code in (
                HTTPStatus.NOT_FOUND, HTTPStatus.BAD_REQUEST
        ):
            return {}

        raise CriticalResponseError(response)

    except SSLError as error:
        raise QualysSSLError(error)
    except (ConnectionError, MissingSchema):
        raise QualysConnectionError(current_app.config['API_URL'])


def headers(credentials: dict, fresh: bool = False) -> Dict[str, str]:
    """Returns headers with an authorization token for Qualys."""
    return {
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + token(credentials, fresh),
        'Content-Type': 'application/json',
        'User-Agent': agent
    }


def token(credentials: dict, fresh: bool = False) -> str:
    """Returns an authorization token for Qualys."""

    if fresh or 'token' not in session:
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
