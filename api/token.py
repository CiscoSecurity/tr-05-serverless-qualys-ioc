from typing import Dict

import requests
from authlib.jose import jwt
from flask import session, current_app, request

from .url import join


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

        response = requests.post(url,
                                 data=b'username=' + username.encode() + b'&'
                                      b'password=' + password.encode() + b'&'
                                      b'token=true',
                                 headers={'Content-Type':
                                          'application/x-www-form-urlencoded'})
        response.raise_for_status()

        session['token'] = response.text

    return session['token']


def headers(fresh: bool = False) -> Dict[str, str]:
    """Returns headers with an authorization token."""
    return {
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + token(fresh),
        'Content-Type': 'application/json',
        'User-Agent': ('Cisco Threat Response Integrations '
                       '<tr-integrations-support@cisco.com>')
    }
