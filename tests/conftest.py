from datetime import datetime
from http import HTTPStatus
from unittest.mock import MagicMock

from authlib.jose import jwt
from pytest import fixture
from requests import HTTPError

from app import app


@fixture(scope='session')
def secret_key():
    # Generate some string based on the current datetime.
    return datetime.utcnow().isoformat()


@fixture(scope='session')
def client(secret_key):
    app.secret_key = secret_key

    app.testing = True

    with app.test_client() as client:
        yield client


@fixture(scope='session')
def valid_jwt(client):
    header = {'alg': 'HS256'}

    payload = {'user': 'user', 'pass': 'pass'}

    secret_key = client.application.secret_key

    return jwt.encode(header, payload, secret_key).decode('ascii')


@fixture(scope='session')
def invalid_jwt(valid_jwt):
    header, payload, signature = valid_jwt.split('.')

    def jwt_decode(s: str) -> dict:
        from authlib.common.encoding import urlsafe_b64decode, json_loads
        return json_loads(urlsafe_b64decode(s.encode('ascii')))

    def jwt_encode(d: dict) -> str:
        from authlib.common.encoding import json_dumps, urlsafe_b64encode
        return urlsafe_b64encode(json_dumps(d).encode('ascii')).decode('ascii')

    payload = jwt_decode(payload)

    # Corrupt the valid JWT by tampering with its payload.
    payload['superuser'] = True

    payload = jwt_encode(payload)

    return '.'.join([header, payload, signature])


def qualys_api_response_mock(status_code, text=None, json_=None):
    def raise_for_status(self):
        http_error_msg = ''
        if 400 <= self.status_code < 500:
            http_error_msg = u'%s Client Error: %s for url: %s' % (
                self.status_code, 'reason', self.url
            )

        elif 500 <= self.status_code < 600:
            http_error_msg = u'%s Server Error: %s for url: %s' % (
                self.status_code, 'reason', self.url
            )

        if http_error_msg:
            raise HTTPError(http_error_msg, response=self)

    mock_response = MagicMock()

    mock_response.status_code = status_code
    mock_response.ok = status_code == HTTPStatus.OK

    mock_response.text = text
    mock_response.json = json_ or MagicMock()

    mock_response.raise_for_status = lambda: raise_for_status(mock_response)

    return mock_response


@fixture(scope='session')
def qualys_response_unauthorized_creds(secret_key):
    return qualys_api_response_mock(
        HTTPStatus.UNAUTHORIZED,
        json_=lambda: {'detail': 'Error: Bad API key'}
    )


@fixture(scope='session')
def qualys_response_internal_server_error(secret_key):
    return qualys_api_response_mock(
        HTTPStatus.INTERNAL_SERVER_ERROR
    )


@fixture(scope='session')
def qualys_response_token(secret_key):
    return qualys_api_response_mock(
        HTTPStatus.OK,
        text='token'
    )


@fixture(scope='module')
def sslerror_expected_payload():
    return {
        'errors': [
            {
                'code': 'unknown',
                'message': 'Unable to verify SSL certificate:'
                           ' Self signed certificate',
                'type': 'fatal'
            }
        ]
    }


@fixture(scope='module')
def fatal_error_expected_payload():
    return {
        'errors': [
            {
                'type': 'fatal',
                'code': 'oops',
                'message': 'Something went wrong.'
            }
        ]
    }


@fixture(scope='module')
def unauthorised_creds_expected_payload():
    return {
        'errors': [
            {
                'code': 'access denied',
                'message': 'Access to Qualys IOC denied.',
                'type': 'fatal'
            }
        ]
    }


@fixture(scope='module')
def refer_expected_payload():
    return {
        'data': [
            {
                'categories': ['Search', 'Qualys'],
                'description': 'Check this domain status with Qualys',
                'id': 'ref-qualys-search-domain-google.com',
                'title': 'Search for this domain',
                'url': '/ioc/#/hunting?search=network.remote.address.'
                       'fqdn%3A%20%22google.com%22'
            }
        ]
    }
