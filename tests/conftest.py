import json
from datetime import datetime
from http import HTTPStatus
from unittest.mock import MagicMock

from authlib.jose import jwt
from pytest import fixture

from api.errors import INVALID_ARGUMENT
from app import app


@fixture(scope='session')
def secret_key():
    # Generate some string based on the current datetime.
    return datetime.utcnow().isoformat()


@fixture(scope='session')
def client(secret_key):
    app.secret_key = secret_key
    app.api_url = 'XXX'

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
    mock_response = MagicMock()

    mock_response.status_code = status_code
    mock_response.ok = status_code == HTTPStatus.OK

    mock_response.text = text
    mock_response.json = lambda: json_ or {}

    return mock_response


@fixture(scope='session')
def qualys_response_unauthorized_creds(secret_key):
    return qualys_api_response_mock(
        HTTPStatus.UNAUTHORIZED,
        json_={
            'authentication_exceptions': ['InvalidCredentialsException']
        }
    )


@fixture(scope='session')
def qualys_response_internal_server_error(secret_key):
    return qualys_api_response_mock(
        HTTPStatus.INTERNAL_SERVER_ERROR,
        text='Internal server error'
    )


@fixture(scope='session')
def qualys_response_events(secret_key):
    with open('tests/unit/data/file_name.json', 'r') as file:
        data = json.loads(file.read())
        return qualys_api_response_mock(
            HTTPStatus.OK,
            json_=data['input']
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
def connection_error_expected_payload():
    return {
        'errors': [
            {
                'code': 'connection error',
                'message': 'Unable to connect Microsoft Qualys Security,'
                           ' validate the configured API URL: ',
                'type': 'fatal'
            }
        ]
    }


@fixture(scope='module')
def internal_server_error_expected_payload():
    return {
        'errors': [
            {
                'type': 'fatal',
                'code': 'unknown',
                'message': 'Unexpected response from Qualys IOC:'
                           ' Internal server error'
            }
        ]
    }


@fixture(scope='module')
def invalid_json_expected_payload():
    return {
        'errors': [
            {
                'code': INVALID_ARGUMENT,
                'message':
                    'Invalid JSON payload received. {"0": {"value": '
                    '["Missing data for required field."]}}',
                'type': 'fatal'}
        ]
    }


@fixture(scope='module')
def refer_expected_payload():
    return {
        'data': [
            {
                'categories': ['Search', 'Qualys'],
                'description': 'Check this file name status with Qualys',
                'id': 'ref-qualys-search-file_name-ChromeSetup.exe',
                'title': 'Search for this file name',
                'url': '/ioc/#/hunting'
                       '?search=file.name%3A%20%22ChromeSetup.exe%22'
            }
        ]
    }
