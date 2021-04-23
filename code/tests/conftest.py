import jwt
import json

from app import app
from pytest import fixture
from http import HTTPStatus
from unittest.mock import MagicMock, patch
from api.errors import INVALID_ARGUMENT
from tests.mock_for_tests import PRIVATE_KEY

from tests.mock_for_tests import EXPECTED_RESPONSE_OF_JWKS_ENDPOINT


@fixture(scope='session')
def client():
    app.rsa_private_key = PRIVATE_KEY
    app.api_url = 'XXX'

    app.testing = True

    with app.test_client() as client:
        yield client


@fixture(scope='session')
def valid_jwt(client):
    def _make_jwt(
            user='some_user',
            password='some_pass',
            jwks_host='visibility.amp.cisco.com',
            aud='http://localhost',
            kid='02B1174234C29F8EFB69911438F597FF3FFEE6B7',
            wrong_structure=False
    ):
        payload = {
            'user': user,
            'pass': password,
            'API_URL': '',
            'PLATFORM_URL': '',
            'jwks_host': jwks_host,
            'aud': aud,
        }

        if wrong_structure:
            payload.pop('user')

        return jwt.encode(
            payload, client.application.rsa_private_key, algorithm='RS256',
            headers={
                'kid': kid
            }
        )

    return _make_jwt


@fixture(scope='module')
def mock_request():
    with patch('requests.get') as mock_request:
        yield mock_request


def qualys_api_response_mock(status_code, text=None, json_=None):
    mock_response = MagicMock()

    mock_response.status_code = status_code
    mock_response.ok = status_code == HTTPStatus.OK

    mock_response.text = text
    mock_response.json = lambda: json_ or {}

    return mock_response


@fixture(scope='session')
def qualys_response_public_key():
    return qualys_api_response_mock(
        HTTPStatus.OK,
        json_=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
    )


@fixture(scope='session')
def qualys_response_unauthorized_creds():
    return qualys_api_response_mock(
        HTTPStatus.UNAUTHORIZED,
        json_={
            'authentication_exceptions': ['InvalidCredentialsException']
        }
    )


@fixture(scope='session')
def qualys_response_internal_server_error():
    return qualys_api_response_mock(
        HTTPStatus.INTERNAL_SERVER_ERROR,
        text='Internal server error'
    )


@fixture(scope='session')
def qualys_response_events():
    with open('tests/unit/data/file_name.json', 'r') as file:
        data = json.loads(file.read())
        return qualys_api_response_mock(
            HTTPStatus.OK,
            json_=data['input']
        )


@fixture(scope='session')
def qualys_response_token():
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
