from http import HTTPStatus
from unittest.mock import patch, MagicMock

from pytest import fixture
from requests.exceptions import SSLError, ConnectionError

from .utils import headers


def routes():
    yield '/health'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


TOKEN = 'token'


def test_health_call_with_ssl_error(
        route, client, valid_jwt, sslerror_expected_payload,
        qualys_response_public_key
):
    with patch('api.client.token') as token_mock, \
            patch('requests.get') as get_mock:
        token_mock.return_value = TOKEN
        mock_exception = MagicMock()
        mock_exception.reason.args.__getitem__().verify_message \
            = 'self signed certificate'
        get_mock.side_effect = [
            qualys_response_public_key,
            SSLError(mock_exception)
        ]

        response = client.post(route, headers=headers(valid_jwt()))

        assert response.status_code == HTTPStatus.OK
        assert response.json == sslerror_expected_payload


def test_health_call_with_connection_error(
        route, client, valid_jwt, connection_error_expected_payload,
        qualys_response_public_key
):
    with patch('api.client.token') as token_mock, \
            patch('requests.get') as get_mock:
        token_mock.return_value = TOKEN
        get_mock.side_effect = [
            qualys_response_public_key,
            ConnectionError()
        ]

        response = client.post(route, headers=headers(valid_jwt()))

        assert response.status_code == HTTPStatus.OK
        assert response.json == connection_error_expected_payload


def test_health_call_with_http_error(
        route, client, valid_jwt,
        qualys_response_internal_server_error,
        internal_server_error_expected_payload,
        qualys_response_public_key
):
    with patch('api.client.token') as token_mock, \
            patch('requests.get') as get_mock:
        token_mock.return_value = TOKEN
        get_mock.side_effect = [
            qualys_response_public_key,
            qualys_response_internal_server_error
        ]

        response = client.post(route, headers=headers(valid_jwt()))

        assert response.status_code == HTTPStatus.OK
        assert response.json == internal_server_error_expected_payload


def test_health_call_success(
        route, client, valid_jwt, qualys_response_events,
        qualys_response_public_key
):
    with patch('api.client.token') as token_mock, \
            patch('requests.get') as get_mock:
        token_mock.return_value = TOKEN
        get_mock.side_effect = [
            qualys_response_public_key,
            qualys_response_events
        ]

        response = client.post(route, headers=headers(valid_jwt()))

        assert response.status_code == HTTPStatus.OK
        assert response.json == {'data': {'status': 'ok'}}
