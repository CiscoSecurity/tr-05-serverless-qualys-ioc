from pytest import fixture
from .utils import headers
from http import HTTPStatus
from unittest.mock import patch
from api.errors import AUTH_ERROR


def routes():
    yield '/health'
    yield '/observe/observables'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@fixture(scope='module')
def valid_json():
    return [{'type': 'domain', 'value': 'ibm.com'}]


def authorization_error(message):
    return {
        'errors': [
            {
                'code': AUTH_ERROR,
                'message': f'Authorization failed: {message}',
                'type': 'fatal'
            }
        ]
    }


def test_call_with_authorization_header_missing(
        route, client, valid_json
):
    response = client.post(route, json=valid_json)

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_error(
        'Authorization header is missing'
    )


def test_call_with_authorization_type_error(route, client, valid_json):
    response = client.post(
        route, json=valid_json, headers={'Authorization': 'Basic blabla'}
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_error('Wrong authorization type')


def test_call_with_jwt_structure_error(route, client, valid_json, mock_request,
                                       qualys_response_public_key):
    mock_request.return_value = qualys_response_public_key
    response = client.post(
        route, json=valid_json, headers={'Authorization': 'Bearer blabla'}
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_error('Wrong JWT structure')


def test_call_with_jwt_payload_structure_error(
        route, client, valid_json, valid_jwt,
        qualys_response_public_key,
        qualys_response_unauthorized_creds,
        mock_request
):
    mock_request.side_effect = [
        qualys_response_unauthorized_creds,
        qualys_response_public_key
    ]
    response = client.post(
        route, json=valid_json,
        headers=headers(valid_jwt(wrong_structure=True))
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_error('Wrong JWT payload structure')


def test_call_with_unauthorized_creds(
        route, client, valid_jwt, valid_json,
        qualys_response_unauthorized_creds,
        qualys_response_public_key,
        qualys_response_events
):
    with patch('api.client.token') as token_mock, \
            patch('requests.get') as requests_mock:
        token_mock.return_value = 'TOKEN'
        requests_mock.side_effect = [
            qualys_response_public_key,
            qualys_response_unauthorized_creds,
            qualys_response_unauthorized_creds
        ]

        response = client.post(
            route, headers=headers(valid_jwt()),
            json=valid_json
        )

        assert response.status_code == HTTPStatus.OK
        assert token_mock.call_count == 2
        assert response.json == authorization_error(
            "['InvalidCredentialsException']"
        )
