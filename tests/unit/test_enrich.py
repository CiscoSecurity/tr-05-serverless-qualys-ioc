from http import HTTPStatus
from unittest.mock import patch, MagicMock

from pytest import fixture
from requests.exceptions import SSLError


def headers(jwt):
    return {'Authorization': f'Bearer {jwt}'}


@fixture(scope='module')
def valid_json():
    return [{'type': 'email', 'value': 'ignore'},
            {'type': 'domain', 'value': 'google.com'}]


def test_enrich_call_with_ssl_error(
        client, valid_json, valid_jwt, qualys_response_token,
        sslerror_expected_payload
):
    with patch('requests.post') as token_mock, \
            patch('requests.get') as get_mock:

        token_mock.return_value = qualys_response_token
        mock_exception = MagicMock()
        mock_exception.reason.args.__getitem__().verify_message \
            = 'self signed certificate'
        get_mock.side_effect = SSLError(mock_exception)

        response = client.post(
            '/observe/observables', headers=headers(valid_jwt),
            json=valid_json
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == sslerror_expected_payload
        token_mock.assert_called_once()


def test_enrich_call_with_http_error(
        client, valid_json, valid_jwt,
        qualys_response_internal_server_error,
        fatal_error_expected_payload
):
    with patch('api.qualys.token') as token_mock, \
            patch('requests.get') as get_mock:
        token_mock.return_value = 'token'
        get_mock.return_value = qualys_response_internal_server_error

        response = client.post(
            '/observe/observables', headers=headers(valid_jwt),
            json=valid_json
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == fatal_error_expected_payload
        token_mock.assert_called_once()


def test_enrich_call_with_unauthorised_creds(
        client, valid_json, valid_jwt,
        qualys_response_unauthorized_creds,
        unauthorised_creds_expected_payload
):
    with patch('api.qualys.token') as token_mock, \
            patch('requests.get') as get_mock:
        token_mock.return_value = 'token'
        get_mock.return_value = qualys_response_unauthorized_creds

        response = client.post(
            '/observe/observables', headers=headers(valid_jwt),
            json=valid_json
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == unauthorised_creds_expected_payload
        assert token_mock.call_count == 2


def test_enrich_call_with_invalid_jwt(
        client, invalid_jwt, valid_json, fatal_error_expected_payload
):
    response = client.post(
        '/observe/observables', headers=headers(invalid_jwt), json=valid_json
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == fatal_error_expected_payload


@fixture(scope='module')
def invalid_json():
    return [{'type': 'domain'}]


def test_enrich_call_with_invalid_json(
        client, valid_jwt, invalid_json, fatal_error_expected_payload
):
    response = client.post(
        '/observe/observables', headers=headers(valid_jwt), json=invalid_json
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == fatal_error_expected_payload


def test_refer_call(
        client, valid_jwt, valid_json, refer_expected_payload
):
    response = client.post(
        '/refer/observables', headers=headers(valid_jwt), json=valid_json
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == refer_expected_payload


def test_deliberate_call(
        client, valid_jwt, valid_json
):
    response = client.post(
        '/deliberate/observables', headers=headers(valid_jwt), json=valid_json
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == {'data': {}}
