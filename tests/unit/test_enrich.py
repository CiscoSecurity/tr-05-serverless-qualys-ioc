from http import HTTPStatus
from unittest.mock import patch, MagicMock

from pytest import fixture
from requests.exceptions import SSLError


def headers(jwt):
    return {'Authorization': f'Bearer {jwt}'}


@fixture(scope='module')
def valid_json():
    return [{'type': 'email', 'value': 'ignore'},
            {'type': 'file_name', 'value': 'ChromeSetup.exe'}]


def test_deliberate_call_success(
        client, valid_jwt, valid_json
):
    response = client.post(
        '/deliberate/observables', headers=headers(valid_jwt), json=valid_json
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == {'data': {}}


def test_refer_call_success(
        client, valid_jwt, valid_json, refer_expected_payload
):
    response = client.post(
        '/refer/observables', headers=headers(valid_jwt), json=valid_json
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == refer_expected_payload


OBSERVE_OBSERVABLES_ROUT = '/observe/observables'
TOKEN = 'token'


@fixture(scope='module')
def invalid_json():
    return [{'type': 'domain'}]


def test_enrich_call_with_invalid_json(
        client, valid_jwt, invalid_json, invalid_json_expected_payload
):
    response = client.post(
        OBSERVE_OBSERVABLES_ROUT, headers=headers(valid_jwt), json=invalid_json
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == invalid_json_expected_payload


def test_enrich_call_success(
        client, valid_json, valid_jwt,
        qualys_response_token, qualys_response_events
):
    with patch('requests.post') as token_mock, \
            patch('requests.get') as get_mock:
        token_mock.return_value = qualys_response_token
        get_mock.return_value = qualys_response_events

        response = client.post(
            OBSERVE_OBSERVABLES_ROUT, headers=headers(valid_jwt),
            json=valid_json
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json.get('data')
        assert response.json.get('errors') is None
        token_mock.assert_called_once()


def test_enrich_call_with_ssl_error(
        client, valid_json, valid_jwt, sslerror_expected_payload
):
    with patch('api.client.token') as token_mock, \
            patch('requests.get') as get_mock:
        token_mock.return_value = TOKEN
        mock_exception = MagicMock()
        mock_exception.reason.args.__getitem__().verify_message \
            = 'self signed certificate'
        get_mock.side_effect = SSLError(mock_exception)

        response = client.post(
            OBSERVE_OBSERVABLES_ROUT, headers=headers(valid_jwt),
            json=valid_json
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == sslerror_expected_payload
        token_mock.assert_called_once()


def test_enrich_call_with_http_error(
        client, valid_json, valid_jwt,
        qualys_response_internal_server_error,
        internal_server_error_expected_payload
):
    with patch('api.client.token') as token_mock, \
            patch('requests.get') as get_mock:
        token_mock.return_value = TOKEN
        get_mock.return_value = qualys_response_internal_server_error

        response = client.post(
            OBSERVE_OBSERVABLES_ROUT, headers=headers(valid_jwt),
            json=valid_json
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == internal_server_error_expected_payload
        token_mock.assert_called_once()


def test_enrich_call_success_with_extended_error_handling(
        client, valid_json, valid_jwt,
        qualys_response_events, qualys_response_internal_server_error,
        internal_server_error_expected_payload
):
    with patch('api.client.token') as token_mock, \
            patch('requests.get') as get_mock:
        token_mock.return_value = TOKEN
        get_mock.side_effect = [qualys_response_events, qualys_response_events,
                                qualys_response_internal_server_error]

        response = client.post(
            OBSERVE_OBSERVABLES_ROUT, headers=headers(valid_jwt),
            json=[*valid_json, {'type': 'domain', 'value': 'google.com'}]
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json.pop('data')
        assert response.json == internal_server_error_expected_payload
        assert token_mock.call_count == 3
