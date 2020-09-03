from http import HTTPStatus

from pytest import fixture


def routes():
    yield '/health'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


def test_health_call_success(route, client):
    response = client.post(route)

    assert response.status_code == HTTPStatus.OK
    assert response.json == {'data': {'status': 'ok'}}
