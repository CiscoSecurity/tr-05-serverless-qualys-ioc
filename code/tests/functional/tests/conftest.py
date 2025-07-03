# coding: utf-8
"""Configurations for py.test runner"""

import pytest

from ctrlibrary.core import settings
from ctrlibrary.relay_api.base import RelayApiToken
from ctrlibrary.threatresponse import token
from tests.functional.library.endpoints import RELAY_PREFIX


def pytest_collection_modifyitems():
    if not settings.configured:
        settings.configure()
    return settings


@pytest.fixture(scope='session')
def session_headers():
    return {'Authorization': 'Bearer {}'.format(
        settings.server.app_client_password)}


@pytest.fixture(scope='session')
def relay_api(session_headers):
    return RelayApiToken(
        hostname=settings.server.app_hostname,
        prefix=RELAY_PREFIX,
        token={'headers': session_headers}
    )


@pytest.fixture(scope='module')
def module_token():
    return token.request_token(
        settings.server.ctr_client_id, settings.server.ctr_client_password)


@pytest.fixture(scope='module')
def module_headers(module_token):
    return {'Authorization': 'Bearer {}'.format(module_token)}
