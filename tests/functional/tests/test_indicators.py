import pytest

from ctrlibrary.threatresponse.enrich import enrich_observe_observables
from ctrlibrary.core.utils import get_observables

SCHEMA_VERSION = '1.0.16'


@pytest.mark.parametrize(
    'observable,observable_type',
    (('701fb8ed9d1f72c901e207dd01b481266be8458f6e03750c1a139c901f2995fa',
      'sha256'),
     ('ec2-52-58-78-16.eu-central-1.compute.amazonaws.com', 'domain'),
     ('52.58.78.16', 'ip'),
     ('WininetStartupMutex', 'mutex'),
     (r'C:\Users\User01\Downloads\Malware', 'file_path'),
     ('buzus.exe', 'file_name'))
)
def test_positive_enrich_observe_observables_indicators(
        module_headers, observable, observable_type):
    """Perform testing for enrich observe observables endpoint to get
    indicators for observable different types from Qualys module

    ID: CCTRI-798-eff9a553-95fe-495a-ac20-768c0241822b

    Steps:
        1. Send request to enrich observe observables endpoint

    Expectedresults:
        1. Check that data in response body contains expected indicators for
            observable from Qualys module

    Importance: Critical
    """
    expected_observable = {
        'schema_version': SCHEMA_VERSION,
        'source': 'Qualys IOC',
        'type': 'indicator'
    }

    # Get indicator
    observables = [{"value": observable, "type": observable_type}]
    response = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )['data']
    direct_observables = get_observables(response, 'Qualys IOC')

    # Check respond data
    indicator = direct_observables['data']['indicators']['docs'][0]

    assert 'id' in indicator
    assert 'valid_time' in indicator

    for key in expected_observable.keys():
        assert expected_observable[key] == indicator[key]


def test_positive_enrich_observe_observables_detail_indicators(module_headers):
    """ Perform testing for enrich observe observables endpoint to get
    indicators for observable Qualys module with details respond

    ID: CCTRI-798-f6b973fd-29d9-40ce-96a2-491c7dda50af

    Steps:
        1. Send request with observable that has md5 type to observe
            observables endpoint

    Expectedresults:
        1. Check that data in response body contains expected information
            in indicators from Qualys module

    Importance: Critical
    """
    observable = '415e5cc23e106483711abe70ad78c8e2'
    observable_type = 'md5'

    expected_observable = {
        'schema_version': SCHEMA_VERSION,
        'severity': 'Medium',
        'source': 'Qualys IOC',
        'producer': 'Qualys IOC',
        'type': 'indicator',
        'external_ids': (
            ['F_5b49017b-90dd-4a6d-92ea-7651bafdc1ec_-8729057863409581450']),
        'confidence': 'High'
    }

    # Get indicator
    observables = [{"value": observable, "type": observable_type}]
    response = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )['data']
    direct_observables = get_observables(response, 'Qualys IOC')

    # Check respond data
    indicator = direct_observables['data']['indicators']['docs'][0]

    for key in expected_observable.keys():
        assert expected_observable[key] == indicator[key]
