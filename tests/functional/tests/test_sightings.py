import pytest

from ctrlibrary.threatresponse.enrich import (
    enrich_refer_observables, enrich_observe_observables)
from ctrlibrary.core.utils import get_observables

SCHEMA_VERSION = '1.0.16'


@pytest.mark.parametrize(
    'observable, observable_type',
    (('ceres.alastyr.com', 'domain'),
     ('31b2fd20f0f5cdf922009558d592514cfaa6c1fca1570a0f3c06df755613e024',
      'sha256'),
     ('415e5cc23e106483711abe70ad78c8e2', 'md5'),
     ('buzus.exe', 'file_name'))
)
def test_positive_relay_refer_observables_sightings(
        module_headers, observable, observable_type):
    """ Perform testing for enrich refer observables endpoint for file_name
    in in Qualys

    ID: CCTRI-744-6114ff9d-e97f-47ae-ab41-6508eec000d6

    Steps:
        1. Send request with observable that has file_name type to endpoint
            refer observables

    Expectedresults:
        1. Check that data in response body contains expected information
            from Qualys module

    Importance: Critical
    """

    expected_observable = {
        'module': 'Qualys IOC',
        'module-type': 'RelayModule+Custom+CS'
    }

    # Get sightings
    observables = [{"value": observable, "type": observable_type}]
    sighting = enrich_refer_observables(
        payload=observables,
        **{'headers': module_headers})['data']
    direct_observables = get_observables(sighting, 'Qualys IOC')

    # Check respond data
    assert direct_observables['categories'] == ['Qualys', 'Search']

    for key in expected_observable.keys():
        assert expected_observable[key] == direct_observables[key]

    assert 'description' in direct_observables
    assert 'id' in direct_observables
    assert 'url' in direct_observables
    assert 'title' in direct_observables
    assert 'categories' in direct_observables


def test_positive_relay_refer_observables_detail_sightings(module_headers):
    """ Perform testing for enrich refer observables endpoint for IP  in Qualys
    with details respond

    ID: CCTRI-744-6114ff9d-e97f-47ae-ab41-6508eec000d6

    Steps:
        1. Send request with observable that has IP type to refer
            observables endpoint

    Expectedresults:
        1. Check that data in response body contains expected information
            from Qualys module

    Importance: Critical
    """
    observable = '213.128.83.163'
    observable_type = 'ip'

    expected_observable = {
        'description': 'Check this IP status with Qualys',
        'id': 'ref-qualys-search-ip-213.128.83.163',
        'module': 'Qualys IOC',
        'module-type': 'RelayModule+Custom+CS',
        'title': 'Search for this IP',
        'categories': ['Qualys', 'Search'],
        'url': ('/ioc/#/hunting?search=network.local.address.ip%3A%20%22213.'
                '128.83.163%22%20or%20network.remote.address.ip%3A%20%22213.'
                '128.83.163%22')
    }

    # Get sightings
    observables = [{"value": observable, "type": observable_type}]
    sighting = enrich_refer_observables(
        payload=observables,
        **{'headers': module_headers})['data']
    direct_observables = get_observables(sighting, 'Qualys IOC')

    # Check respond data
    assert direct_observables['categories'] == ['Qualys', 'Search']

    for key in expected_observable.keys():
        assert expected_observable[key] <= direct_observables[key]


def test_positive_enrich_observe_observables_detail_sightings(module_headers):
    """Perform testing for enrich observe observables endpoint to get
    sightings for observable Qualys module with details respond

    ID: CCTRI-750-6ac272bd-5a91-4ecb-a907-e7cfcb5c616d

    Steps:
        1. Send request with observable that has SHA256 type to observe
            observables endpoint

    Expectedresults:
        1. Check that data in response body contains expected information
            in sightings from Qualys module with details respond

    Importance: Critical
    """
    observable = (
        '701fb8ed9d1f72c901e207dd01b481266be8458f6e03750c1a139c901f2995fa')
    observable_type = 'sha256'
    expected_observable = {
        'schema_version': SCHEMA_VERSION,
        'external_ids': (
            ['F_5b49017b-90dd-4a6d-92ea-7651bafdc1ec_-8729057863409581450']),
        'severity': 'Medium',
        'source': 'Qualys IOC',
        'type': 'sighting',
        'confidence': 'High',
        'count': 1
    }

    # Get sightings
    observables = [{"value": observable, "type": observable_type}]
    response = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )['data']
    direct_observables = get_observables(response, 'Qualys IOC')

    # Check respond data
    sighting = direct_observables['data']['sightings']['docs'][0]
    assert sighting['observables'] == observables

    for key in expected_observable.keys():
        assert expected_observable[key] == sighting[key]


@pytest.mark.parametrize(
    'observable, observable_type',
    (('ec2-52-58-78-16.eu-central-1.compute.amazonaws.com', 'domain'),
     ('52.58.78.16', 'ip'),
     ('415e5cc23e106483711abe70ad78c8e2', 'md5'),
     ('WininetStartupMutex', 'mutex'),
     (r'C:\Users\User01\Downloads\Malware', 'file_path'),
     ('buzus.exe', 'file_name'))
)
def test_positive_enrich_observe_observables_sightings(
        module_headers, observable, observable_type):
    """ Perform testing for enrich observe observables endpoint to get
    sightings for observable Qualys module

    ID: CCTRI-750-332e08e6-3998-4d2c-b740-65db14e9ea9d

    Steps:
        1. Send request to enrich observe observable endpoint

    Expectedresults:
        1. Check that data in response body contains expected information
            in sightings from Qualys module

    Importance: Critical
    """

    expected_observable = {
        'schema_version': SCHEMA_VERSION,
        'source': 'Qualys IOC',
        'type': 'sighting'
    }

    # Get sightings
    observables = [{"value": observable, "type": observable_type}]
    response = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers})['data']
    direct_observables = get_observables(response, 'Qualys IOC')

    # Check respond data
    sighting = direct_observables['data']['sightings']['docs'][0]
    assert sighting['observables'] == observables
    assert set(sighting['observed_time'].keys()) == {'start_time'}
    assert 'id' in sighting

    for key in expected_observable.keys():
        assert expected_observable[key] == sighting[key]
