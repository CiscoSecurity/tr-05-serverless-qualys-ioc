import pytest

from ctrlibrary.threatresponse.enrich import (
    enrich_refer_observables, enrich_observe_observables)
from ctrlibrary.core.utils import get_observables


@pytest.mark.parametrize(
    'observable, observable_type',
    (('213.128.83.163', 'ip'),
     ('ceres.alastyr.com', 'domain'),
     ('31b2fd20f0f5cdf922009558d592514cfaa6c1fca1570a0f3c06df755613e024',
      'sha256'),
     ('415e5cc23e106483711abe70ad78c8e2', 'md5'),
     ('buzus.exe', 'file_name'))
)
def test_positive_relay_refer_observables_sightings(
        module_headers, observable, observable_type):
    """ Perform testing for enrich refer observables endpoint for file_name
    in Qualys

    ID: CCTRI-744-6114ff9d-e97f-47ae-ab41-6508eec000d6

    Steps:
        1. Send request with observable that has file_name type to endpoint
            refer observables

    Expectedresults:
        1. Check that data in response body contains expected information
            from Qualys module

    Importance: Critical
    """

    # Get sightings
    observables = [{"value": observable, "type": observable_type}]
    response = enrich_refer_observables(
        payload=observables,
        **{'headers': module_headers})['data']
    sightings = get_observables(response, 'Qualys IOC')

    # Check respond data
    assert sightings['categories'] == ['Qualys', 'Search']
    assert sightings['module'] == 'Qualys IOC'
    assert sightings['module_instance_id']
    assert sightings['module_type_id']
    assert sightings['description']
    assert sightings['id'] == (
        f'ref-qualys-search-{observable_type}-{observable}')
    assert sightings['url']
    assert sightings['title']
    assert sightings['categories']


@pytest.mark.parametrize(
    'observable, observable_type',
    (('a23-38-112-137.deploy.static.akamaitechnologies.com', 'domain'),
     ('127.0.0.1', 'ip'),
     ('701fb8ed9d1f72c901e207dd01b481266be8458f6e03750c1a139c901f2995fa',
      'sha256'),
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

    confidence_and_severity = [
        'High', 'Info', 'Low', 'Medium', 'None', 'Unknown'
    ]
    # Get sightings
    observables = [{"value": observable, "type": observable_type}]
    response_from_all_modules = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers})['data']
    response_from_qualys_module = get_observables(
        response_from_all_modules, 'Qualys IOC')
    assert response_from_qualys_module['module'] == 'Qualys IOC'
    assert response_from_qualys_module['module_instance_id']
    assert response_from_qualys_module['module_type_id']

    sightings = response_from_qualys_module['data']['sightings']

    assert len(sightings['docs']) > 0

    # Check respond data
    for sighting in sightings['docs']:
        assert sighting['description']
        assert sighting['schema_version']

        for relation in sighting['relations']:
            if relation['relation'] == 'Resolved_To':
                assert relation['related']['value'] == observable
                assert relation['related']['type'] == observable_type

        assert sighting['observables'] == observables
        assert sighting['observed_time']['start_time']
        assert sighting['id']
        assert sighting['type'] == 'sighting'
        assert sighting['count'] == 1
        assert sighting['source'] == 'Qualys IOC'
        assert sighting['external_ids']
        assert sighting['confidence'] in confidence_and_severity
        assert sighting['severity'] in confidence_and_severity
        assert sighting['sensor'] == 'endpoint'
        assert sighting['data']
        assert 'external_references' in sighting

        assert sighting['targets'][0]['type'] == 'endpoint'
        assert sighting['targets'][0]['observables']
        assert sighting['targets'][0]['observed_time']['start_time']
        assert sighting['targets'][0]['os']

    assert sightings['count'] == len(sightings['docs'])
