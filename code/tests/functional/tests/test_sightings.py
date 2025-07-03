import pytest
from ctrlibrary.threatresponse.enrich import (
    enrich_refer_observables,
    enrich_observe_observables
)
from ctrlibrary.core.utils import get_observables
from tests.functional.tests.constants import (
    MODULE_NAME,
    CONFIDENCE,
    SEVERITY,
    OBSERVABLE_HUMAN_READABLE_NAME,
    CTR_ENTITIES_LIMIT
)


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
    observables = [{'value': observable, 'type': observable_type}]
    response_from_all_modules = enrich_refer_observables(
        payload=observables,
        **{'headers': module_headers}
    )

    sightings = get_observables(response_from_all_modules, MODULE_NAME)

    assert sightings['module'] == MODULE_NAME
    assert sightings['module_instance_id']
    assert sightings['module_type_id']
    assert sightings['description']
    assert sightings['id'] == (
        f'ref-qualys-search-{observable_type}-{observable}')
    assert sightings['url'].startswith(
        'https://qualysguard.qg3.apps.qualys.com')
    assert sightings['title'] == (
        f'Search for this '
        f'{OBSERVABLE_HUMAN_READABLE_NAME[observable_type]}'
    )
    assert sightings['categories'] == ['Qualys', 'Search']


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
    observables = [{"value": observable, "type": observable_type}]
    response_from_all_modules = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers})

    response_from_qualys_module = get_observables(
        response_from_all_modules, MODULE_NAME)

    assert response_from_qualys_module['module'] == MODULE_NAME
    assert response_from_qualys_module['module_instance_id']
    assert response_from_qualys_module['module_type_id']

    sightings = response_from_qualys_module['data']['sightings']
    assert len(sightings['docs']) > 0

    for sighting in sightings['docs']:
        assert sighting['description']
        assert sighting['schema_version']

        for relation in sighting['relations']:
            if relation['relation'] == 'Resolved_To':
                assert relation['related']['value'] == observable
                assert relation['related']['type'] == observable_type

        assert sighting['observables'] == observables
        assert sighting['observed_time']['start_time'] == (
            sighting['observed_time']['end_time'])
        assert sighting['id'].startswith('transient:sighting-')
        assert sighting['type'] == 'sighting'
        assert sighting['count'] == 1
        assert sighting['source'] == MODULE_NAME
        assert sighting['external_ids']
        assert sighting['confidence'] == CONFIDENCE
        assert sighting['severity'] in SEVERITY
        assert sighting['sensor'] == 'endpoint'
        assert sighting['data']
        assert 'external_references' in sighting

        for target in sighting['targets']:
            assert target['type'] == 'endpoint'
            assert target['observables']
            assert target['observed_time']['start_time'] == (
                target['observed_time']['end_time']
            )
            assert target['os']

    assert sightings['count'] == len(sightings['docs']) <= CTR_ENTITIES_LIMIT
