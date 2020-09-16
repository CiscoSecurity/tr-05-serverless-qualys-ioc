import pytest
from ctrlibrary.threatresponse.enrich import enrich_observe_observables
from ctrlibrary.core.utils import get_observables
from tests.functional.tests.constants import (
    MODULE_NAME,
    CTR_ENTITIES_LIMIT
)


@pytest.mark.parametrize(
    'observable, observable_type',
    (('a23-38-112-137.deploy.static.akamaitechnologies.com', 'domain'),
     ('23.38.112.137', 'ip'),
     ('701fb8ed9d1f72c901e207dd01b481266be8458f6e03750c1a139c901f2995fa',
      'sha256'),
     ('415e5cc23e106483711abe70ad78c8e2', 'md5'),
     ('MSFTHISTORY!', 'mutex'),
     (r'C:\Users\User01\Downloads\Malware', 'file_path'),
     ('buzus.exe', 'file_name'))
)
def test_positive_enrich_observe_observables_relationships(
        module_headers, observable, observable_type):
    """ Perform testing for enrich observe observables endpoint to get
    relationships for observable Qualys module

    ID: CCTRI-798-bcb33509-c153-4436-93c3-7345e7704b9d

    Steps:
        1. Send request to enrich observe observable endpoint

    Expectedresults:
        1. Check that data in response body contains expected information
            in relationships from Qualys module

    Importance: Critical
    """
    observables = [{"value": observable, "type": observable_type}]
    response_from_all_modules = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers})['data']
    response_from_qualys_ioc = get_observables(
        response_from_all_modules, MODULE_NAME)

    assert response_from_qualys_ioc['module'] == MODULE_NAME
    assert response_from_qualys_ioc['module_instance_id']
    assert response_from_qualys_ioc['module_type_id']

    relationships = response_from_qualys_ioc['data']['relationships']
    sightings = response_from_qualys_ioc['data']['sightings']
    indicators = response_from_qualys_ioc['data']['indicators']
    judgements = response_from_qualys_ioc['data']['judgements']

    indicators_ids = frozenset(
        indicator['id'] for indicator in indicators['docs'])
    judgements_ids = frozenset(
        judgement['id'] for judgement in judgements['docs'])
    sightings_ids = frozenset(
        sighting['id'] for sighting in sightings['docs'])

    assert len(relationships['docs']) > 0

    for relationship in relationships['docs']:
        assert relationship['schema_version']
        assert relationship['type'] == 'relationship'
        assert relationship['source'] == MODULE_NAME
        assert relationship['id'].startswith('transient:relationship-')
        assert 'external_ids' in relationship
        assert 'source_uri' in relationship

        if relationship['relationship_type'] == 'based-on':
            if relationship['target_ref'].startswith('transient:indicator-'):
                assert relationship['target_ref'] in indicators_ids
                assert relationship['source_ref'] in judgements_ids
            elif relationship['target_ref'].startswith('transient:judgement-'):
                assert relationship['target_ref'] in judgements_ids
                assert relationship['source_ref'] in sightings_ids

        elif relationship['relationship_type'] == 'sighting-of':
            assert relationship['target_ref'] in indicators_ids
            assert relationship['source_ref'] in sightings_ids
        else:
            raise AssertionError('Unsupported relationship type')

    assert relationships['count'] == len(relationships['docs']) <= (
        CTR_ENTITIES_LIMIT)
