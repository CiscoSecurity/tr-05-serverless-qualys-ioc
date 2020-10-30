import pytest
from ctrlibrary.threatresponse.enrich import enrich_observe_observables
from ctrlibrary.core.utils import get_observables
from tests.functional.tests.constants import (
    MODULE_NAME,
    CONFIDENCE,
    CTR_ENTITIES_LIMIT
)


@pytest.mark.parametrize(
    'observable,observable_type,disposition_name,disposition',
    (('701fb8ed9d1f72c901e207dd01b481266be8458f6e03750c1a139c901f2995fa',
     'sha256', 'Unknown', 5),
     ('a23-38-112-137.deploy.static.akamaitechnologies.com', 'domain', 'Clean',
     1),
     ('23.38.112.137', 'ip', 'Clean', 1),
     ('MSFTHISTORY!', 'mutex', 'Clean', 1),
     (r'C:\Users\User01\Downloads\Malware', 'file_path', 'Malicious', 2),
     ('buzus.exe', 'file_name', 'Malicious', 2),
     ('415e5cc23e106483711abe70ad78c8e2', 'md5', 'Unknown', 5))
)
def test_positive_enrich_observe_observables_judgements(
        module_headers, observable, observable_type, disposition_name,
        disposition):
    """Perform testing for enrich observe observables endpoint to get
    judgements for observable Qualys module

    ID: CCTRI-797-9ce334d2-74bc-4c3a-bb8a-181f260076f0

    Steps:
        1. Send request to enrich observe observable endpoint

    Expectedresults:
        1. Check that data in response body contains expected judgements for
            observable from Qualys module

    Importance: Critical
    """
    observables = [{"value": observable, "type": observable_type}]
    response_from_all_modules = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )

    response_from_qualys_ioc = get_observables(response_from_all_modules,
                                               'Qualys IOC')

    assert response_from_qualys_ioc['module']
    assert response_from_qualys_ioc['module_instance_id']
    assert response_from_qualys_ioc['module_type_id']

    judgements = response_from_qualys_ioc['data']['judgements']
    assert len(judgements['docs']) > 0

    for judgement in judgements['docs']:
        assert 'valid_time' in judgement
        assert judgement['schema_version']
        assert judgement['observable'] == observables[0]
        assert judgement['type'] == 'judgement'
        assert judgement['source'] == MODULE_NAME
        assert judgement['external_ids']
        assert judgement['disposition'] == disposition
        assert 'external_references' in judgement
        assert 'reason' in judgement
        assert judgement['disposition_name'] == disposition_name
        assert judgement['priority'] == 90
        assert judgement['id'].startswith('transient:judgement-')
        assert judgement['severity']
        assert judgement['confidence'] == CONFIDENCE

    assert judgements['count'] == len(judgements['docs']) <= CTR_ENTITIES_LIMIT
