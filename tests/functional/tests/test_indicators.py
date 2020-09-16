import pytest
from ctrlibrary.threatresponse.enrich import enrich_observe_observables
from ctrlibrary.core.utils import get_observables
from tests.functional.tests.constants import (
    MODULE_NAME,
    CTR_ENTITIES_LIMIT,
    SEVERITY,
    CONFIDENCE
)


@pytest.mark.parametrize(
    'observable,observable_type',
    (('701fb8ed9d1f72c901e207dd01b481266be8458f6e03750c1a139c901f2995fa',
      'sha256'),
     ('a23-38-112-137.deploy.static.akamaitechnologies.com', 'domain'),
     ('127.0.0.1', 'ip'),
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
    observables = [{"value": observable, "type": observable_type}]
    response_from_all_modules = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )['data']
    response_from_qualys_ioc = get_observables(response_from_all_modules,
                                               MODULE_NAME)

    assert response_from_qualys_ioc['module']
    assert response_from_qualys_ioc['module_instance_id']
    assert response_from_qualys_ioc['module_type_id']

    indicators = response_from_qualys_ioc['data']['indicators']
    assert len(indicators['docs']) > 0

    for indicator in indicators['docs']:
        assert indicator['id'].startswith('transient:indicator-')
        assert 'valid_time' in indicator
        assert indicator['producer'] == MODULE_NAME
        assert indicator['schema_version']
        assert indicator['type'] == 'indicator'
        assert indicator['source'] == MODULE_NAME
        assert indicator['severity'] in SEVERITY
        assert indicator['confidence'] == CONFIDENCE
        assert indicator['external_ids']

    assert indicators['count'] == len(indicators['docs']) <= CTR_ENTITIES_LIMIT
