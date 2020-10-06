import pytest
from ctrlibrary.threatresponse.enrich import enrich_observe_observables
from ctrlibrary.core.utils import get_observables
from tests.functional.tests.constants import MODULE_NAME


@pytest.mark.parametrize(
    'observable, observable_type',
    (('test.org', 'domain'),
     ('4.3.1.4', 'ip'),
     ('824916EE370035D2FCED9D4D216D6EA45E5F3866590130C1FA5FDA652F952529',
      'sha256'),
     ('d41d8cd98f00b204e9800998ecf8427r', 'md5'),
     ('WininetStartMutex', 'mutex'),
     (r'C:\Users\Users\Downloads\Malware', 'file_path'),
     ('test.exe', 'file_name'))
)
def test_positive_smoke_empty_observables(
        module_headers, observable, observable_type):
    """Perform testing for enrich observe observables endpoint to check that
     observable, on which Qualys doesn't have information, will
     return empty data

    ID: CCTRI-1707-2af2e5ec-d6bd-4a9b-83c1-5cb78786f145

    Steps:
        1. Send request to enrich observe observables endpoint

    Expectedresults:
        1. Response body contains empty data dict from Qualys module

    Importance: Critical
    """
    observables = [{"value": observable, "type": observable_type}, ]
    response_from_all_modules = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )

    qualys_data = response_from_all_modules['data']

    response_from_qualys_module = get_observables(qualys_data, MODULE_NAME)

    assert response_from_qualys_module['module'] == MODULE_NAME
    assert response_from_qualys_module['module_instance_id']
    assert response_from_qualys_module['module_type_id']

    assert response_from_qualys_module['data'] == {}
