import pytest

from ctrlibrary.threatresponse.enrich import enrich_observe_observables
from ctrlibrary.core.utils import get_observables

SCHEMA_VERSION = '1.0.16'


@pytest.mark.parametrize(
    'observable,observable_type,disposition_name,disposition',
    (('701fb8ed9d1f72c901e207dd01b481266be8458f6e03750c1a139c901f2995fa',
     'sha256', 'Unknown', 5),
     ('a23-38-112-137.deploy.static.akamaitechnologies.com', 'domain', 'Clean',
     1),
     ('23.38.112.137', 'ip', 'Clean', 1),
     ('MSFTHISTORY!', 'mutex', 'Clean', 1),
     (r'C:\Users\User01\Downloads\Malware', 'file_path', 'Malicious', 2),
     ('buzus.exe', 'file_name', 'Malicious', 2))
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
    expected_observable = {
        'schema_version': SCHEMA_VERSION,
        'disposition': disposition,
        'disposition_name': disposition_name,
        'source': 'Qualys IOC',
        'type': 'judgement'
    }

    # Get judgement
    observables = [{"value": observable, "type": observable_type}]
    response = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )['data']
    direct_observables = get_observables(response, 'Qualys IOC')

    # Check respond data
    judgement = direct_observables['data']['judgements']['docs'][0]

    for key in expected_observable.keys():
        assert expected_observable[key] == judgement[key]

    assert 'valid_time' in judgement
    assert 'external_ids' in judgement
    assert 'external_references' in judgement
    assert 'reason' in judgement
    assert 'priority' in judgement
    assert 'id' in judgement
    assert 'severity' in judgement
    assert 'confidence' in judgement


def test_positive_enrich_observe_observables_detail_judgements(module_headers):
    """ Perform testing for enrich observe observables endpoint for detail
    respond in Qualys module(judgements) with details respond

    ID: CCTRI-797-88669278-2ad6-4c9f-86c1-2d0b51180e5b

    Steps:
        1. Send request with observable that has md5 type to observe
            observables endpoint

    Expectedresults:
        1. Check that data in response body contains expected information
            in judgements from Qualys module

    Importance: Critical
    """
    observable = '415e5cc23e106483711abe70ad78c8e2'
    observable_type = 'md5'

    expected_observable = {
        'schema_version': SCHEMA_VERSION,
        'severity': 'Medium',
        'source': 'Qualys IOC',
        'type': 'judgement',
        'external_ids': (
            ['F_5b49017b-90dd-4a6d-92ea-7651bafdc1ec_-8729057863409581450']),
        'valid_time': {},
        'disposition': 5,
        'disposition_name': 'Unknown',
        'external_references': [],
        'confidence': 'High',
        'priority': 90
    }

    # Get judgement
    observables = [{"value": observable, "type": observable_type}]
    response = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )['data']
    direct_observables = get_observables(response, 'Qualys IOC')

    # Check respond data
    judgement = direct_observables['data']['judgements']['docs'][0]

    assert judgement['observable'] == observables[0]

    for key in expected_observable.keys():
        assert expected_observable[key] == judgement[key]
