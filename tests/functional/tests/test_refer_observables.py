

def test_positive_relay_refer_observables_domain(relay_api):
    """ Test relay refer observables api mock for domain in Qualys

    ID: CCTRI-744-5a17cb01-7470-4ac8-9552-1f52eb4db2c8

    Steps:
        1. Send request with domain type to endpoint refer observables

    Expectedresults:
        1. Check data in body respond

    Importance: Critical
    """
    observable = 'ceres.alastyr.com'
    observable_type = 'domain'

    expected_observable = {
        'description': 'Check this domain status with Qualys',
        'id': 'ref-qualys-search-domain-ceres.alastyr.com',
        'title': 'Search for this domain',
        'url': (
            'https://qualysguard.qg3.apps.qualys.com'
            '/ioc/#/hunting?search=network.remote.address.fqdn%3A%20%22ceres.'
            'alastyr.com%22')
    }

    # Get sightings
    observables = [{"value": observable, "type": observable_type}]
    sighting = relay_api.refer_observables(
        payload=observables).json()['data'][0]

    # Check respond data
    assert sighting['categories'] == ['Search', 'Qualys']

    for key in expected_observable.keys():
        assert expected_observable[key] == sighting[key]


def test_positive_relay_refer_observables_md5(relay_api):
    """ Test relay refer observables api mock for md5 in Qualys

    ID: CCTRI-744-82ba703c-ac7c-4025-bfe1-7bac29ae0e86

    Steps:
        1. Send request with md5 type to endpoint refer observables

    Expectedresults:
        1. Check data in body respond

    Importance: Critical
    """
    observable = '415e5cc23e106483711abe70ad78c8e2'
    observable_type = 'md5'

    expected_observable = {
        'description': 'Check this MD5 status with Qualys',
        'id': 'ref-qualys-search-md5-415e5cc23e106483711abe70ad78c8e2',
        'title': 'Search for this MD5',
        'url': (
            'https://qualysguard.qg3.apps.qualys.com'
            '/ioc/#/hunting?search=file.hash.'
            'md5%3A%20%22415e5cc23e106483711abe70ad78c8e2%22')
    }

    # Get sightings
    observables = [{"value": observable, "type": observable_type}]
    sighting = relay_api.refer_observables(
        payload=observables).json()['data'][0]

    # Check respond data
    assert sighting['categories'] == ['Search', 'Qualys']

    for key in expected_observable.keys():
        assert expected_observable[key] == sighting[key]


def test_positive_relay_refer_observables_sha256(relay_api):
    """ Test relay refer observables api mock for sha256 in Qualys

    ID: CCTRI-744-d291b2f5-ecc1-4f10-bdfa-7086b71e1f11

    Steps:
        1. Send request with sha256 type to endpoint refer observables

    Expectedresults:
        1. Check data in body respond

    Importance: Critical
    """
    observable = (
        '31b2fd20f0f5cdf922009558d592514cfaa6c1fca1570a0f3c06df755613e024')
    observable_type = 'sha256'

    expected_observable = {
        'description': 'Check this SHA256 status with Qualys',
        'id': (
            'ref-qualys-search-sha256-31b2fd20f0f5cdf922009558d592514'
            'cfaa6c1fca1570a0f3c06df755613e024'),
        'title': 'Search for this SHA256',
        'url': (
            'https://qualysguard.qg3.apps.qualys.com'
            '/ioc/#/hunting?search=file.hash.sha256%3A%20%2231b2fd20f0f5'
            'cdf922009558d592514cfaa6c1fca1570a0f3c06df755613e024%22')
    }

    # Get sightings
    observables = [{"value": observable, "type": observable_type}]
    sighting = relay_api.refer_observables(
        payload=observables).json()['data'][0]

    # Check respond data
    assert sighting['categories'] == ['Search', 'Qualys']

    for key in expected_observable.keys():
        assert expected_observable[key] == sighting[key]


def test_positive_relay_refer_observables_file_name(relay_api):
    """ Test relay refer observables api mock for file_name in Qualys

    ID: CCTRI-744-6114ff9d-e97f-47ae-ab41-6508eec000d6

    Steps:
        1. Send request with file_name type to endpoint refer observables

    Expectedresults:
        1. Check data in body respond

    Importance: Critical
    """
    observable = 'buzus.exe'
    observable_type = 'file_name'

    expected_observable = {
        'description': 'Check this file name status with Qualys',
        'id': 'ref-qualys-search-file_name-buzus.exe',
        'title': 'Search for this file name',
        'url': 'https://qualysguard.qg3.apps.qualys.com'
               '/ioc/#/hunting?search=file.name%3A%20%22buzus.exe%22'
    }

    # Get sightings
    observables = [{"value": observable, "type": observable_type}]
    sighting = relay_api.refer_observables(
        payload=observables).json()['data'][0]

    # Check respond data
    assert sighting['categories'] == ['Search', 'Qualys']

    for key in expected_observable.keys():
        assert expected_observable[key] == sighting[key]


def test_positive_relay_refer_observables_ip(relay_api):
    """ Test relay refer observables api mock for ip in Qualys

    ID: CCTRI-744-6114ff9d-e97f-47ae-ab41-6508eec000d6

    Steps:
        1. Send request with ip type to endpoint refer observables

    Expectedresults:
        1. Check data in body respond

    Importance: Critical
    """
    observable = '213.128.83.163'
    observable_type = 'ip'

    expected_observable = {
        'description': 'Check this IP status with Qualys',
        'id': 'ref-qualys-search-ip-213.128.83.163',
        'title': 'Search for this IP',
        'url': ('https://qualysguard.qg3.apps.qualys.com'
                '/ioc/#/hunting?search=network.local.address.ip%3A%20%22213.'
                '128.83.163%22%20or%20network.remote.address.ip%3A%20%22213.'
                '128.83.163%22')
    }

    # Get sightings
    observables = [{"value": observable, "type": observable_type}]
    sighting = relay_api.refer_observables(
        payload=observables).json()['data'][0]

    # Check respond data
    assert sighting['categories'] == ['Search', 'Qualys']

    for key in expected_observable.keys():
        assert expected_observable[key] == sighting[key]
