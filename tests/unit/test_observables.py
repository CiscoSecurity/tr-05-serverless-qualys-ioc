import json
from urllib.parse import quote

from api.observables import \
    Observable, MD5, SHA256, FileName, FilePath, IP, Domain, Mutex


def test_observable_of():
    assert isinstance(Observable.of('md5'), MD5)
    assert isinstance(Observable.of('sha256'), SHA256)
    assert isinstance(Observable.of('file_name'), FileName)
    assert isinstance(Observable.of('file_path'), FilePath)
    assert isinstance(Observable.of('ip'), IP)
    assert isinstance(Observable.of('domain'), Domain)
    assert isinstance(Observable.of('mutex'), Mutex)
    assert Observable.of('whatever') is None


def test_md5_refer():
    observable = MD5()
    url = observable.refer(api='', observable='deadbeef')

    assert url == (
        f'/ioc/#/hunting?search=' +
        quote('file.hash.md5: "deadbeef"')
    )


def test_sha256_refer():
    observable = SHA256()
    url = observable.refer(api='', observable='deadbeef')

    assert url == (
        f'/ioc/#/hunting?search=' +
        quote('file.hash.sha256: "deadbeef"')
    )


def test_file_name_refer():
    observable = FileName()
    url = observable.refer(api='', observable='danger.exe')

    assert url == (
        f'/ioc/#/hunting?search=' +
        quote('file.name: "danger.exe"')
    )


def test_file_path_refer():
    observable = FilePath()
    url = observable.refer(api='', observable='\\path\\to\\danger.exe')

    assert url == (
        f'/ioc/#/hunting?search=' +
        quote('file.fullPath: "\\path\\to\\danger.exe"')
    )


def test_ip_refer():
    observable = IP()
    url = observable.refer(api='', observable='1.2.3.4')

    assert url == (
        f'/ioc/#/hunting?search=' +
        quote(
            'network.local.address.ip: "1.2.3.4" or '
            'network.remote.address.ip: "1.2.3.4"'
        )
    )


def test_domain_refer():
    observable = Domain()
    url = observable.refer(api='', observable='danger.com')

    assert url == (
        f'/ioc/#/hunting?search=' +
        quote('network.remote.address.fqdn: "danger.com"')
    )


def test_mutex_refer():
    observable = Mutex()
    url = observable.refer(api='', observable='danger')

    assert url == (
        f'/ioc/#/hunting?search=' +
        quote('handle.name: "danger"')
    )


def test_map():
    with open('tests/unit/data/sha256.json') as file:
        data = json.loads(file.read())
        observable = Observable.of(data['observable']['type'])
        output = observable.map(data['observable']['value'],
                                data['input'],
                                active=True)

        assert output.keys() == data['output'].keys()

        for key in output.keys():
            assert key in data['output']
            assert len(output[key]) == len(data['output'][key])

            for a, b in zip(output[key], data['output'][key]):
                assert a.pop('id').startswith('transient:')

                if key == 'relationships':
                    assert a.pop('source_ref').startswith('transient:')
                    assert a.pop('target_ref').startswith('transient:')

                assert a == b
