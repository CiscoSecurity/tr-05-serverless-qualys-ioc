from abc import ABCMeta, abstractmethod
from collections import defaultdict
from itertools import chain
from typing import Optional, Dict, Any, Iterable, List
from urllib.parse import quote
from uuid import uuid4, uuid5

from flask import current_app

from . import client


class Observable(metaclass=ABCMeta):
    """Represents an observable."""

    SCHEMA = '1.0.17'

    @staticmethod
    def of(type_: str) -> Optional['Observable']:
        """Returns an instance of `Observable` for the specified type."""

        for cls in Observable.__subclasses__():
            if cls.type() == type_:
                return cls()

        return None

    @staticmethod
    @abstractmethod
    def type() -> str:
        """Returns the observable type."""

    @staticmethod
    @abstractmethod
    def name() -> str:
        """Returns the name of the observable type.

        The name must be suitable to be used in sentences like "Search for this
        {name}". For example, an observable of type 'md5' should have a name
        'MD5', 'file_path' should have a name 'file path', etc.
        """

    @abstractmethod
    def filter(self, observable: str) -> str:
        """Returns a filter to search for the provided observable."""

    def observe(self, observable: str, limit: int, creds: dict) \
            -> Dict[str, Any]:
        """Retrieves objects (sightings, verdicts, etc.) for an observable."""

        data = defaultdict(list)

        def truncate(name, objects):
            return objects[:limit - len(data.get(name, []))]

        for active in [True, False]:
            amount = limit - len(data.get('sightings', []))
            events = client.events(active, amount, creds,
                                   quote(self.filter(observable)))

            # Map received events to CTIM objects
            # and append them to the result.
            for event in events:
                sightings = [self._sighting(event, observable, active)]
                sightings = truncate('sightings', sightings)

                if event.get('score') is not None:
                    indicators = [self._indicator(event)]
                    indicators = truncate('indicators', indicators)
                else:
                    indicators = []

                judgements = self._judgements(event, observable)
                judgements = truncate('judgements', judgements)

                relationships = list(chain(
                    self._relationships(judgements, 'based-on', indicators),
                    self._relationships(sightings, 'based-on', judgements),
                    self._relationships(sightings, 'sighting-of', indicators),
                ))

                data['sightings'].extend(sightings)
                data['indicators'].extend(indicators)
                data['judgements'].extend(judgements)
                data['relationships'].extend(relationships)

        return data

    def refer(self, api: str, observable: str) -> str:
        """Returns a URL for pivoting back to Qualys."""
        return f'{api}/ioc/#/hunting?search={quote(self.filter(observable))}'

    @classmethod
    def _sighting(cls, event: Dict[str, Any], observable: str, active: bool) \
            -> Dict[str, Any]:
        """Constructs a single CTIM sighting from a Qualys IOC event."""

        return clean({
            'id': f'transient:sighting-{uuid4()}',
            'confidence': 'High',
            'count': 1,
            'external_ids': [
                get(event, '.id')
            ],
            'external_references': [],
            'observables': [
                {
                    'type': cls.type(),
                    'value': observable
                }
            ],
            'observed_time': {
                'start_time': get(event, '.dateTime'),
                'end_time': get(event, '.dateTime')
            },
            'relations': list(relations(event)),
            'schema_version': cls.SCHEMA,
            'severity': severity(event),
            'sensor': 'endpoint',
            'source': 'Qualys IOC',
            'targets': [
                {
                    'observables': list(targets(event)),
                    'observed_time': {
                        'start_time': get(event, '.dateTime'),
                        'end_time': get(event, '.dateTime')
                    },
                    'type': 'endpoint',
                    'os': get(event, '.asset.fullOSName')
                }
            ],
            'type': 'sighting',
            'description': f'A Qualys IOC event related to "{observable}"',
            'data': {
                'columns': [{'name': 'Active', 'type': 'string'}],
                'rows': [[str(active)]],
                'row_count': 1
            },
        })

    @staticmethod
    def get_transient_id(entity_type, base_value=None):
        uuid = (uuid5(current_app.config['NAMESPACE_BASE'], base_value)
                if base_value else uuid4())
        return f'transient:{entity_type}-{uuid}'

    @staticmethod
    def get_title(score: str) -> str:
        titles = {
            '0': 'Known Good',
            '1': 'Remediated',
            '2': 'Suspicious Low File event',
            '3': 'Suspicious Low Process event',
            '4': 'Suspicious Low Network event',
            '5': 'Suspicious Medium File event',
            '6': 'Suspicious Medium Process event',
            '7': 'Suspicious Medium Network event',
            '8': 'Malicious File event',
            '9': 'Malicious Process event',
            '10': 'Malicious Network event'
        }
        return titles[score]

    @classmethod
    def _indicator(cls, event: Dict[str, Any]) \
            -> Dict[str, Any]:
        """Constructs a single CTIM indicator from a Qualys IOC event."""

        return clean({
            'title': cls.get_title(event['score']),
            'id': cls.get_transient_id('indicator', event['id']),
            'type': 'indicator',
            'schema_version': cls.SCHEMA,
            'source': 'Qualys IOC',
            'producer': 'Qualys IOC',
            'severity': severity(event),
            'valid_time': {},
            'external_ids': [
                get(event, '.id')
            ],
            'confidence': 'High',
        })

    @classmethod
    def _judgements(cls, event: Dict[str, Any], observable: str) \
            -> List[Dict[str, Any]]:
        """Constructs CTIM judgements from a Qualys IOC event."""

        dispositions = {
            'Clean': 1,
            'Malicious': 2,
            'Suspicious': 3,
            'Common': 4,
            'Unknown': 5,
        }
        disposition_names = {
            'KNOWN': 'Clean',
            'UNKNOWN': 'Unknown',
            'SUSPICIOUS': 'Suspicious',
            'MALICIOUS': 'Malicious',
            'REMEDIATED': 'Malicious',
        }

        judgements = []

        for indicator2 in get(event, '.indicator2') or []:
            verdict = indicator2.get('verdict')

            disposition_name = disposition_names.get(verdict) or 'Unknown'
            disposition = dispositions[disposition_name]

            judgement = clean({
                'id': f'transient:judgement-{uuid4()}',
                'confidence': 'High',
                'disposition': disposition,
                'disposition_name': disposition_name,
                'external_ids': [
                    get(event, '.id')
                ],
                'external_references': [],
                'observable': {
                    'type': cls.type(),
                    'value': observable
                },
                'priority': 90,
                'reason': indicator2.get('threatName', ''),
                'schema_version': cls.SCHEMA,
                'severity': severity(event),
                'source': 'Qualys IOC',
                'type': 'judgement',
                'valid_time': {}
            })
            judgements.append(judgement)

        return judgements

    @classmethod
    def _relationships(cls,
                       sources_: Iterable[Dict[str, Any]],
                       type_: str,
                       targets_: Iterable[Dict[str, Any]]) \
            -> List[Dict[str, Any]]:
        """Constructs CTIM relationships between source and target objects."""

        relationships = []

        for source in sources_:
            for target in targets_:
                relationship = clean({
                    'id': f'transient:relationship-{uuid4()}',
                    'type': 'relationship',
                    'schema_version': cls.SCHEMA,
                    'source': 'Qualys IOC',
                    'source_uri': '',
                    'source_ref': source['id'],
                    'target_ref': target['id'],
                    'relationship_type': type_,
                    'external_ids': []
                })
                relationships.append(relationship)

        return relationships


class MD5(Observable):

    @staticmethod
    def type() -> str:
        return 'md5'

    @staticmethod
    def name() -> str:
        return 'MD5'

    def filter(self, observable: str) -> str:
        return f'file.hash.md5: "{observable}"'


class SHA256(Observable):

    @staticmethod
    def type() -> str:
        return 'sha256'

    @staticmethod
    def name() -> str:
        return 'SHA256'

    def filter(self, observable: str) -> str:
        return f'file.hash.sha256: "{observable}"'


class FileName(Observable):

    @staticmethod
    def type() -> str:
        return 'file_name'

    @staticmethod
    def name() -> str:
        return 'file name'

    def filter(self, observable: str) -> str:
        return f'file.name: "{observable}"'


class FilePath(Observable):

    @staticmethod
    def type() -> str:
        return 'file_path'

    @staticmethod
    def name() -> str:
        return 'file path'

    def filter(self, observable: str) -> str:
        return f'file.fullPath: "{observable}"'


class IP(Observable):

    @staticmethod
    def type() -> str:
        return 'ip'

    @staticmethod
    def name() -> str:
        return 'IP'

    def filter(self, observable: str) -> str:
        return (f'network.local.address.ip: "{observable}" or '
                f'network.remote.address.ip: "{observable}"')


class Domain(Observable):

    @staticmethod
    def type() -> str:
        return 'domain'

    @staticmethod
    def name() -> str:
        return 'domain'

    def filter(self, observable: str) -> str:
        return f'network.remote.address.fqdn: "{observable}"'


class Mutex(Observable):

    @staticmethod
    def type() -> str:
        return 'mutex'

    @staticmethod
    def name() -> str:
        return 'mutex'

    def filter(self, observable: str) -> str:
        return f'handle.name: "{observable}"'


def get(event: Dict[str, Any], path: str, default: Any = None) -> Any:
    """Returns a value by the specified path if such exists or default."""

    result = event
    parts = iter(path.split('.'))

    # Skip the first entry.
    # It is always empty due to the leading period.
    next(parts)

    for part in parts:
        if part in result:
            result = result[part]
        else:
            return default

    return result


def clean(data: Any) -> Any:
    """Recursively cleans a `dict` or a `list` from 'None' values."""

    if isinstance(data, list):
        return [x for x in map(clean, data) if x is not None]

    if isinstance(data, dict):
        result = {key: clean(value) for key, value in data.items()}
        result = {key: value for key, value in result.items()
                  if value is not None}

        return result

    return data


def relations(event: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    """Constructs relations based on the provided event."""

    def mapped(relations_):
        for source, relation, target in relations_:
            source_type, source_path = source
            target_type, target_path = target

            source_value = get(event, source_path)
            target_value = get(event, target_path)

            if source_value and target_value:
                yield {
                    "origin": 'Qualys IOC',
                    "related": {
                        "type": target_type,
                        "value": target_value
                    },
                    "relation": relation,
                    "source": {
                        "type": source_type,
                        "value": source_value
                    }
                }

    return mapped([
        # Relations from `.file`.
        (['file_name', '.file.fileName'], 'File_Name_Of',
         ['sha256',    '.file.sha256']),
        (['file_name', '.file.fileName'], 'File_Name_Of',
         ['md5',       '.file.md5']),
        (['file_path', '.file.fullPath'], 'File_Path_Of',
         ['sha256',    '.file.sha256']),
        (['file_path', '.file.fullPath'], 'File_Path_Of',
         ['md5',       '.file.md5']),

        # Relations from `.process`.
        (['file_name', '.process.processName'], 'Connected_To',
         ['ip',        '.network.remoteIP']),
        (['file_name', '.process.processName'], 'Connected_To',
         ['domain',    '.network.remoteDns']),

        # Relations from `.network`.
        (['ip',     '.network.remoteIP'], 'Resolved_To',
         ['domain', '.network.remoteDns']),
    ])


def targets(event: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    """Constructs targets based on the provided event."""

    if event['asset'].get('netBiosName'):
        yield {'type': 'hostname', 'value': event['asset']['netBiosName']}

    for interface in event['asset'].get('interfaces') or []:
        if interface.get('ipAddress'):
            yield {'type': 'ip', 'value': interface['ipAddress']}
        if interface.get('macAddress'):
            yield {'type': 'mac_address', 'value': interface['macAddress']}


def severity(event: Dict[str, Any]) -> str:
    """Maps `score` of a Qualys event to `severity`.

    Possible `score` values:
         0 = Known Good [File/Process/Network]
         1 = Remediated [File/Process/Network]
         2 = Suspicious Low File event
         3 = Suspicious Low Process event
         4 = Suspicious Low Network event
         5 = Suspicious Medium File event
         6 = Suspicious Medium Process event
         7 = Suspicious Medium Network event
         8 = Malicious File event
         9 = Malicious Process event
        10 = Malicious Network event
    """

    if 'score' not in event:
        return 'Unknown'

    scores = {
        '0': 'None',
        '1': 'High',
        '2': 'Low',
        '3': 'Low',
        '4': 'Low',
        '5': 'Medium',
        '6': 'Medium',
        '7': 'Medium',
        '8': 'High',
        '9': 'High',
        '10': 'High'
    }

    score = event['score']

    return scores.get(score, 'Unknown')
