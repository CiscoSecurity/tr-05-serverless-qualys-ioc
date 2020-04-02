<!-- [![Travis CI Build Status](https://travis-ci.com/CiscoSecurity/tr-05-serverless-qualys-ioc.svg?branch=develop)](https://travis-ci.com/CiscoSecurity/tr-05-serverless-qualys-ioc) -->

# Qualys IOC Relay API

A sample Relay API implementation using the
Qualys IOC API
as an example of a third-party Threat Intelligence service provider.

The API itself is just a simple Flask (WSGI) application which can be easily
packaged and deployed as an AWS Lambda Function working behind an AWS API
Gateway proxy using [Zappa](https://github.com/Miserlou/Zappa).

An already deployed Relay API (e.g., packaged as an AWS Lambda Function) can
be pushed to Threat Response as a Relay Module using the
[Threat Response Relay CLI](https://github.com/threatgrid/tr-lambda-relay).

## Installation

```bash
pip install -U -r requirements.txt
```

## Testing

```bash
pip install -U -r test-requirements.txt
```

- Check for *PEP 8* compliance: `flake8 .`.
- Run the suite of unit tests: `pytest -v tests/unit/`.

## Deployment

```bash
pip install -U -r deploy-requirements.txt
```

As an AWS Lambda Function:
- Deploy: `zappa deploy dev`.
- Check: `zappa status dev`.
- Update: `zappa update dev`.
- Monitor: `zappa tail dev --http`.

As a TR Relay Module:
- Create: `relay add`.
- Update: `relay edit`.
- Delete: `relay remove`.

**Note.** For convenience, each TR Relay CLI command may be prefixed with
`env $(cat .env | xargs)` to automatically read the required environment
variables from a `.env` file (i.e.`TR_API_CLIENT_ID`, `TR_API_CLIENT_PASSWORD`,
`URL`, `JWT`) and pass them to the corresponding command.

## Usage

```bash
pip install -U -r use-requirements.txt
```

```bash
export URL=<...>
export JWT=<...>

http POST "${URL}"/health Authorization:"Bearer ${JWT}"
http POST "${URL}"/observe/observables Authorization:"Bearer ${JWT}" < observables.json
```

## Details

The Qualys IOC Relay API implements the following list of endpoints:
* `/observe/observables`,
* `/refer/observables`,
* `/health`.

Even though the API is still able to handle requests to other Relay API endpoints 
(i.e., `/deliberate/observables`, `/respond/observables` and `/respond/trigger`), 
it is programmed only to return empty responses.

The `/observe/observables` and `/refer/observables` endpoints only support observables of types listed below:
* `md5`,
* `sha256`,
* `file_name`,
* `file_path`,
* `ip`,
* `domain`,
* `mutex`.

Other types of observables will not be handled (though no error will be raised either), 
and observables of such types will simply be ignored.

When querying the `/observe/observables` endpoint, the API performs two requests per observable to the Qualys IOC API 
for events from `Active` and `Historical` states.
The difference between these events is that `Active` events are still present in the system, 
while `Historical` events are not. 
For example, if a connection is still established, an event related to this connection will be in the `Active` state, 
otherwise, it will be in the `Historical` state.

The `/observe/observables` endpoint returns lists of the following CTIM objects:
* [sightings](https://github.com/threatgrid/ctim/blob/master/doc/structures/sighting.md), 
* [judgements](https://github.com/threatgrid/ctim/blob/master/doc/structures/judgement.md), 
* [indicators](https://github.com/threatgrid/ctim/blob/master/doc/structures/indicator.md) and
* [relationships](https://github.com/threatgrid/ctim/blob/master/doc/structures/relationship.md) between them 
  (better described [here](https://github.com/threatgrid/ctim/blob/master/doc/defined_relationships.md)).

These objects are constructed from events returned by the Qualys IOC API.
The mapping between Qualys IOC events and CTIM objects can be found in the source code 
(see [observables.py](https://github.com/CiscoSecurity/tr-05-serverless-qualys-ioc/blob/develop/api/observables.py)).
