[![Gitter Chat](https://img.shields.io/badge/gitter-join%20chat-brightgreen.svg)](https://gitter.im/CiscoSecurity/Threat-Response "Gitter Chat")

# Qualys IOC Relay (Cisco Hosted)

Concrete Relay implementation using
[Qualys IOC](https://www.qualys.com/apps/indication-of-compromise/)
as a third-party Cyber Threat Intelligence service provider.

The Relay itself is just a simple application written in Python that can be
easily packaged and deployed. This relay is now Cisco Hosted and no longer requires AWS Lambda.

## Rationale

- We need an application that will translate API requests from SecureX Threat Response to the third-party integration, and vice versa.
- We need an application that can be completely self contained within a virtualized container using Docker.

## Testing (Optional)

Open the code folder in your terminal.
```
cd code
```

If you want to test the application you have to install a couple of extra
dependencies from the [test-requirements.txt](test-requirements.txt) file:
```
pip install --upgrade --requirement requirements.txt
```

You can perform two kinds of testing:

- Run static code analysis checking for any semantic discrepancies and
[PEP 8](https://www.python.org/dev/peps/pep-0008/) compliance:

  `flake8 .`

- Run the suite of unit tests and measure the code coverage:

  `coverage run --source api/ -m pytest --verbose tests/unit/ && coverage report`

If you want to test the live Lambda you may use any HTTP client (e.g. Postman),
just make sure to send requests to your Lambda's `URL` with the `Authorization`
header set to `Bearer <JWT>`.

### Building the Docker Container
In order to build the application, we need to use a `Dockerfile`.  

 1. Open a terminal.  Build the container image using the `docker build` command.

```
docker build -t tr-05-qualys-ioc .
```

 2. Once the container is built, and an image is successfully created, start your container using the `docker run` command and specify the name of the image we have just created.  By default, the container will listen for HTTP requests using port 9090.

```
docker run -dp 9090:9090 --name tr-05-qualys-ioc tr-05-qualys-ioc
```

 3. Watch the container logs to ensure it starts correctly.

```
docker logs tr-05-qualys-ioc
```

 4. Once the container has started correctly, open your web browser to http://localhost:9090.  You should see a response from the container.

```
curl http://localhost:9090
```

## Implementation Details

### Implemented Relay Endpoints

- `POST /health`
  - Verifies the Authorization Bearer JWT and decodes it to restore the
  original credentials.
  - Authenticates to the underlying external service to check that the provided
  credentials are valid and the service is available at the moment.

- `POST /observe/observables`
  - Accepts a list of observables and filters out unsupported ones.
  - Verifies the Authorization Bearer JWT and decodes it to restore the
  original credentials.
  - Makes a series of requests to the underlying external service to query for
  some cyber threat intelligence data on each supported observable.
  - Maps the fetched data into appropriate CTIM entities.
  - Returns a list per each of the following CTIM entities (if any extracted):
    - `Sighting`,
    - `Indicator`,
    - `Judgement`,
    - `Relationship`.

- `POST /refer/observables`
  - Accepts a list of observables and filters out unsupported ones.
  - Builds a search link per each supported observable to pivot back to the
  underlying external service and look up the observable there.
  - Returns a list of those links.
  
- `POST /version`
  - Returns the current version of the application.
  
### Supported Types of Observables

- `ip`
- `domain`
- `file_name`
- `file_path`
- `mutex`
- `md5`
- `sha256`

### CTIM Mapping Specifics

Each Qualys IOC event produces a single `Sighting`, a single `Indicator`, a list of `Judgements` (may be empty)
and the corresponding `Relations` between them.

#### `Sighting`

The mapping between an event and a `Sighting` is straightforward, but there are a few details that should be mentioned:

- `targets` of a `Sighting` contain a single `target` with the following `target.observables`:
  - `asset.netBiosName` as `hostname`;
  - `asset.interfaces[].ipAddress` as `ip`;
  - `asset.interfaces[].macAddress` as `mac_address`.

- `severity` of a `Sighting` is mapped from `score` of an event:

  | Score | Description                       | Severity |
  |-------|-----------------------------------|----------|
  | 0     | Known Good [File/Process/Network] | None     |
  | 1     | Remediated [File/Process/Network] | High     |
  | 2     | Suspicious Low File event         | Low      |
  | 3     | Suspicious Low Process event      | Low      |
  | 4     | Suspicious Low Network event      | Low      |
  | 5     | Suspicious Medium File event      | Medium   |
  | 6     | Suspicious Medium Process event   | Medium   |
  | 7     | Suspicious Medium Network event   | Medium   |
  | 8     | Malicious File event              | High     |
  | 9     | Malicious Process event           | High     |
  | 10    | Malicious Network event           | High     |
  
- `data` of a `Sighting` contains information on whether the event is in the active (or current) state or not.
  For example, `data` will contain `Active: True` if an event that a `Sighting` is mapped from is in the active state,
  and `Active: False` otherwise.

#### `Indicator`

The mapping between an event and an `Indicator` is even simpler.
The only thing to keep in mind is:

- `severity` of an `Indicator` is mapped from `score` of an event in the same way as for a `Sighting`.

#### `Judgement`

Each entry in the `indicator2` list of an event is mapped to a single `Judgement`.
The mapping is defined as follows:

- `disposition` of a `Judgement` is mapped from `indicator2[].verdict` as follows:

  | Verdict    | Disposition | Disposition Name |
  |------------|-------------|------------------|
  | KNOWN      | 1           | Clean            |
  | UNKNOWN    | 5           | Unknown          |
  | SUSPICIOUS | 3           | Suspicious       |
  | MALICIOUS  | 2           | Malicious        |
  | REMEDIATED | 2           | Malicious        |

- `reason` of a `Judgement` is mapped from `indicator2[].threatName`.

- `severity` of a `Judgement` is mapped from `score` of an event in the same way as for a `Sighting`.

#### `Relationship`

`Relationships` between `Sighting`, `Indicator` and `Judgements` are defined as follows:

| Source       | Relation    | Target       |
|--------------|-------------|--------------|
| `Judgements` | based-on    | `Indicator`  |
| `Sighting`   | based-on    | `Judgements` |
| `Sighting`   | sighting-of | `Indicator`  |
