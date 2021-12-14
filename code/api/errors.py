from http import HTTPStatus

INVALID_ARGUMENT = 'invalid argument'
UNKNOWN = 'unknown'
AUTH_ERROR = 'authorization error'
PERMISSION_DENIED = 'permission denied'
TOO_MANY_REQUESTS = 'too many requests'
UNAUTHORIZED = 'unauthorized'
NOT_FOUND = 'not found'
UNAVAILABLE = 'service unavailable'
CONNECTION_ERROR = 'connection error'


class TRFormattedError(Exception):
    def __init__(self, code, message, type_='fatal'):
        super().__init__()
        self.code = code or UNKNOWN
        self.message = message or 'Something went wrong.'
        self.type_ = type_

    @property
    def json(self):
        return {'type': self.type_,
                'code': self.code,
                'message': self.message}


class QualysSSLError(TRFormattedError):
    def __init__(self, error):
        error = error.args[0].reason.args[0]
        message = getattr(error, 'verify_message', error.args[0]).capitalize()
        super().__init__(
            UNKNOWN,
            f'Unable to verify SSL certificate: {message}'
        )


class QualysConnectionError(TRFormattedError):
    def __init__(self, url):
        super().__init__(
            CONNECTION_ERROR,
            f'Unable to connect Microsoft Qualys Security,'
            f' validate the configured API URL: {url}'
        )


class AuthorizationError(TRFormattedError):
    def __init__(self, message):
        super().__init__(
            AUTH_ERROR,
            f'Authorization failed: {message}'
        )


class InvalidArgumentError(TRFormattedError):
    def __init__(self, error):
        super().__init__(
            INVALID_ARGUMENT,
            str(error)
        )


class CriticalResponseError(TRFormattedError):
    def __init__(self, response):
        message = response.text

        def get_auth_failed_json():
            response_json = response.json()
            return (response_json.get('message')
                    or response_json.get('authentication_exceptions')
                    or response.text)

        details_map = {
            HTTPStatus.TOO_MANY_REQUESTS: lambda: {
                'code': TOO_MANY_REQUESTS,
                'message': 'Too many requests to Qualys IOC '
                           'have been made. Please try again later.'
            },
            HTTPStatus.UNAUTHORIZED: lambda: {
                'code': AUTH_ERROR,
                'message': f'Authorization failed: {get_auth_failed_json()}'
            },
            HTTPStatus.SERVICE_UNAVAILABLE: lambda: {
                'code': UNAVAILABLE,
                'message': 'Service temporarily unavailable. '
                           'Please try again later.'
            },
            HTTPStatus.BAD_REQUEST: lambda: {'code': INVALID_ARGUMENT},
            HTTPStatus.FORBIDDEN: lambda: {'code': PERMISSION_DENIED},
            HTTPStatus.NOT_FOUND: lambda: {'code': NOT_FOUND},
            HTTPStatus.INTERNAL_SERVER_ERROR: lambda: {'code': UNKNOWN},
        }

        details = details_map.get(response.status_code, {})()

        super().__init__(
            details.get('code', UNKNOWN),
            details.get('message',
                        f'Unexpected response from Qualys IOC: {message}')
        )


class WatchdogError(TRFormattedError):
    def __init__(self):
        super().__init__(
            code='health check failed',
            message='Invalid Health Check'
        )
