import os
from typing import Any


def positive_int(value: Any, default: int) -> int:
    """Parses positive integers."""

    try:
        value = int(value)
    except (ValueError, TypeError):
        return default

    return value if value > 0 else default


class Config:
    API_URL = os.environ.get('API_URL', '')
    PLATFORM_URL = os.environ.get('PLATFORM_URL', '')

    SECRET_KEY = os.environ.get('SECRET_KEY', '')

    CTR_ENTITIES_LIMIT = \
        positive_int(os.environ.get('CTR_ENTITIES_LIMIT'),
                     default=100)
