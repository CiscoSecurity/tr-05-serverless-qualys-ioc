import os
import json

from uuid import NAMESPACE_X500


class Config:
    settings = json.load(open('container_settings.json', 'r'))
    VERSION = settings["VERSION"]

    SECRET_KEY = os.urandom(12).hex()

    API_URL_DEFAULT = ''
    PLATFORM_URL_DEFAULT = ''
    CTR_ENTITIES_LIMIT_DEFAULT = 100

    NAMESPACE_BASE = NAMESPACE_X500
