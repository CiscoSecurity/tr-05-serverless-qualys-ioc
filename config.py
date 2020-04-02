import os


class Config:
    API_URL = os.environ.get('API_URL', '')
    PLATFORM_URL = os.environ.get('PLATFORM_URL', '')

    SECRET_KEY = os.environ.get('SECRET_KEY', '')
