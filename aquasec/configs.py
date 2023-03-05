"""Configurations"""

import os

from aquasec.utilities import set_bool


class Config:  # pylint: disable=missing-class-docstring
    API_KEY = os.getenv("AQUA_API_KEY", "")
    API_SECRET = os.getenv("AQUA_API_SECRET", "")
    API_URL = "https://api.cloudsploit.com/v2"
    API_VERSION = os.getenv("AQUA_API_VERSION", 'v2')
    LOGNAME = os.getenv("AQUA_LOGNAME", "aquasec.log")
    LOGLOCATION = os.getenv("AQUA_LOGLOCATION", "")
    LOGSTREAM = set_bool(os.getenv("AQUA_LOGSTREAM", 'true'))
    LOGGING = os.getenv("AQUA_LOGGING", "INFO")
    SET_LOG = set_bool(os.getenv("AQUA_SET_LOG", "true"))
    ENCODING = "utf-8"
    CERT = set_bool(os.getenv("AQUA_CERT", 'true'))  # pylint: disable=invalid-name
