"""Initialization"""

import hashlib
import hmac
from os.path import expanduser, exists
import time
from urllib.parse import urlparse

import yaml

from aquasec.auth import WorkloadAuth
from aquasec.configs import Config
from aquasec.logging import RotatingLog


config = Config()
home = expanduser("~")
filename = f"{home}/.config/.aquaconf"
# Prefer Yaml configs over OS ENV Settings
if exists(filename):
    with open(filename, 'r', encoding='utf-8') as yam:
        yaml_config = yaml.safe_load(yam)
    config.WORKLOAD_API_KEY = yaml_config.get('AQUA_WORKLOAD_API_KEY', config.WORKLOAD_API_KEY)
    config.WORKLOAD_API_SECRET = yaml_config.get(
        'AQUA_WORKLOAD_API_SECRET', config.WORKLOAD_API_SECRET)
    config.CSPM_API_KEY = yaml_config.get("AQUA_CSPM_API_KEY", config.CSPM_API_KEY)
    config.CSPM_API_SECRET = yaml_config.get("AQUA_CSPM_API_SECRET", config.CSPM_API_SECRET)
    config.API_VERSION = yaml_config.get("AQUA_API_VERSION", 'v2')
    config.CERT = yaml_config.get('AQUA_CERT', False)
    config.LOGGING = yaml_config.get("AQUA_LOGGING", "INFO")
    config.SET_LOG = yaml_config.get("AQUA_SET_LOG", True)
    config.LOGNAME = yaml_config.get("AQUA_LOGNAME", "aquasec.log")
    config.LOGSTREAM = yaml_config.get("AQUA_LOGSTREAM", True)
    config.LOGLOCATION = yaml_config.get("AQUA_LOGLOCATION", "")


def return_workload_auth(**kwargs) -> WorkloadAuth:
    """Return Workload Authorization

    Args:
        workload_auth (WorkloadAuth, Optional): If supplied Object is returned
        api_secret (str, Optional): Required if not set in configurations
        api_key (str, Optional): Required if no workload_auth or if not set in config
        verify (str|bool, Optional): Sets the verification for RestAPI call
        timeout (int, Optional): Sets the RestAPI timeout. Default 60s

    Returns:
        Object: Workload Authoriation Object that contains a timed token
    """
    workload_auth: WorkloadAuth = kwargs.pop('workload_auth', "")
    if not workload_auth:
        if (kwargs.get('api_key') and kwargs.get('api_secret')):
            # remove possible kwargs values
            workload_auth = WorkloadAuth(api_key=kwargs.pop('api_key'),
                                         api_secret=kwargs.pop('api_secret'),
                                         api_version=kwargs.pop('api_version', 'v2'),
                                         **kwargs)
        else:
            workload_auth = WorkloadAuth(config.WORKLOAD_API_KEY,
                                         config.WORKLOAD_API_SECRET,
                                         config.API_VERSION,
                                         verify=config.CERT,
                                         **kwargs)
    return workload_auth


def create_cspm_headers(url: str, method: str = "GET", payload: str = "", **kwargs) -> dict:
    """Create AquaSec Header

    Args:
        url (str): Requested URL.
        method (str, optional): RestAPI call type. Default: "GET".
        payload (str, optional): used to create the header signature. Defaults:"".
        api_secret (str, optional): API secret to override configurations
        api_key (str, optional): API Key that overrides the configurations

    Returns:
        dict: Headers used for CSMP Audit calls and for Workload Headers
    """
    # sets time for AquaSec to base the time limit of the token Expiration
    timestamp = str(int(time.time() * 1000))
    path = urlparse(url).path
    string = (timestamp + method + path + payload).replace(" ", "")
    secret_bytes = bytes(kwargs.pop('api_secret', config.CSPM_API_SECRET), config.ENCODING)
    string_bytes = bytes(string, config.ENCODING)
    sig = hmac.new(secret_bytes, msg=string_bytes, digestmod=hashlib.sha256).hexdigest()
    headers = {
        "accept": "application/json",
        "x-api-key": kwargs.pop('api_key', config.CSPM_API_KEY),
        "x-signature": sig,
        "x-timestamp": timestamp,
        "content-type": "application/json",
    }
    return headers


# Set logging if Logging set to True
logger = RotatingLog(name=__name__,
                     logName=config.LOGNAME,
                     logDir=config.LOGLOCATION,
                     stream=config.LOGSTREAM,  # type: ignore
                     level=config.LOGGING)
