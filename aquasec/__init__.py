"""Initialization"""

import hashlib
import hmac
import json
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
    config.API_KEY = yaml_config['AQUA_API_KEY']
    config.API_SECRET = yaml_config['AQUA_API_SECRET']
    config.API_VERSION = yaml_config.get("AQUA_API_VERSION", 'v2')
    config.CERT = yaml_config.get('CERT', False)
    config.LOGGING = yaml_config.get("AQUA_LOGGING", "INFO")
    config.SET_LOG = yaml_config.get("AQUA_SET_LOG", True)
    config.LOGNAME = yaml_config.get("AQUA_LOGNAME", "aquasec.log")
    config.LOGSTREAM = yaml_config.get("AQUA_LOGSTREAM", True)
    config.LOGLOCATION = yaml_config.get("AQUA_LOGLOCATION", "")


def return_auth(**kwargs) -> WorkloadAuth:
    """_summary_

    Returns:
        Auth: _description_
    """
    workload_auth = kwargs.pop('workload_auth') if kwargs.get('workload_auth') else ""
    if not workload_auth:
        if (kwargs.get('api_key') and kwargs.get('api_secret')):
            workload_auth = WorkloadAuth(kwargs['api_key'],
                                         kwargs['api_secret'],
                                         kwargs.get('api_version', 'v2'),
                                         **kwargs)
        else:
            workload_auth = WorkloadAuth(config.API_KEY,
                                         config.API_SECRET,
                                         config.API_VERSION,
                                         verify=config.CERT)
    return workload_auth


def create_headers(url: str, method: str = "GET", payload: str = "", **kwargs) -> dict:
    """Create AquaSec Header

    Args:
        url (str): _description_
        method (str, optional): _description_. Defaults to "GET".
        payload (str, optional): _description_. Defaults to "".
        api_secret (str, optional)
        api_key (str, optional):

    Returns:
        dict: _description_
    """
    # sets time for AquaSec to base the time limit of the token Expiration
    timestamp = str(int(time.time() * 1000))
    path = urlparse(url).path
    print(f"{path=}")
    string = (timestamp + method + path + payload).replace(" ", "")
    print(f"{string=}")
    secret_bytes = bytes(kwargs['api_secret'], config.ENCODING) if kwargs.get(
        'api_secret') else bytes(config.API_SECRET, config.ENCODING)
    string_bytes = bytes(string, config.ENCODING)
    sig = hmac.new(secret_bytes, msg=string_bytes, digestmod=hashlib.sha256).hexdigest()
    headers = {
        "accept": "application/json",
        "x-api-key": kwargs['api_key'] if kwargs.get('api_key') else config.API_KEY,
        "x-signature": sig,
        "x-timestamp": timestamp,
        "content-type": "application/json",
    }
    print(f"headers={json.dumps(headers,indent=2)}")
    return headers


# Set logging if Logging set to True
logger = RotatingLog(name=__name__,
                     logName=config.LOGNAME,
                     logDir=config.LOGLOCATION,
                     stream=config.LOGSTREAM,  # type: ignore
                     level=config.LOGGING)
