"""s"""
from urllib.parse import urlparse
import json
import ssl
import hmac
import hashlib
import time
import requests
from requests.utils import DEFAULT_CA_BUNDLE_PATH
import jwt
from aquasec import config

def headers(url: str, method: str = "GET", payload: str = "") -> dict:
    timestamp = str(int(time.time() * 1000))
    path = urlparse(url).path
    print(f"{path=}")
    string = (timestamp + method + path + payload).replace(" ", "")
    print(f"{string=}")
    secret_bytes = bytes(config._API_SECRET, "utf-8")
    string_bytes = bytes(string, "utf-8")
    sig = hmac.new(secret_bytes, msg=string_bytes, digestmod=hashlib.sha256).hexdigest()
    header = {
        "accept": "application/json",
        "x-api-key": config.API_KEY,
        "x-signature": sig,
        "x-timestamp": timestamp,
        "content-type": "application/json",
    }
    print(f"headers={json.dumps(header,indent=2)}")
    return header


def cwpp_headers(token: str) -> dict:
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}"
    }
    return headers
 
def scan_headers(token: str = "") -> dict:
    headers = {
        "Authorization": f"Bear {token}"
    }
    return headers

def gen_token():
    #aqssl._create_default_https_context = ssl._create_unverified_context
    url = f"{config.API_URL}/tokens"
    method = 'POST'
    payload = json.dumps({"validity": 240, "allowed_endpoints": [
                         "ANY"], "csp_roles": ["api_auditor"]})
    print(f"{payload=}")
    # TODO: remove legacy auth requirements build my own header pass allong
    request = requests.request(method="POST", url=url,data=payload, headers=headers(url, method, payload), timeout=60)
    response_body = json.loads(request.text)
    token = response_body["data"]
    # TODO: remove all print
    print(f"{response_body=}")
    print(f"{token=}")
    # TODO: Fix return value should actually gen token
    return token


def get_aqua_url(token: str) -> str:
    """Decodes token and returns the Aqua Tenant URL Endpoint

    Args:
        token (_type_): _description_

    Returns:
        str: <tenant>.cloud.aquqsec.com
    """
    #### Decode JWT Token for URL ###
    decoded_parse = jwt.decode(token, options={"verify_signature": False})
    print(f"{decoded_parse=}")
    aqua_url = decoded_parse["csp_metadata"]["urls"]["ese_url"]
    print(f"{aqua_url=}")
    return aqua_url

def check_license():
    """Verifies license
    """
    api_endpoint = f'api/{config.API_VERSION}/license'
    token = gen_token()
    aqua_url = "https://" + get_aqua_url(token)
    print(f"{aqua_url=}")
    endpoint_url = f"{aqua_url}/{api_endpoint}"
    print(f"{endpoint_url=}")

    # TODO: figure out what cwpp headers is for
    request = requests.get(endpoint_url, headers=cwpp_headers(token), timeout=60)
    request_response = json.loads(request.text)
    license = json.dumps(request_response, indent=4, sort_keys=True)
    print(f"{license=}")
    return license


# TODO: Based off initial session token and timmer create a decorator auth class to handle this
if __name__ == '__main__':
    check_license()
