"""Auth"""

import hashlib
import hmac
import json
import time
from urllib.parse import urlparse
import jwt

import requests

ENCODING = "utf-8"

class WorkloadAuth:
    """Workload Token Authorization with expiration time

    Returns:
        _type_: _description_
    """
    TOKEN_URL = "https://api.cloudsploit.com/{}/tokens"
    PAYLOAD: str = json.dumps({"validity": 240, "allowed_endpoints": [
        "ANY"], "csp_roles": ["api_auditor"]})
    method: str = "POST"
    # Decoded Token Data
    account_id: int = 0
    aqua_user_id: str = ""
    account_admin: bool = False
    user_groups_user: list = []
    user_groups_admin: list = []
    access_token_expiration: int = 0
    audit: bool = False
    allowed_endpoints: list = []
    csp_enabled: bool = False
    csp_metadata: dict = {}
    aqua_url: str = ""
    aqua_gw_url: str = ""
    csp_roles: list = []
    tenant: str = ''

    def __init__(self, api_key: str, api_secret: str, api_version: str = 'v2', **kwargs):
        self.api_version = api_version
        self.TOKEN_URL = self.TOKEN_URL.format(self.api_version)
        self.api_key = api_key
        self._api_secret = api_secret
        self.token = self.gen_token()

    def gen_token(self) -> str:
        """Generates Token

        Returns:
            str: _description_
        """
        # TODO: remove legacy auth requirements build my own header pass allong
        headers = self.create_headers()
        request = requests.request(method="POST", url=self.TOKEN_URL,
                                   data=self.PAYLOAD, headers=headers, timeout=60)
        # ERROR: 'status': 403, 'id': 'a0cd8f1d-a617-4997-886f-00f8ea99dbf5', 'code': 1, 'message': 'Access denied', 'errors': ['The request is missing the session token. Please login.']}
        request.raise_for_status()
        # TODO: Raise Exception
        token = request.json()["data"]
        # TODO: remove all print
        print(f"{token=}")
        self._decode_aqua_token(token=token)
        # TODO: Fix return value should actually gen token
        return token

    def _decode_aqua_token(self, token: str) -> None:
        """Decodes token and returns the Aqua Tenant URL Endpoint

        Args:
            token (_type_): _description_

        Returns:
            str: <tenant>.cloud.aquqsec.com
        """
        #### Decode JWT Token for URL ###
        decoded_parse = jwt.decode(token, options={"verify_signature": False})
        # decoded_parse = jwt.decode(token, config._API_SECRET, algorithms=["HS256"])
        print(f"{decoded_parse=}")
        self.aqua_user_id = decoded_parse['user_id']
        self.account_id = decoded_parse['account_id']
        self.account_admin = decoded_parse['account_admin']
        self.user_groups_admin = decoded_parse['user_groups_admin']
        self.user_groups_user = decoded_parse['user_groups_user']
        self.access_token_expiration = decoded_parse['exp']
        self.audit = decoded_parse['audit']
        self.allowed_endpoints = decoded_parse['allowed_endpoints']
        self.csp_enabled = decoded_parse['csp_enabled']
        self.csp_metadata = decoded_parse['csp_metadata']
        self.aqua_url = f'https://{decoded_parse["csp_metadata"]["urls"]["ese_url"]}'
        self.aqua_gw_url = f'https://{decoded_parse["csp_metadata"]["urls"]["ese_gw_url"]}'
        self.csp_roles = decoded_parse['csp_roles']
        self.tenant = decoded_parse["csp_metadata"]["urls"]["ese_url"].split('.')[0]
    
    def create_headers(self) -> dict:
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
        path = urlparse(self.TOKEN_URL).path
        print(f"{path=}")
        string = (timestamp + self.method + path + self.PAYLOAD).replace(" ", "")
        print(f"{string=}")
        secret_bytes = bytes(self._api_secret, ENCODING)
        string_bytes = bytes(string, ENCODING)
        sig = hmac.new(secret_bytes, msg=string_bytes, digestmod=hashlib.sha256).hexdigest()
        headers = {
            "accept": "application/json",
            "x-api-key": self.api_key,
            "x-signature": sig,
            "x-timestamp": timestamp,
            "content-type": "application/json",
        }
        print(f"headers={json.dumps(headers,indent=2)}")
        return headers

def refresh_workload_token(decorated):
    """refreshes token"""
    def wrapper(token: WorkloadAuth, *args, **kwargs):
        if time.time() > token.access_token_expiration:
            # regenerate token and reset timmer
            token.gen_token()
        # send back just token from auth class
        return decorated(token.token, *args, **kwargs)
    return wrapper
