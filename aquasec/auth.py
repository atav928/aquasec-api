"""Auth"""

import hashlib
import hmac
import json
import time
from typing import List
from urllib.parse import urlparse
import jwt

import requests
from requests import Response

from aquasec.exceptions import AquaSecAPIError, AquaSecPermission


ENCODING = "utf-8"


class WorkloadAuth:
    """Workload Token Authorization with expiration time

    Returns:
        _type_: _description_
    """
    TOKEN_URL = "https://api.cloudsploit.com/{}/tokens"
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
    # csp_roles: list = []
    tenant: str = ''
    # cwpp_header
    headers: dict = {}

    def __init__(self, api_key: str, api_secret: str, api_version: str = 'v2', **kwargs):
        self.api_version: str = api_version
        self.TOKEN_URL: str = self.TOKEN_URL.format(self.api_version)
        self.api_key: str = api_key
        self._api_secret: str = api_secret
        self.allowed_endpoints: list = kwargs.pop("allowed_endpoints", ["ANY"])
        self.csp_roles: list = kwargs.pop("csp_roles", ["api_auditor"])
        self.payload: str = self._create_payload(allowed_endpoints=self.allowed_endpoints,
                                                 csp_roles=self.csp_roles)
        self.verify = kwargs.pop('verify', True)
        self.timeout: int = kwargs.pop('timeout', 60)
        self.token = self.gen_token()

    def gen_token(self) -> str:
        """Generates Token

        Returns:
            str: _description_
        """
        headers = self.create_headers()
        response = requests.request(method="POST",
                                    url=self.TOKEN_URL,
                                    data=self.payload,
                                    headers=headers,
                                    timeout=self.timeout,
                                    verify=self.verify)
        # ERROR: 'status': 403, 'id': 'a0cd8f1d-a617-4997-886f-00f8ea99dbf5',
        #  'code': 1, 'message': 'Access denied',
        #  'errors': ['The request is missing the session token. Please login.']}
        self.api_raise_error(response=response)
        response.raise_for_status()
        token = response.json()["data"]
        self._decode_aqua_token(token=token)
        self._cwpp_headers(token=token)
        return token

    def _create_payload(self,
                        allowed_endpoints: List[str],
                        csp_roles: List[str]) -> str:
        return json.dumps({"validity": 240,
                           "allowed_endpoints": allowed_endpoints,
                           "csp_roles": csp_roles})

    def _decode_aqua_token(self, token: str) -> None:
        """Decodes token and returns the Aqua Tenant URL Endpoint

        Args:
            token (_type_): _description_

        Returns:
            str: <tenant>.cloud.aquqsec.com
        """
        #### Decode JWT Token for URL ###
        decoded_parse = jwt.decode(token, options={"verify_signature": False})
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

    def _cwpp_headers(self, token: str) -> None:
        self.headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}"
        }

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
        # print(f"{path=}")
        string = (timestamp + self.method + path + self.payload).replace(" ", "")
        # print(f"{string=}")
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
        # print(f"headers={json.dumps(headers,indent=2)}")
        return headers

    def api_raise_error(self, response: Response) -> None:
        """Raises error if response not what was expected

        Args:
            response (Response): _description_

        Raises:
            AquaSecPermission: _description_
            AquaSecAPIError: _description_
        """
        if response.status_code == 403:
            message = response.json().get("message", "Permission Denied")
            raise AquaSecPermission(message)
        if not (response.status_code >= 200 or response.status_code < 299):
            raise AquaSecAPIError(response.json())


def refresh_workload_token(decorated):
    """refreshes token"""
    def wrapper(workload_auth: WorkloadAuth, *args, **kwargs):
        if time.time() > workload_auth.access_token_expiration:
            # regenerate token and reset timmer
            workload_auth.gen_token()
        # send back just token from auth class
        return decorated(workload_auth, *args, **kwargs)
    return wrapper
