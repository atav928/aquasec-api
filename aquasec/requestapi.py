"""Request API"""
import json
from typing import Any, Dict
import requests
from requests import Response

from aquasec import config, logger, create_cspm_headers
from aquasec.auth import WorkloadAuth, refresh_workload_token
from aquasec.exceptions import (AquaSecAPIError, AquaSecMissingParam, AquaSecPermission)
from aquasec.utilities import reformat_exception

logger.addLogger(__name__)
aquasec_logger = logger.getLogger(__name__)
if not config.SET_LOG:
    aquasec_logger.disabled = True


@refresh_workload_token
def aqua_workload_request(workload_auth: WorkloadAuth, **kwargs) -> Dict[str, Any]:  # pylint: disable=too-many-locals
    """_summary_

    Args:
        token (Auth): Auth class that is used to refresh bearer token upon expiration.
        url_type (str): specify the api call
        method (str): specifies the type of HTTPS method used
        params (dict, optional): specifies parameters passed to request
        data (str, optional): specifies the data being sent
        verify (str|bool, optional): sets request to verify with a custom
         cert bypass verification or verify with standard library. Defaults to True
        timeout (int, optional): sets API call timeout. Defaults to 60
        delete_object (str, required|optional): Required if method is DELETE
        put_object (str, required|optional): Required if method is PUT
        limit (int, Optional): The maximum number of results
        offset (int, Optional): The offset of the result entry
        get_object (str, Optional): Used if method is "GET", but additional path parameters required
    Returns:
        _type_: _description_
    """
    try:
        method: str = kwargs.pop('method')
        url: str = kwargs.pop('url')
        timeout: int = kwargs.pop('timeout', 60)
        verify = kwargs.pop('verify', config.CERT)
        params: dict = kwargs.pop('params', {})
        data: dict = kwargs.pop('data', None)
    except KeyError as err:
        error = reformat_exception(err)
        aquasec_logger.error("AquaSecMissingParam: %s", error)
        raise AquaSecMissingParam(error)  # pylint: disable=raise-missing-from
    if data:
        data = json.dumps(data)
    response = requests.request(method=method,
                                url=url,
                                headers=workload_auth.headers,
                                data=data,
                                params=params,
                                verify=verify,
                                timeout=timeout)
    aquasec_logger.debug("Response Code=%s|Full Response=%s",
                         str(response.status_code), response.text.rstrip())
    api_raise_error(response=response)
    if response.status_code == 204:
        json_response = {"message": "Data Created", "code": response.status_code}
    else:
        json_response = response.json()
    return json_response


def retrieve_full_list(workload_auth: WorkloadAuth, **kwargs):
    """Retrieves fulll list of requirements based on multiple calls

    Args:
        workload_auth (WorkloadAuth): _description_
        url (str): url to call
        method (str): Requests Type

    Raises:
        AquaSecPermission: Missing Parameter

    Returns:
        dict: response dictionary
    """
    params: dict = {
        "page": 1,
        "pagesize": 1000
    }
    try:
        url: str = kwargs.pop('url')
        method: str = kwargs.pop('method')
    except KeyError as err:
        error = reformat_exception(err)
        aquasec_logger.error("AquaSecPermission: %s", error)
        raise AquaSecPermission(error)  # pylint: disable=raise-missing-from
    response = {
        "result": [],
        "page": 0,
        "pagesize": 0,
        "count": 0
    }
    result: list = []
    iterations: int = 0
    while (len(result) <= response["count"] or iterations == 0):
        try:
            response = aqua_workload_request(workload_auth=workload_auth,
                                             url=url,
                                             method=method,
                                             params=params,
                                             **kwargs)
            if response['result']:
                result = result + response['result']
                aquasec_logger.debug("result_length=%s|result_count=%s",
                                     str(len(result)), str(response["count"]))
            if not response['result']:
                break
            params = {**params, **{"page": params["page"] + 1}}
            iterations += 1
        except Exception as err:  # pylint: disable=broad-exception-caught
            error = reformat_exception(err)
            aquasec_logger.error("Unable to get %s data error=%s", url, error)
            return {"error": error}
    response['result'] = result
    return response


def aqua_cloudsploit_request(url: str, method: str, **kwargs) -> Dict[str, Any]:
    """_summary_

    Args:
        url (str): _description_
        method (str): _description_
        verify (str|bool): Location of specific cert or bool. Default: True
        timeout (int): timeout for request. Default: 60s

    Returns:
        Dict[str,Any]: _description_
    """
    payload = kwargs.pop("payload") if kwargs.get("payload") else ""
    headers = create_cspm_headers(url=url, method=method, payload=payload)
    verify = kwargs.pop('verify', config.CERT)
    timeout: int = kwargs.pop('timeout', 60)
    params: dict = kwargs.pop('params', {})
    response = requests.request(method=method,
                                url=url,
                                headers=headers,
                                params=params,
                                timeout=timeout,
                                verify=verify)
    aquasec_logger.debug("Response Code: %s| Full Response: %s",
                         str(response.status_code), response.text)
    api_raise_error(response=response)
    return response.json()


def api_raise_error(response: Response) -> None:
    """Raises error if response not what was expected

    Args:
        response (Response): _description_

    Raises:
        AquaSecPermission: _description_
        AquaSecAPIError: _description_
    """
    if response.status_code == 403:
        message = response.json().get("message", "Permission Denied")
        aquasec_logger.error("AquaSecPermission: %s", message)
        raise AquaSecPermission(message)
    if not (response.status_code >= 200 and response.status_code < 299):
        aquasec_logger.error("Status Code: %s| Error: %s", str(
            response.status_code), response.json())
        raise AquaSecAPIError(response.json())


Traceback (most recent call last):
  File "/.env/lib/python3.8/site-packages/requests/models.py", line 971, in json
    return complexjson.loads(self.text, **kwargs)
  File "/Users/adamt/.pyenv/versions/3.8.15/lib/python3.8/json/__init__.py", line 357, in loads
    return _default_decoder.decode(s)
  File "/Users/adamt/.pyenv/versions/3.8.15/lib/python3.8/json/decoder.py", line 337, in decode
    obj, end = self.raw_decode(s, idx=_w(s, 0).end())
  File "/Users/adamt/.pyenv/versions/3.8.15/lib/python3.8/json/decoder.py", line 355, in raw_decode
    raise JSONDecodeError("Expecting value", s, err.value) from None
json.decoder.JSONDecodeError: Expecting value: line 1 column 1 (char 0)

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "test_call.py", line 41, in <module>
    print(response.json())
  File "/.env/lib/python3.8/site-packages/requests/models.py", line 975, in json
    raise RequestsJSONDecodeError(e.msg, e.doc, e.pos)
requests.exceptions.JSONDecodeError: Expecting value: line 1 column 1 (char 0)
