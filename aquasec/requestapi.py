"""Request API"""
from typing import Any, Dict
import requests
from requests import Response

from aquasec import config, logger, create_headers
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
    except KeyError as err:
        error = reformat_exception(err)
        aquasec_logger.error("AquaSecMissingParam: %s", error)
        raise AquaSecMissingParam(error)  # pylint: disable=raise-missing-from
    response = requests.request(method=method,
                                url=url,
                                headers=workload_auth.headers,
                                # data=data,
                                # params=params,
                                verify=verify,
                                timeout=timeout)
    aquasec_logger.debug("Response Code: %s| Full Response: %s",
                         str(response.status_code), response.text)
    api_raise_error(response=response)
    return response.json()


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
    headers = create_headers(url=url, method=method, payload=payload)
    verify = kwargs.pop('verify', True)
    timeout: int = kwargs.pop('timeout', 60)
    response = requests.request(method=method,
                                url=url,
                                headers=headers,
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
    if not (response.status_code >= 200 or response.status_code < 299):
        aquasec_logger.error("Status Code: %s| Error: %s", str(
            response.status_code), response.json())
        raise AquaSecAPIError(response.json())
