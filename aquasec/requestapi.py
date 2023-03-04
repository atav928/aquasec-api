"""Request API"""
from typing import Any, Dict
import requests

from aquasec import config, logger
from aquasec.auth import WorkloadAuth, refresh_workload_token, create_headers

logger.addLogger(__name__)
aquasec_logger = logger.getLogger(__name__)
if not config.SET_LOG:
    aquasec_logger.disabled = True


@refresh_workload_token
def aqua_workload_request(token: WorkloadAuth, **kwargs) -> Dict[str, Any]:  # pylint: disable=too-many-locals
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
        name (string, Optional): The name of the entry
        potition (str, Optional|Required): Required if inspecting Security Rules
        get_object (str, Optional): Used if method is "GET", but additional path parameters required
    Returns:
        _type_: _description_
    """
    #TODO: Fix
    response = requests.request(method=method,
                                url=url,
                                headers=headers,
                                data=data,
                                params=params,
                                verify=verify,
                                timeout=timeout)
    response.raise_for_status()
    return response.json()

def aqua_cloudsploit_request(url: str, method: str, **kwargs) -> Dict[str,Any]:
    """_summary_

    Args:
        url (str): _description_
        method (str): _description_

    Returns:
        Dict[str,Any]: _description_
    """
    payload = kwargs.pop("payload") if kwargs.get("payload") else ""
    headers = create_headers(url=url, method=method, payload=payload)
    response = requests.request(method=method,
                                url=url,
                                headers=headers,
                                timeout=60,
                                verify=True)
    response.raise_for_status()
    return response.json()
