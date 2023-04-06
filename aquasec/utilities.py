"""Utilities"""

from pathlib import Path

from aquasec.auth import WorkloadAuth, refresh_workload_token


def set_bool(value: str, default=False):
    """sets bool value when pulling string from os env

    Args:
        value (str|bool, Required): the value to evaluate
        default (bool): default return bool value. Default False

    Returns:
        (str|bool): String if certificate path is passed otherwise True|False
    """
    value_bool = default
    if isinstance(value, bool):
        value_bool = value
    elif str(value).lower() == 'true':
        value_bool = True
    elif str(value).lower() == 'false':
        value_bool = False
    elif isinstance(value, str):
        if Path.exists(Path(value)):
            value_bool = value
    return value_bool


def reformat_exception(error: Exception) -> str:
    """Reformates Exception to print out as a string pass for logging

    Args:
        error (Exception): _description_

    Returns:
        str: _description_
    """
    return f"{type(error).__name__}: {str(error)}" if error else ""


class UrlUtils:
    @staticmethod
    @refresh_workload_token
    def create_workload_url(workload_auth: WorkloadAuth,
                            workload_url: str,
                            url_path: str,
                            api_version: str) -> str:
        """_summary_

        Args:
            workload_auth (WorkloadAuth): _description_
            workload_url (str): _description_
            url_path (str): _description_
            api_version (str): _description_

        Returns:
            str: _description_
        """
        url = workload_url.format(workload_auth.aqua_url, api_version, url_path)
        return url
