"""Get Method"""

from aquasec import config, logger

from aquasec.auth import refresh_workload_token, WorkloadAuth
from aquasec.requestapi import (aqua_cloudsploit_request, aqua_workload_request, retrieve_full_list)
from aquasec.utilities import reformat_exception

logger.addLogger(__name__)
aquasec_logger = logger.getLogger(__name__)
if not config.SET_LOG:
    aquasec_logger.disabled = True


class Get:
    """Get Class for Aquasec CSPM and Workload Protection
    """
    _parent_class = None
    method: str = "GET"

    all_hosts: list = []

    def cspm(self, url_path: str, **kwargs):
        """Creates CSPM endpoint. Pass any paremters required to complete the Request.

        Args:
            url_path (str, required): The URL resource path. Ex "alerts"
            params (dict, optional): RestAPI parameters
            api_version (str, optional): Defaults to configured version

        Returns:
            dict: JSON results
        """
        api_version: str = kwargs.pop("api_verison", self._parent_class.api_version)  # type: ignore
        url = self._parent_class.cloudsploit_url.format(  # type:ignore
            api_version,
            url_path)
        aquasec_logger.info("Created URL=%s", url)
        response = aqua_cloudsploit_request(url=url, method=self.method, **kwargs)
        aquasec_logger.debug("Response=%s", response)
        return response

    def workload_protection(self, url_path: str, **kwargs):
        """Workload Protection Requests, see README.md for some assistance here.
            this is difficult to get as there is no documentation and most is pulled
            from the cloud portal. But there are some examples to help on readme.

        Args:
            url_path (str): The URL Resource path. Ex: "risks/bench/{id}/bench_results"
            api_version (str, optional): Overrides the version set in the configuration
            params (dict, Optional): required params for request see README for examples

        Returns:
            dict: JSON results
        """
        try:
            api_version: str = kwargs.pop(
                'api_version', self._parent_class.workload_auth.api_version)  # type:ignore
            get_all: bool = kwargs.pop('get_all', False)
        except KeyError as err:
            error = reformat_exception(err)
            aquasec_logger.error("AquaSecMissingParam: %s", error)
        url = Get._create_workload_url(self._parent_class.workload_auth,  # type: ignore
                                       self._parent_class.workload_url,  # type:ignore
                                       url_path=url_path,
                                       api_version=api_version)  # type: ignore
        aquasec_logger.info("Created Workload URL=%s", url)
        if not get_all:
            response = aqua_workload_request(self._parent_class.workload_auth,  # type: ignore
                                             url=url,
                                             method=self.method,
                                             **kwargs)
        else:
            response = retrieve_full_list(self._parent_class.workload_auth,  # type: ignore
                                          url=url,
                                          method=self.method,
                                          **kwargs)
        aquasec_logger.info("Retrieved Inforomation from Workload Protection")
        return response

    def _endpoint(self, url_path: str, **kwargs) -> str:
        """Creates endpoint for Cloudsploit

        Args:
            endpoint (str): _description_

        Returns:
            str: _description_
        """
        api_version: str = kwargs.pop(
            'api_version', self._parent_class.api_version)  # type: ignore # type :ignore
        url = self._parent_class.cloudsploit_url.format(api_version, url_path)  # type: ignore
        return url

    @staticmethod
    @refresh_workload_token
    def _create_workload_url(
            workload_auth: WorkloadAuth, workload_url: str, url_path: str, api_version: str) -> str:
        url = workload_url.format(workload_auth.aqua_url, api_version, url_path)
        aquasec_logger.debug("Created url %s", url)
        return url
