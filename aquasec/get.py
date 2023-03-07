"""Get Method"""

from aquasec import config, logger

from aquasec.auth import refresh_workload_token, WorkloadAuth
from aquasec.requestapi import aqua_cloudsploit_request, aqua_workload_request
from aquasec.utilities import reformat_exception

logger.addLogger(__name__)
aquasec_logger = logger.getLogger(__name__)
if not config.SET_LOG:
    aquasec_logger.disabled = True


class Get:
    """Get Class for Aquasec

    Returns:
        _type_: _description_
    """
    _parent_class = None
    method: str = "GET"

    def cspm(self, url_path: str, **kwargs):
        """_summary_

        Returns:
            _type_: _description_
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
        """Workload Protection Requests

        Args:
            endpoint (str): _description_

        Returns:
            _type_: _description_
        """
        try:
            api_version: str = kwargs.pop(
                'api_version', self._parent_class.workload_auth.api_version)  # type:ignore
        except KeyError as err:
            error = reformat_exception(err)
            aquasec_logger.error("AquaSecMissingParam: %s", error)
        url = Get._create_workload_url(self._parent_class.workload_auth,  # type: ignore
                                       self._parent_class.workload_url,  # type:ignore
                                       url_path=url_path,
                                       api_version=api_version)  # type: ignore
        aquasec_logger.info("Created Workload URL=%s", url)
        response = aqua_workload_request(self._parent_class.workload_auth,  # type: ignore
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
        api_version: str = kwargs.pop('api_version', self._parent_class.api_version)  # type :ignore
        url = self._parent_class.cloudsploit_url.format(api_version, url_path)  # type: ignore
        return url

    @staticmethod
    @refresh_workload_token
    def _create_workload_url(
            workload_auth: WorkloadAuth, workload_url: str, url_path: str, api_version: str) -> str:
        url = workload_url.format(workload_auth.aqua_url, api_version, url_path)
        aquasec_logger.debug("Created url %s", url)
        return url
