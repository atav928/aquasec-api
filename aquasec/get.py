"""Get Method"""

from aquasec import config, logger

from aquasec.auth import refresh_workload_token, WorkloadAuth
from aquasec.requestapi import aqua_cloudsploit_request, aqua_workload_request

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

    def alerts(self) -> dict:
        """Gets Alerts

        Returns:
            dict: _description_
        """
        url = self._parent_class.cloudsploit_url.format(  # type:ignore
            self._parent_class.api_version, self._parent_class.endpoint_alerts)  # type:ignore
        response = aqua_cloudsploit_request(url=url, method=self.method)
        return response

    def check_license(self):
        """Check license

        Returns:
            _type_: _description_
        """
        url = Get._create_workload_url(self._parent_class.workload_auth, # type: ignore
                                       self._parent_class.workload_url, "license") # type:ignore
        response = aqua_workload_request(
            self._parent_class.workload_auth, url=url, method=self.method) # type: ignore
        aquasec_logger.info("")
        return response

    @staticmethod
    @refresh_workload_token
    def _create_workload_url(workload_auth: WorkloadAuth, workload_url: str, endpoint: str) -> str:
        url = workload_url.format(workload_auth.aqua_url, workload_auth.api_version, endpoint)
        aquasec_logger.debug("Created url %s", url)
        return url
