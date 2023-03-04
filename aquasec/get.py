"""Get Method"""

from aquasec.auth import refresh_workload_token, WorkloadAuth
from aquasec.requestapi import aqua_cloudsploit_request, aqua_workload_request


class Get:
    _parent_class: str = None
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
        url = Get._create_workload_url(self._parent_class.workload_auth, self._parent_class.workload_url, "license")
        response = aqua_workload_request(self._parent_class.workload_auth,url=url, method=self.method)
        return response

    @staticmethod
    @refresh_workload_token
    def _create_workload_url(workload_auth: WorkloadAuth, workload_url: str, endpoint: str) -> str:
        print(workload_auth.aqua_url)
        url = workload_url.format(workload_auth.aqua_url,workload_auth.api_version,endpoint)
        return url