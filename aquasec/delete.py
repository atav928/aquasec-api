# pylint: disable=line-too-long
"""Delete Method"""

from dataclasses import asdict

from aquasec import config, logger
from aquasec.requestapi import aqua_workload_request
from aquasec.structures import FirewallPolicy
from aquasec.utilities import UrlUtils

logger.addLogger(__name__)
aquasec_logger = logger.getLogger(__name__)
if not config.SET_LOG:
    aquasec_logger.disabled = True


class Delete:
    _parent_class = None
    method: str = "DELETE"

    def workload_protection(self, url_path, **kwargs):
        """_summary_

        Args:
            url_path (_type_): _description_
            api_version (str): api version when making call

        Returns:
            _type_: _description_
        """
        api_version = kwargs.pop('api_version',
                                 self._parent_class.workload_auth.api_version)  # type: ignore
        url = UrlUtils.create_workload_url(workload_auth=self._parent_class.workload_auth,  # type: ignore
                                           workload_url=self._parent_class.workload_url,  # type: ignore
                                           url_path=url_path,
                                           api_version=api_version)
        aquasec_logger.info("Created URL=%s", url)
        response = aqua_workload_request(workload_auth=self._parent_class.workload_auth,  # type: ignore
                                         method=self.method,
                                         url=url,
                                         verify=self._parent_class.workload_auth.verify,  # type:ignore
                                         )
        aquasec_logger.debug("response=%s", response)
        return response
