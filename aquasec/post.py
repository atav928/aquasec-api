# pylint: disable=line-too-long
"""Post Method"""

from dataclasses import asdict
from aquasec import config, logger
from aquasec.requestapi import aqua_workload_request
from aquasec.statics import DATA_TYPES
from aquasec.utilities import UrlUtils

# from aquasec.auth import refresh_workload_token, WorkloadAuth
# from aquasec.requestapi import aqua_cloudsploit_request, aqua_workload_request

logger.addLogger(__name__)
aquasec_logger = logger.getLogger(__name__)
if not config.SET_LOG:
    aquasec_logger.disabled = True


class Post:
    """Get Class for Aquasec

    Returns:
        _type_: _description_
    """
    _parent_class = None
    method: str = "POST"
    data_types: dict = DATA_TYPES

    def workload_protection(self, url_path: str, data_type: str, data: dict, **kwargs):
        """_summary_

        Args:
            url_path (str): _description_
            data_type (str): _description_
            data (dict): _description_

        Returns:
            _type_: _description_
        """
        post_data = asdict(self.data_types[data_type](**data))
        aquasec_logger.debug("post_data=%s", post_data)
        api_version = kwargs.pop('api_version',
                                 self._parent_class.workload_auth.api_version)  # type: ignore
        url = UrlUtils.create_workload_url(workload_auth=self._parent_class.workload_auth,  # type: ignore
                                           workload_url=self._parent_class.workload_url,  # type: ignore,
                                           url_path=url_path,
                                           api_version=api_version)
        aquasec_logger.info("Created URL=%s", url)
        response = aqua_workload_request(workload_auth=self._parent_class.workload_auth,  # type: ignore
                                         method=self.method,
                                         url=url,
                                         verify=self._parent_class.workload_auth.verify,  # type: ignore
                                         data=post_data)
        aquasec_logger.debug("response=%s", response)
        return response
