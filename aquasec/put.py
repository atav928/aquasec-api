"""Put Method"""

from dataclasses import asdict
from aquasec import config, logger

from aquasec.statics import DATA_TYPES

from aquasec.requestapi import aqua_workload_request
from aquasec.structures import FirewallPolicy
from aquasec.utilities import UrlUtils

logger.addLogger(__name__)
aquasec_logger = logger.getLogger(__name__)
if not config.SET_LOG:
    aquasec_logger.disabled = True


class Put:
    _parent_class = None
    method: str = "PUT"
    data_types: dict = DATA_TYPES

    def workload_protection(self, url_path: str, data_type: str, data: str, **kwargs) -> dict:
        """Updates an existing object

        Args:
            url_path (str): _description_
            data_type (str): _description_
            data (str): _description_
            api_version (str): defaults config version otherwise can be adjusted

        Returns:
            dict: _description_
        """
        put_data = asdict(self.data_types[data_type](**data))
        aquasec_logger.debug("put_data=%s", put_data)
        api_version = kwargs.pop('api_version',
                                 self._parent_class.workload_auth.api_version)  # type: ignore
