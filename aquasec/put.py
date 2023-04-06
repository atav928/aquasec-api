"""Put Method"""

from dataclasses import asdict
from aquasec import config, logger
from aquasec.requestapi import aqua_workload_request
from aquasec.structures import FirewallPolicy
from aquasec.utilities import UrlUtils

logger.addLogger(__name__)
aquasec_logger = logger.getLogger(__name__)
if not config.SET_LOG:
    aquasec_logger.disabled = True


class Post:
    _parent_class = None
    method: str = "PUT"
    data_types = 