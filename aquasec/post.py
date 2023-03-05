"""Post Method"""

from aquasec import config, logger

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
