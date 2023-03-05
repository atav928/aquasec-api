# pylint: disable=missing-class-docstring,too-few-public-methods
"""API"""

from aquasec import logger, config, return_auth
from aquasec.get import Get
from aquasec.post import Post
from aquasec.utilities import reformat_exception
from aquasec.exceptions import (AquaSecPermission, AquaSecAPIError)

logger.addLogger(__name__)
aqua_logger = logger.getLogger(__name__)
if not config.SET_LOG:
    aqua_logger.disabled = True


class API:
    """_summary_
    """
    cloudsploit_url: str = "https://api.cloudsploit.com/{}/{}"
    workload_url: str = "{}/api/{}/{}"
    endpoint_alerts: str = "alerts"
    endpoint_apikeys: str = "apikeys"

    def __init__(self, **kwargs):
        try:
            self.workload_auth = return_auth(**kwargs)
            aqua_logger.info("Created WorkloadAuth Token for URL %s", self.workload_auth.aqua_url)
        except (AquaSecPermission, AquaSecAPIError) as err:
            error = reformat_exception(err)
            aqua_logger.error("Cannot Create Workload Auth| %s", error)
        self.api_version = kwargs.pop('api_version') if kwargs.get(
            'api_version') else config.API_VERSION
        self.supported_urls: dict = self.list_supported_urls()

        # Bind API method classes to this object
        subclasses = self._subclass_container()
        self.get = subclasses['get']()
        self.post = subclasses['post']()

    def list_supported_urls(self) -> dict:
        """Create a dictionary of supported endpoint URLs

        Returns:
            dict: _description_
        """
        supported_urls: dict = {}
        attr_list = dir(self)
        for i in attr_list:
            if i.split('_')[0] == 'endpoint':
                value = getattr(self, i)
                supported_urls.update({i: self.cloudsploit_url.format(self.api_version, value)})
        return supported_urls

    def _subclass_container(self):  # pylint: disable=too-many-locals
        """
        Call subclasses via function to allow passing parent namespace to subclasses.

        **Returns:** dict with subclass references.
        """
        _parent_class = self

        return_object = {}

        class GetWrapper(Get):
            def __init__(self):
                self._parent_class = _parent_class
        return_object['get'] = GetWrapper

        class PostWrapper(Post):
            def __init__(self):
                self._parent_class = _parent_class
        return_object['post'] = PostWrapper
        return return_object
