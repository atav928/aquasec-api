"""API"""
from aquasec import logger, config, return_auth
from aquasec.get import Get

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
        self.workload_auth = return_auth(**kwargs)
        self.api_version = kwargs.pop('api_version') if kwargs.get('api_version') else config.API_VERSION

        # Bind API method classes to this object
        subclasses = self._subclass_container()
        self.get = subclasses['get']()

    def list_supported_urls(self) -> list:
        supported_urls = []
        attr_list = dir(self)
        for i in attr_list:
            if i.split('_')[0] == 'endpoint':
                value = getattr(self, i)
                supported_urls.append(self.cloudsploit_url.format(self.api_version,value))
        return supported_urls

    def to_dict(self) -> dict:
        return dir(self)
    
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
        return return_object
