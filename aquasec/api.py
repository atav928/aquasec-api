# pylint: disable=missing-class-docstring,too-few-public-methods
"""API"""

from aquasec import logger, config, return_workload_auth
from aquasec.get import Get
from aquasec.post import Post
from aquasec.delete import Delete
from aquasec.put import Put
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
    api_version: str = ""  # set on initialization
    # Endpoints for CSPM going away from this
    # TODO: Remove the endpoint capability and just use the direct csmp get()
    endpoint_alerts: str = "alerts"
    endpoint_apikeys: str = "apikeys"
    endpoint_auditlogs: str = "auditlogs"
    # Testing workload and endpoint types.. this should eventually go away
    # TODO: figure out how to get all the actual endpoints listed some how and their params
    workload_license = 'licenses'
    workload_assurance_policy = 'assurance_policy'  # Query params
    workload_access_management = 'access_management'  # access_management/scopes/available
    workload_firewall_polcies = "firewall_polcies"
    workload_fatureflags = "featureflags"
    workload_notifications = 'notifications'
    workload_vul_insghts = "dashboards/widgets/vulnerabilityInsights"
    worload_vul_trends = "dashboards/widgets/imagesVulnerabilitiesTrends"  # param period: str 1h
    # Version 1
    workload_features = "features"
    workload_network_policies = "networkpolicies"
    workload_hosts = "hosts"  # batch_name={clustername}page=1 pagesize=10
    # params orderby=name page=1 pagesize=200 orderedby=display_name type=enforcer
    workload_applications = "applications"

    def __init__(self, **kwargs):
        try:
            self.workload_auth = return_workload_auth(**kwargs)
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
        self.put = subclasses['put']()
        self.delete = subclasses['delete']()

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

        class PutWrapper(Put):
            def __inti__(self):
                self._parent_class = _parent_class
        return_object['put'] = PutWrapper

        class DeleteWrapper(Delete):
            def __init__(self):
                self._parent_class = _parent_class
        return_object['delete'] = DeleteWrapper
        return return_object
