# pylint: disable=line-too-long
"""Get Method"""

from aquasec import config, logger

from aquasec.auth import (refresh_workload_token, WorkloadAuth)
from aquasec.statics import BENCH_REPORTS
from aquasec.requestapi import (aqua_cloudsploit_request, aqua_workload_request, retrieve_full_list)
from aquasec.utilities import (reformat_exception, UrlUtils)
from aquasec.exceptions import (AquaSecWrongParam, AquaSecAPIError)

logger.addLogger(__name__)
aquasec_logger = logger.getLogger(__name__)
if not config.SET_LOG:
    aquasec_logger.disabled = True


class Get:
    """Get Class for Aquasec CSPM and Workload Protection
    """
    _parent_class = None
    method: str = "GET"

    all_hosts: list = []

    def cspm(self, url_path: str, **kwargs):
        """Creates CSPM endpoint. Pass any paremters required to complete the Request.

        Args:
            url_path (str, required): The URL resource path. Ex "alerts"
            params (dict, optional): RestAPI parameters
            api_version (str, optional): Defaults to configured version

        Returns:
            dict: JSON results
        """
        api_version: str = kwargs.pop("api_verison", self._parent_class.api_version)  # type: ignore
        url = self._parent_class.cloudsploit_url.format(  # type:ignore
            api_version,
            url_path)
        aquasec_logger.info("Created URL=%s", url)
        response = aqua_cloudsploit_request(url=url, method=self.method, **kwargs)
        aquasec_logger.debug("Response=%s", response)
        return response

    def workload_protection(self, url_path: str, **kwargs):
        """Workload Protection Requests, see README.md for some assistance here.
            this is difficult to get as there is no documentation and most is pulled
            from the cloud portal. But there are some examples to help on readme.

        Args:
            url_path (str): The URL Resource path. Ex: "risks/bench/{id}/bench_results"
            api_version (str, optional): Overrides the version set in the configuration
            params (dict, Optional): required params for request see README for examples

        Returns:
            dict: JSON results
        """
        try:
            api_version: str = kwargs.pop(
                'api_version', self._parent_class.workload_auth.api_version)  # type:ignore
            get_all: bool = kwargs.pop('get_all', False)
        except KeyError as err:
            error = reformat_exception(err)
            aquasec_logger.error("AquaSecMissingParam: %s", error)
        url = UrlUtils.create_workload_url(self._parent_class.workload_auth,  # type: ignore
                                           self._parent_class.workload_url,  # type:ignore
                                           url_path=url_path,
                                           api_version=api_version)  # type: ignore
        aquasec_logger.info("Created Workload URL=%s", url)
        # retrieve response either for a single page, or entire result through a looping function
        response = aqua_workload_request(self._parent_class.workload_auth,  # type: ignore
                                         url=url,
                                         method=self.method,
                                         # type: ignore
                                         **kwargs) if not get_all else retrieve_full_list(self._parent_class.workload_auth,
                                                                                          url=url,
                                                                                          method=self.method,
                                                                                          **kwargs)
        # Log out entry
        aquasec_logger.info("Retrieved Inforomation from Workload Protection")
        return response

    def bench_reports(self, report_type: str, **kwargs) -> dict:
        """_summary_

        Args:
            report_type (list): What report to run. Options:
                ['cis', 'kube_bench', 'linux', 'openshift', 'disa_stig', 'all', 'full']
            cluster_name (str,Optional): specifies only a cluster report


        Returns:
            dict: _description_
        """
        report_type = report_type.lower()
        if report_type not in BENCH_REPORTS:
            aquasec_logger.error("AquaSecWrongParam: Invalid report_type value %s", report_type)
            raise AquaSecWrongParam(f"Invalid report_type value: {report_type=}")
        cluster_name: str = kwargs.pop('cluster_name', "")
        hosts: list = self._get_hosts_id_list(cluster_name=cluster_name)
        # TODO: Paralize
        bench_report: dict = self._get_bench_report(host_id_list=hosts, report_type=report_type)
        return bench_report

    def _get_hosts_id_list(self, cluster_name: str) -> list:
        """Gets all hosts by ID

        Args:
            cluster_name (str, optional): _description_. Defaults to "".

        Returns:
            list: _description_
        """
        host_id_list: list = []
        response: dict = self.workload_protection(
            url_path=config.WORKLOAD_URL_PATHS['hosts']['path'],
            api_version=config.WORKLOAD_URL_PATHS['hosts']['version'],
            get_all=True)
        try:
            all_hosts: list = response['result']
        except KeyError as err:
            error = reformat_exception(err)
            aquasec_logger.error("AquaSecAPIError: %s", error)
        if cluster_name:
            aquasec_logger.info("Searching for hosts that belong to cluster_name=%s", cluster_name)
        for _ in all_hosts:
            if cluster_name and _['cluster_name'] == cluster_name:
                host_id_list.append(_['id'])
            else:
                host_id_list.append(_['id'])
        return host_id_list

    def _get_bench_report(self, host_id_list: list, report_type: str) -> dict:
        """Get Bench Report

        Args:
            host_id_list (list): _description_
            report_type (str): _description_

        Returns:
            dict: _description_
        """
        bench_report: dict = {}
        for _ in host_id_list:
            bench_report[_] = self.workload_protection(
                url_path=config.WORKLOAD_URL_PATHS['host_bench_report']['path'].format(_),
                api_version=config.WORKLOAD_URL_PATHS['host_bench_report']['version'])
        if report_type in ['all', 'full']:
            aquasec_logger.info("Retrieved full bench report")
            return bench_report
        # Gets specific report
        specific_bench_report: dict = {identifier: {report_type: {}}
                                       for identifier in bench_report}
        for _ in list(bench_report):
            specific_bench_report[_][f"{report_type}"] = bench_report[_].get(report_type, {})
        aquasec_logger.info("Retrieved %s_report for specified hosts", report_type)
        return specific_bench_report

    def _endpoint(self, url_path: str, **kwargs) -> str:
        """Creates endpoint for Cloudsploit

        Args:
            endpoint (str): _description_

        Returns:
            str: _description_
        """
        api_version: str = kwargs.pop(
            'api_version', self._parent_class.api_version)  # type: ignore # type :ignore
        url = self._parent_class.cloudsploit_url.format(api_version, url_path)  # type: ignore
        return url
