"""Create Bench Report"""

from aquasec import config, logger

from aquasec.api import API
from aquasec.statics import BENCH_REPORTS
from aquasec.exceptions import AquaSecWrongParam
from aquasec.utilities import reformat_exception

logger.addLogger(__name__)
aquasec_logger = logger.getLogger(__name__)
if not config.SET_LOG:
    aquasec_logger.disabled = True


class Hosts:
    host_ids: list
    cluster_name: str

    def __init__(self, api: API, **kwargs):
        self.api = api
        self.cluster_name: str = kwargs.pop('cluster_name', 'All')
        self.host_ids = self._get_hosts()

    def _get_hosts(self) -> list:
        """Gets all hosts by ID

        Args:
            cluster_name (str, optional): _description_. Defaults to "".

        Returns:
            list: _description_
        """
        host_id_list: list = []
        response = self.api.get.workload_protection(
            url_path=config.WORKLOAD_URL_PATHS['hosts']['path'],
            api_version=config.WORKLOAD_URL_PATHS['hosts']['version'],
            get_all=True)
        try:
            all_hosts: list = response['result']
        except KeyError as err:
            error = reformat_exception(err)
            aquasec_logger.error("AquaSecAPIError: %s", error)
        if self.cluster_name:
            aquasec_logger.info(
                "Searching for hosts that belong to self.cluster_name=%s", self.cluster_name)
        for _ in all_hosts:
            if self.cluster_name and _['cluster_name'] == self.cluster_name:
                host_id_list.append(_['id'])
            else:
                host_id_list.append(_['id'])
        return host_id_list


class ClusterHosts:
    hosts_ids: list
    cluster_name: str

    def __init__(self, hosts: Hosts):
        self.hosts_ids = hosts.host_ids
        self.cluster_name = hosts.cluster_name
        self.ClusterHosts: dict = {
            self.cluster_name if self.cluster_name else "All": self.hosts_ids}


class BenchReport:
    bench_report: dict
    REPORT_TYPE: list = BENCH_REPORTS

    def __init__(self, api: API, report_type: str, cluster_hosts: ClusterHosts):
        self.hosts = cluster_hosts.hosts_ids
        self.cluster_name = cluster_hosts.cluster_name
        self.api = api
        self.report_type = report_type
        self.bench_report: dict = {}
        if self.report_type.lower() not in self.REPORT_TYPE:
            aquasec_logger.error("report_type=%s|msg=\"invalid\"", self.report_type)
            raise AquaSecWrongParam(f"{self.report_type=}")
        self._get_bench_report()

    def _get_bench_report(self):
        """Get Bench Report

        Args:
            host_id_list (list): _description_
            report_type (str): _description_

        Returns:
            dict: _description_
        """
        full_bench_report: dict = {}
        for _ in self.hosts:
            full_bench_report[_] = self.api.get.workload_protection(
                url_path=config.WORKLOAD_URL_PATHS['host_bench_report']['path'].format(_),
                api_version=config.WORKLOAD_URL_PATHS['host_bench_report']['version'])
        self._get_bench_report_specific(full_bench_report=full_bench_report)

    def _get_bench_report_specific(self, full_bench_report: dict):
        if self.report_type.lower() == 'all':
            reports = self.REPORT_TYPE.remove('all')
            for host in self.hosts:
                for report in reports:
                    self.bench_report[host][report] = full_bench_report[host].get(report, {})
        else:
            for host in self.hosts:
                self.bench_report[host][
                    self.report_type] = full_bench_report[host].get(
                    self.report_type, {})
