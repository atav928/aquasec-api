# pylint: disable=line-too-long
"""Create Bench Report"""

from typing import Any
from aquasec import config, logger

from aquasec.api import API
from aquasec.statics import BENCH_REPORTS
from aquasec.exceptions import AquaSecWrongParam, AquaSecError
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
        self.cluster_name: str = kwargs.pop('cluster_name', 'all')

    def delete(self):
        """deletes current host ids
        """
        self.host_ids = []
        self.cluster_name = ''

    def run(self):
        """Runs a collection of hosts
        """
        self.delete()
        aquasec_logger.info("Gathering list of hosts IDs")
        self.host_ids = self._get_hosts()
        aquasec_logger.info("Got list of %s hosts", str(len(self.host_ids)))

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
    """Generates a report specific to the type

    Args:
        api (API): AquaSec-API Object
        report_type (str): Type of report. Options: ['cis', 'kube_bench', 'linux', 'openshift', 'disa_stig', 'all']
        cluster_name (str|Optional): cluster specific name
        report_format (str|Optional): Format of report. Options: ['list', 'flat_list', 'raw']

    Raises:
        AquaSecWrongParam: _description_
    """
    bench_report: Any
    full_bench_report: dict = {}
    REPORT_TYPE: list = BENCH_REPORTS
    REFORMAT_TYPES: list = ['list', 'raw']  # TODO: issue with flat_list
    reports: list = ['cis', 'kube_bench', 'linux', 'openshift', 'disa_stig']
    host_ids: list
    cluster_name: str

    def __init__(self, api: API, report_type: str, **kwargs):
        """Generates a report specific to the type

        Args:
            api (API): AquaSec-API Object
            report_type (str): Type of report. Options: ['cis', 'kube_bench', 'linux', 'openshift', 'disa_stig', 'all']
            cluster_name (str|Optional): cluster specific name
            report_format (str|Optional): Format of report. Options: ['list', 'flat_list', 'raw']

        Raises:
            AquaSecWrongParam: _description_
        """
        self.report_format: str = kwargs.pop("report_format", "list")
        self.cluster_name = kwargs.pop('cluster_name', "")
        # self.cluster_name = cluster_hosts.cluster_name
        self.api = api
        self.report_type = report_type
        if self.report_type.lower() not in self.REPORT_TYPE:
            aquasec_logger.error(
                "report_type=%s|msg=\"invalid\"", self.report_type)
            raise AquaSecWrongParam(f"{self.report_type=}")
        self.__REPORT_FORMAT_FUNC: dict = {
            "list": self._reformat_list,
            "raw": self._reformat_raw,
            "flat_list": self._reformat_list
        }

    def delete(self):
        """_summary_
        """
        self.full_bench_report = {}
        self.bench_report = None
        self.host_ids = []

    def run(self, **kwargs):
        """_summary_
        """
        self.delete()
        self.report_format = self.report_format if not kwargs.get(
            "report_format", "") else kwargs.pop("report_format")
        if self.report_format not in self.REFORMAT_TYPES:
            aquasec_logger.error(
                "AquaSecWrongParam: Invalid report_format=%s", self.report_format)
            raise AquaSecWrongParam(
                f"Invalid report_format={self.report_format}")
        aquasec_logger.info("Creating Report %s in %s format",
                            self.report_type, self.report_format)
        aquasec_logger.info("Getting list of hosts %s",
                            f" for clusters{f' {self.cluster_name}' if self.cluster_name else ''}")
        hosts = Hosts(self.api, cluster_name=self.cluster_name)
        hosts.run()
        self.host_ids = hosts.host_ids
        self._get_bench_report()
        aquasec_logger.info("Generated report")

    def _get_bench_report(self):
        """Get Bench Report

        Args:
            host_id_list (list): _description_
            report_type (str): _description_

        Returns:
            dict: _description_
        """
        for _ in self.host_ids:
            self.full_bench_report[_] = self.api.get.workload_protection(
                url_path=config.WORKLOAD_URL_PATHS['host_bench_report']['path'].format(
                    _),
                api_version=config.WORKLOAD_URL_PATHS['host_bench_report']['version'])
        self.__REPORT_FORMAT_FUNC[self.report_format]()

    def _reformat_raw(self):
        self.bench_report: dict = {}
        bench_list = self._return_bench_list()
        self.bench_report = {host_id: {} for host_id in self.host_ids}
        for bench in bench_list:
            for host in self.bench_report:
                self.bench_report[host][bench] = self.full_bench_report[host]

    def _reformat_list(self):
        self.bench_report: list = []
        bench_list = self._return_bench_list()
        for host in self.host_ids:
            self.bench_report.append(self._build_report(
                bench_list=bench_list, host_id=host))
            aquasec_logger.debug(
                "message=\"Generated report\"|host=%s|bench=%s", host, ','.join(bench_list))

    def _build_report(self, bench_list: list, host_id: str):
        data: dict = {}
        try:
            data["id"] = host_id
            data["date"] = self.full_bench_report[host_id]["date"]
            for bench in bench_list:
                data[f"{bench}_report"] = {}
                data[f"{bench}_report"][f"{bench}_file"] = self.full_bench_report[host_id][bench]['host']['file']
                data[f"{bench}_report"][f"{bench}_logical_name"] = self.full_bench_report[host_id][bench]['host']['logical_name']
                data[f"{bench}_report"][f"{bench}_name"] = self.full_bench_report[host_id][bench]['host']['name']
                data[f"{bench}_report"][f"{bench}_total_info"] = self.full_bench_report[host_id][bench]["result"]["total_info"]
                data[f"{bench}_report"][f"{bench}_total_pass"] = self.full_bench_report[host_id][bench]["result"]["total_pass"]
                data[f"{bench}_report"][f"{bench}_total_warn"] = self.full_bench_report[host_id][bench]["result"]["total_warn"]
                data[f"{bench}_report"][f"{bench}_total_fail"] = self.full_bench_report[host_id][bench]["result"]["total_fail"]
                data[f"{bench}_report"][f"{bench}_disabled"] = self.full_bench_report[host_id][bench]["result"]["disabled"]
                data[f"{bench}_report"][f"{bench}_version"] = self.full_bench_report[host_id][bench]["result"]["version"]
                data[f"{bench}_report"][f"{bench}_scan_status"] = self.full_bench_report[host_id][bench]["scan_status"]["status"]
                data[f"{bench}_report"][f"{bench}_scan_message"] = self.full_bench_report[host_id][bench]["scan_status"]["message"]
                if self.report_format == "list":
                    data[f"{bench}_report"][f"{bench}_tests"] = self.full_bench_report[host_id][bench]["result"]["tests"]
                if self.report_format == "flat_list":
                    self._reformat_flat_list(
                        bench=bench, value=self.full_bench_report[host_id], host_id=host_id)
            data["enforcer_status"] = self.full_bench_report[host_id].get(
                "enforcer_status", "")
            return data
        except Exception as err:
            error = reformat_exception(err)
            aquasec_logger.error("AquaSecError: %s", error)
            aquasec_logger.debug(
                "bench_list=%s|host_id=%s|bench=%s", bench_list, host_id, bench)
            raise AquaSecError(error)

    def _reformat_flat_list(self, bench: str, value: dict, host_id: str):
        """_summary_

        Args:
            bench (str): _description_
            value (dict): _description_
            host_id (str): _description_
        """
        try:
            temp_bench_report: dict = {}
            aquasec_logger.debug("build_results values=%s",
                                 value[bench]['result']['tests'])
            temp_bench_report = self._build_results(
                value[bench]['result']['tests'],
                bench_type=f"{bench}_report_tests") if value[bench]['result']['tests'] else None
            aquasec_logger.debug("temp_bench_report=%s", temp_bench_report)
            if temp_bench_report:
                self.bench_report[host_id][f"{bench}_report"] = {
                    **self.bench_report[host_id][f"{bench}_report"], **temp_bench_report}
            else:
                self.bench_report[host_id][f"{bench}_report"][f"{bench}_report_tests"] = None
        except Exception as err:
            error = reformat_exception(err)
            aquasec_logger.error("Error: %s", error)
            aquasec_logger.debug("build_results values=%s",
                                 value[bench]['result']['tests'])
            raise AquaSecError(error)

    def _build_results(self, values: list, bench_type: str):
        """_summary_

        Args:
            values (list): _description_
            bench_type (str): _description_

        Returns:
            _type_: _description_
        """
        results: dict = {}
        for test in values:
            if test.get("section", ""):
                base: str = f"{bench_type}_section_{test.get('section')}"
                results[base] = test["section"]
                results[f"{base}_desc"] = test.get("desc")
                results[f"{base}_info"] = test.get("info", 0)
                results[f"{base}_pass"] = test.get("pass", 0)
                results[f"{base}_warn"] = test.get("warn")
                results[f"{base}_fail"] = test.get("fail")
                if test['results']:
                    returned_test_results = self._build_test_results(
                        base_name=base, values=test['results'])
                    results = {**results, **returned_test_results}
                else:
                    results[f"{base}_results"] = None
        return results

    def _build_test_results(self, base_name: str, values: list) -> dict:
        """_summary_

        Args:
            base_name (str): _description_
            values (list): _description_

        Returns:
            dict: _description_
        """
        test_results: dict = {}
        for result in values:
            if result.get('test_number'):
                base: str = f"{base_name}_results_test_number_{result['test_number']}"
                test_results[f"{base}"] = result['test_number']
                test_results[f"{base}_test_desc"] = result["test_desc"]
                test_results[f"{base}_status"] = result["status"]
                test_results[f"{base}_test_info"] = result["test_info"]
                test_results[f"{base}_actual_value"] = result["actual_value"]
                test_results[f"{base}_expected_result"] = result["expected_result"]
                test_results[f"{base}_audit"] = result["audit"]
                test_results[f"{base}_severity"] = result["severity"]
        return test_results

    def _return_bench_list(self) -> list:
        """_summary_

        Returns:
            list: report_type in list format
        """
        return self.reports if self.report_type.lower() == 'all' else [
            self.report_type]
