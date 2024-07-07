"""Configurations"""

import os

from aquasec.utilities import set_bool


class Config:  # pylint: disable=missing-class-docstring
    WORKLOAD_API_KEY: str = os.getenv("AQUA_WORKLOAD_API_KEY", "")
    WORKLOAD_API_SECRET: str = os.getenv("AQUA_WORKLOAD_API_SECRET", "")
    CSPM_API_KEY: str = os.getenv("AQUA_CSPM_API_KEY", "")
    CSPM_API_SECRET: str = os.getenv("AQUA_CSPM_API_SECRET", "")
    API_URL = "https://api.cloudsploit.com/v2"
    API_VERSION: str = os.getenv("AQUA_API_VERSION", 'v2')
    LOGNAME: str = os.getenv("AQUA_LOGNAME", "aquasec.log")
    LOGLOCATION: str = os.getenv("AQUA_LOGLOCATION", "")
    LOGSTREAM = set_bool(os.getenv("AQUA_LOGSTREAM", 'true'))
    LOGGING: str = os.getenv("AQUA_LOGGING", "INFO")
    SET_LOG = set_bool(os.getenv("AQUA_SET_LOG", "true"))
    ENCODING = "utf-8"
    CERT = set_bool(os.getenv("AQUA_CERT", 'true'))  # pylint: disable=invalid-name
    WORKLOAD_URL_PATHS: dict = {
        "hosts": {
            "path": "hosts",
            "version": "v1"
        },
        "host_bench_report": {
            "path": "risks/bench/{}/bench_results",
            "version": "v2"
        },
        "containers": {
            "path": "containers",
            "version": "v2"
        }
    }
