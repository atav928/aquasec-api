# aquasec-api

Aqua Sec Cloud Secuirty API Tool used for interacting with Aqua Security CSPM Enterprise and Workload.

## Documents

* [CSPM API Docs](https://cloudsploit.docs.apiary.io/#)
* [Aqua CSPM API Overview](https://support.aquasec.com/support/solutions/articles/16000129694-aqua-cspm-api-overview)
* [Authenticte Enterprise CSPM](https://support.aquasec.com/support/solutions/articles/16000127855-how-to-authenticate-to-the-enterprise-api-in-the-cspm-platform)
* [GitHub Repository](https://github.com/atav928/aquasec-api)

## Installation

Install

__Production Version:__

```bash
python -m pip install aquasec-api
```

__Testing Version:__

```bash
pip install -i https://test.pypi.org/simple/ aquasec-api
```

## Configurations

You are able to directly interact with the SDK and pass the variables required to get the creadentials required. You can also have that handled inside of a configuration file or environment.

1. Using system environment variables. Below is a sample.
    __Required:__

    ```bash
    AQUA_WORKLOAD_API_KEY="workload key"
    AQUA_WORKLOAD_API_SECRET="workload secret"
    AQUA_CSPM_API_KEY="cspm key"
    AQUA_CSPM_API_SECRET="cspm secret"
    AQUA_API_VERSION"='v2'
    ```

    __Optional:__

    ```bash
    AQUA_LOGNAME="aquasec.log"
    AQUA_LOGLOCATION="/tmp/logs/"
    AQUA_LOGSTREAM=true
    AQUA_LOGGING="INFO"
    AQUA_SET_LOG=true
    AQUA_CERT=false
    ```

1. Using a yaml configuration file located in _~/.config/.aquaconf_. If a YAML config is found that will override any env variables taking priority.

    __Required:__

    ```yaml
    AQUA_WORKLOAD_API_KEY: "workload key"
    AQUA_WORKLOAD_API_SECRET: "workload secret"
    AQUA_CSPM_API_KEY: "cspm key"
    AQUA_CSPM_API_SECRET: "cspm secret"
    AQUA_API_VERSION: 'v2'
    ```

    __Optional:__

    ```yaml
    AQUA_CERT: true
    AQUA_LOGGING: 'DEBUG'
    AQUA_LOGNAME: 'aquas.log'
    AQUA_LOGSTREAM: true
    AQUA_SET_LOG: true
    AQUA_LOGLOCATION: "/tmp/logs/"
    ```

## Usage

### Workload Protection

Inorder to ensure it workload auth works please be sure to pass the correct paremters that are not set in the configurations. You will require to set variables:

* allowed_endpoints: list
  * Default: __["api_auditor"]__
* csp_roles: list
  * Default: __["ANY"]__

```bash
>>> from aquasec.api import API
>>> api = API(csp_roles=["api_auditor"], allowed_endpoints=["ANY", "GET", "POST"])
INFO    : Created WorkloadAuth Token for URL https://1234567890ab.cloud.aquasec.com
>>> api.get.workload_protection(url_path='license')
INFO    : Created Workload URL=https://1234567890ab.cloud.aquasec.com/api/v2/license
DEBUG   : Response Code: 200| Full Response: {"type":"Standard","organization":"ACME Corp, Inc.","account_id":"","client_name":"user@ACME Corp, Inc.-2023-03-29-StandardS","name":"","email":"john.doe@acme.com","num_agents":0,"num_microenforcers":0,"num_hostenforcers":0,"num_images":0,"num_functions":10000,"num_advanced_functions":0,"num_pas":-1,"num_code_repositories":0,"license_issue_date":1641772800,"license_exp_date":1768003199,"non_prod":false,"approved":true,"external_token":"","strict":false,"level":"Advanced","vpatch":true,"vpatch_coverage":0,"malware_protection":true,"tier":"","agents_running":0,"images_scanned":0,"num_protected_kube_nodes":0,"resource_status":{"Enforcers":"valid","Kubernetes cluster protection":"valid","MicroEnforcers":"valid","Repositories":"valid","VM Enforcers":"valid"}}
```

__Common Params:__

```json
{
    "page": 1,
    "pagesize": 1000
}
```

I found treating page similar to _"limit"_ for a typical API call limiting the amount of responses and _"pagesize"_ is akin to _"offset"_. Responses typically look like this:

```json
{
    "count": 8793,
    "page": 1,
    "pagesize": 9000,
    "result": [
        {
            "id": "9ad366ef-1494-44c1-9b1f-928bca02cf7d",
            "name": "someserver.acme.com",
        }
    ],
    "query": {
        "identifiers_only": false,
        "enforcer_type": "",
        "status": "",
        "cluster": "",
        "image_name": "",
        "image_id": "",
        "server_id": "",
        "kube_enforcer_id": "",
        "batch_name": "",
        "compliant": "",
        "address": "",
        "cve": "",
        "config_file_name": "",
        "scope": "",
        "machine_ids": null,
        "kube_enforcer_exists": false,
        "ke_kube_bench_feature_flag": false
    },
    "more_data_all_pages": 0,
    "is_estimated_count": false
}
```

__Common useful endpoints:__

* Get all hosts (I increase the size based on my company count; you can build out a refresh to get everything until the count equals the amount of records returned)

    ```bash
    >> all_hosts = api.get.workload_protection(url_path='hosts', api_version='v1', params={'pagesize: 1000})
    ```

* Get CIS Benchmark Results

    ```bash
    >> cis_benchmark = api.get.workload_protection(url_path='risk/bench/{id}/bench_results)
    ```

* Get Kubernetes Resources

    ```bash
    >> kube_resources = api.get.workload_protection(url_path='kubernetesresources', params={'pagesize': 1000})
    ```

* Get Kubernetes Applications

    ```bash
    >> applications = api.get.workload_protection(endpoint='applications', api_version='v1')
    ```

* Get Containers

    ```bash
    >>> all_containers = api.get.workload_protection(url_path="containers", api_version='v2', params={'pagesize': 3000})
    ```

## Release Info

### v0.0.1

* WorkloadAuth - usage to get auth token for workload tasks
* API - used to run api calls against CSPM or Workload
* Baseline version to interact with CSPM Enterprise and Workload
* GET is built out to handle almost any api call you need. You just need to figure out the endpoint and pass the url path through the __workload_protection__ or __cspm__

## Version

| Version | Build | Changes |
| ------- | ----- | ------- |
| __0.0.1__ | __a1__ | Initial Alpha Release. Not working baseline for testing |
| __0.0.1__ | __a2__ | built in decorartor and two methods of handling different request types |
| __0.0.1__ | __a3__ | fixed manifest for package deployment |
| __0.0.1__ | __a4__ | fixed requirements |
| __0.0.1__ | __a5__ | removed pathlib from requirments |
| __0.0.1__ | __rc1__| updated readme.md with instructions of usage |
| __0.0.1__ | __rc2__ | issues with dataclasses module |
| __0.0.1__ | __rc3__ | issues with dataclasses and requirements |
| __0.0.1__ | __rc4__ | issues with dataclasses and requirements |
| __0.0.1__ | __rc8__ | final release that solves how the auth works for CSPM and Workload Protection |

__NOTE:__ Use at your own risk!!!! API as is and building on it.
