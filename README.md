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

> __NOTE:__ The Certificate is the verification used for the RestAPI calls. This will be called upon unless you specify in your own _verify=_ in your method call. Just like in the Requests module this is a (str|bool) value that defaults to _True_. If it is a string it will confirm that the string is a file and therefore the location of a specific cert to be verified against a Proxy forwarder.

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

__Bypass OS or YAML Configs:__

```bash
>>> from aquasec.api import API
>>> api = API(api_key="7d6c02219a99", api_secret="0b3b928a1acd4c2580583cc160f49f5e",api_csp_roles=["CSP_USER"],allowed_endpoints=["ANY"])
INFO    : Created WorkloadAuth Token for URL https://1234567890ab.cloud.aquasec.com
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
    >> all_hosts = api.get.workload_protection(url_path='hosts', api_version='v1', get_all=True)
    ```

* Get CIS Benchmark Results

    ```bash
    >> host_id = all_hosts['result'][0]['id']
    >> cis_benchmark = api.get.workload_protection(url_path=f'risks/bench/{host_id}/bench_results')
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
    >>> all_containers = api.get.workload_protection(url_path="containers", api_version='v2', get_all=True)
    ```

* Get CIS Bench Reports Directly

    ```bash
    # Kube Report Only for Production Cluster
    >>> kube_report = api.get.bench_reports(report_type='kube_bench', cluser_name='production')
    # Kube Report for all Clusters
    >>> kube_report = api.get.bench_reports(report_type='kube_bench')
    # Linux Report Only
    >>> all_linux_report = api.get.bench_reports(report_type='linux')
    # disa_stig Report
    >>> disa_stig_report = api.get.bench_reports(report_type='disa_stig')
    # Full CIS Benchmark Report on all Hosts
    >>> full_cis_report = api.get.bench_reports(report_type='all')
    ```

## Release Info

### v0.0.3

* Added ability to POST
* Adding PUT
* Additional Datastructures
* Additional Delete Functionality
* Introducing Orchestration on Actions
* Bug in response code when we POST and possibly PUT an object; no json is returned just a 204. This breaks the standard return expectation. Raised issue with AquaSec. Till than buillt a way to handle it safely and introducted a message response to those responses.

### v0.0.2

* added retrieve_full_list() which allows get to retrieve all items.
* if _"get_all"_ is specified in api.get.workload_protection() the variable will retrieve all possible values.
* updates to README.md, fixed a few typos.
* added ability to retrieve CIS bench reports directly without the need to run mulitple calls.
* Fixed issue with _"get_all"_ where it would go into an infinant loop since the count return did not always match the results.
* Provides direct ability to call on all reports or individual reports.
* Fixed issue where passing api_key or api_secret when creating an API Object would not properly create the WorkloadAuth.

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
| __0.0.2__ | __a1__ | Updated readme testing some additional modeling and possible integration scripts |
| __0.0.2__ | __a2__ | Added ability to retrieve all functions leveraging paging |
| __0.0.2__ | __a3__ | Added CIS benchmark reports, Fix bug with infinate get_all |
| __0.0.2__ | __rc1__ | Bug with providing direct api information into api function with WorkloadAuth |
| __0.0.2__ | __final__ | completed orchestration of bench report and standard get workload checks |
| __0.0.3__ | __a1__ | Intro to POST, PUT, DELETE and adding some datastructures for creating and manipluating AquaSec |

__NOTE:__ Use at your own risk!!!! API as is and building on it.
