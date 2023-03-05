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
    AQUA_API_KEY="your api key"
    AQUA_API_SECRET="your api secret"
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
    AQUA_API_KEY: "API KEY"
    AQUA_API_SECRET: "API SECRET"
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

```bash
>>> from aquasec.api import API
>>> api = API()
INFO    : Created WorkloadAuth Token for URL https://1234567890ab.cloud.aquasec.com
>>> api.get.alerts()
DEBUG   : Response Code: 403| Full Response: {"status":403,"id":"e4ac385c-c7c1-472c-861d-77166fbebeaa","code":1,"message":"Access denied","errors":["This endpoint and method requires the alerts::read permission."]}
ERROR   : AquaSecPermission: Access denied
```

```bash
>>> api.get.check_license()
DEBUG   : Created url https://1234567890ab.cloud.aquasec.com/api/v2/license
DEBUG   : Response Code: 403| Full Response: {"message":"You are not allowed to perform this action","code":403}
ERROR   : AquaSecPermission: You are not allowed to perform this action
```

## Release Info

### v0.0.1

* WorkloadAuth - usage to get auth token for workload tasks
* API - used to run api calls against CSPM or Workload
* Baseline version to interact with CSPM Enterprise and Workload

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