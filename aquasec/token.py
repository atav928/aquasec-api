from inspect import signature
from urllib import response
from auth import headers, cwpp_headers
from urllib.request import Request, urlopen
from urllib.parse import urlparse
import json
import ssl
import os
import requests
from requests.utils import DEFAULT_CA_BUNDLE_PATH
import jwt
from aquasec import config
 
 
def gen_token():
    ssl._create_default_https_context = ssl._create_unverified_context
    url = f"{config.API_URL}/tokens"
    method = 'POST'
    payload = json.dumps({"validity":240,"allowed_endpoints":["ANY"],"csp_roles":["api_auditor"]})
    # TODO: remove legacy auth requirements build my own header pass allong
    request = requests.post(url, data=payload, headers=headers(url,method,payload))
    response_body = json.loads(request.text)
    #token = response_body["data"]
    # TODO: remove all print
    print(response_body)
    # TODO: Fix return value should actually gen token
    #return token
#gen_token()
 
    
def get_aqua_url(token):
    #### Decode JWT Token for URL ###
    # TODO: use newer method
    decoded_parse = jwt.decode(token, options={"verify_signature": False})
    # print(decoded_parse)
    aqua_url = decoded_parse["csp_metadata"]["urls"]["ese_url"]
    # print(aqua_url)
    return aqua_url
    
# get_aqua_url(gen_token())  
 
def check_license():
    ssl._create_default_https_context = ssl._create_unverified_context
    api_version = 'v2'
    api_endpoint = 'api' + '/' + f"{api_version}" + '/'  + 'license'
    token = gen_token()
    # print(token)
    aqua_url = "https://" + get_aqua_url(token)
    print(aqua_url)
    
    endpoint_url = f"{aqua_url}" + '/' + api_endpoint
    # print(endpoint_url)
 
    # TODO: figure out what cwpp headers is for
    request = requests.get(endpoint_url, headers=cwpp_headers(token))
    request_response = json.loads(request.text)
    license = json.dumps(request_response, indent = 4, sort_keys = True)
    print(license)
    
# TODO: Based off initial session token and timmer create a decorator auth class to handle this
check_license()