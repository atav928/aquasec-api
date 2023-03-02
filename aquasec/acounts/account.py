import requests
from aquasec.token import headers

def list_audits_collection() -> dict:
    url = 'https://api.cloudsploit.com/v2/auditlogs'
    header = headers(url=url)
    response = requests.request(method='GET', url=url, headers=header, timeout=60)
    return response.json()
