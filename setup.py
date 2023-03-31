# pylint: disable=exec-used
"""Set up"""

import os.path
from setuptools import setup, find_packages

__version__ = None
readme = '' # pylint: disable=invalid-name
with open('requirements.txt', encoding='utf-8') as f:
    requirements = f.read().splitlines()
here = os.path.abspath(os.path.dirname(__file__))
exec(open(f"{here}/aquasec/_version.py", encoding='utf-8').read())
readme_path = os.path.join(here, "README.md")
if os.path.exists(readme_path):
    with open(readme_path, 'rb') as stream:
        readme = stream.read().decode('utf-8')

setup(
    name='aquasec-api',
    version=__version__,  # type: ignore
    author="atav928",
    description='Aqua Security SDK to pull data from Aquasec Tenant and CSPM for auditing',
    author_email="dev@tavnets.com",
    maintainer_email="dev@tavnets.com",
    packages=find_packages(),
    include_package_data=True,
    install_requires=requirements,
    url='https://github.com/atav928/aquasec-api',
    keywords=['aquasec', 'aqua security', 'workload protection'],
    long_description=readme,
    long_description_content_type='text/markdown',
)  # pragma: no cover
