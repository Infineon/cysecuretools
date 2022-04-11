"""
Copyright (c) 2019-2022 Cypress Semiconductor Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
from setuptools import setup, find_packages


with open('README.md', 'r', encoding='utf-8') as f:
    readme = f.read()

with open('CHANGELOG.md', 'r', encoding='utf-8') as f:
    changelog = f.read()

version = {}
with open('cysecuretools/version.py', 'r', encoding='utf-8') as f:
    exec(f.read(), version)  # pylint: disable=exec-used

setup(
    name='cysecuretools',
    version=version['__version__'],
    install_requires=[
        'setuptools==59.6.0',
        'psutil==5.9.0',
        'cryptography==36.0.1',
        'click==8.0.4',
        'intelhex==2.3.0',
        'python-jose==3.3.0',
        'jsonschema>=4.0.0,<=4.4.0',
        'pyocd==0.32.3',
        'cbor==1.0.0',
        'packaging==21.3'
        ],
    description='Cypress secure tools for Python',
    long_description=readme + '\n\n' + changelog,
    long_description_content_type='text/markdown',
    author='Cypress Semiconductor',
    url='https://github.com/cypresssemiconductorco/cysecuretools',
    license='Apache 2.0',
    python_requires='>=3.6',
    include_package_data=True,  # include files from MANIFEST.in
    classifiers=[
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Operating System :: OS Independent',
        'Topic :: Software Development :: Embedded Systems',
    ],
    entry_points={
        'console_scripts': [
            'cysecuretools = cysecuretools.__main__:main',
        ],
    },
    packages=find_packages(),
    options={
        'bdist_wheel': {
            'python_tag': 'py3',
        }
    }
)
