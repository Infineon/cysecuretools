import sys
from setuptools import setup, find_packages


open_args = {'mode': 'r'}
if sys.version_info[0] > 3:
    open_args['encoding'] = 'utf-8'  # Python 3.x requires explicitly setting the encoding

with open('README.md', **open_args) as f:
    readme = f.read()

setup(
    name='cysecuretools',
    version="1.2.0",
    setup_requires=[
        'setuptools>=40.0'
        ],
    install_requires=[
        'cryptography>=2.4.2',
        'click>=7.0',
        'intelhex>=2.2.1',
        'python-jose>=3.0.1',
        'jsonschema>=3.0.0',
        'pyocd>=0.22.0'
        ],
    description='Cypress secure tools for Python',
    long_description=readme,
    long_description_content_type='text/markdown',
    author='Cypress Semiconductor',
    url='https://github.com/cypresssemiconductorco/cysecuretools',
    license='Apache 2.0',
    python_requires='>=3.6',
    include_package_data=True,  # include files from MANIFEST.in
    classifiers=[
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3.7',
        'Operating System :: OS Independent',
        'Topic :: Software Development :: Embedded Systems',
    ],
    packages=find_packages(),
    options={
        'bdist_wheel': {
            'universal': True,
        }
    }
)

