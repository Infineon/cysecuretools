import sys
from setuptools import setup, find_packages


open_args = {'mode': 'r'}
if sys.version_info[0] > 3:
    open_args['encoding'] = 'utf-8'  # Python 3.x requires explicitly setting the encoding

with open('README.md', **open_args) as f:
    readme = f.read()

setup(
    name='cysecuretools',
    version="1.4.0",
    setup_requires=[
        'setuptools>=40.0,<46',
        'pip>=19,!=20.0,!=20.0.1,<21'
        ],
    install_requires=[
        'cryptography>=2.4.2,<3',
        'click>=7.0,<8',
        'intelhex>=2.2.1,<3',
        'python-jose>=3.0.1,<4',
        'jsonschema>=3.0.0,<4',
        'pyocd==0.25.0'
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
    entry_points={
        'console_scripts': [
            'cysecuretools = cysecuretools.__main__:main',
        ],
    },
    packages=find_packages(),
    options={
        'bdist_wheel': {
            'universal': True,
        }
    }
)

