"""
Copyright (c) 2020 Cypress Semiconductor Corporation

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
import os
import json
import logging
from jose import jws
from jose.constants import ALGORITHMS
from cysecuretools.execute.provisioning_lib.cyprov_crypto import Crypto

logger = logging.getLogger(__name__)


def json_to_jwt(json_file, priv_key, output_file=None, alg='ES256'):
    """
    Create JWT from JSON file
    :param json_file: The JSON file to be signed
    :param priv_key: The private key to sign JSON
    :param output_file: The output file to save the certificate
    :param alg: The signing algorithm
    :return: JWT token
    """
    try:
        with open(json_file) as f:
            file_content = f.read()
            json_data = json.loads(file_content)
    except FileNotFoundError as e:
        logger.error(e)
        return None

    return create_jwt(json_data, priv_key, output_file, alg)


def create_jwt(payload, priv_key, output_file=None, alg='ES256'):
    """
    Create JWT from JSON object
    :param payload: The JSON to be signed
    :param priv_key: The private key to sign JSON
    :param output_file: The output file to save the certificate
    :param alg: The signing algorithm
    :return: JWT token
    """
    if alg == 'ES256':
        headers = {'alg': 'ES256'}
        algorithm = ALGORITHMS.ES256
    else:
        raise ValueError(f'Unsupported algorithm {alg}')

    token = jws.sign(payload, priv_key, headers=headers, algorithm=algorithm)
    logger.debug(f'Created JWT token: {token}')

    if output_file:
        with open(output_file, 'w') as f:
            f.write(token)
        logger.debug(f'Saved JWT token to a file: {output_file}')
    return token


def readable_jwt(jwt):
    """
    Convert a JWT token in base64url into a readable dictionary object
    with decoded payload and header for printing and logging
    :param jwt: JWT filename
    :return: Readable dictionary
    """
    txt = Crypto.read_jwt(jwt) if os.path.isfile(jwt) else jwt
    readable = Crypto.readable_jwt(txt)
    return readable
