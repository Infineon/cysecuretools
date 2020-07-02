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
from jose import jwk, exceptions
from jose.constants import ALGORITHMS
import cysecuretools.execute.keygen as keygen
from cysecuretools.execute.provisioning_lib.cyprov_crypto import Crypto
from cysecuretools.execute.provisioning_lib.cyprov_pem import PemKey
from cysecuretools.execute.sys_call import get_prov_details

logger = logging.getLogger(__name__)


class KeyReaderMXS40V1:
    def __init__(self, target):
        self.target = target
        self.policy_parser = target.policy_parser
        self.policy_dir = self.policy_parser.policy_dir

    def read_public_key(self, tool, key_id, key_format='jwk'):
        passed, key = get_prov_details(tool, self.target.register_map, key_id)
        if passed:
            logger.debug(f'Public key (key_id={key_id}) read successfully')
            logger.debug(f'{key}')
            pub_key = json.loads(key)

            if key_format == 'jwk':
                return pub_key
            elif key_format == 'pem':
                return jwk_to_pem(pub_key)
            else:
                raise ValueError(f'Invalid key format \'{key_format}\'')
        else:
            logger.error(f'Cannot read public key (key_id={key_id})')
            return None

    def get_cypress_public_key(self):
        """
        Gets Cypress public key from cy_auth JWT packet.
        :return: Cypress public key (JWK).
        """
        jwt_text = Crypto.read_jwt(self.policy_parser.get_cy_auth())
        json_data = Crypto.readable_jwt(jwt_text)
        return json_data["payload"]['cy_pub_key']


def jwk_to_pem(json_key, private_key=False):
    pem = PemKey(json_key)
    pem_key = pem.to_str(private_key)
    return pem_key


def get_aes_key(key_size):
    return keygen.generate_aes_key(key_size)


def load_key(key):
    """
    Load JWK for certificate signing.
    :param key: File that contains the key.
    :return: Tuple - private key, public key
    """
    priv_key = None
    pub_key = None

    with open(key, 'r') as f:
        key_str = f.read()

    key_json = json.loads(key_str)
    combined = False
    for item in key_json:
        if 'priv_key' in item or 'pub_key' in item:
            combined = True
            break

    if not combined:
        try:
            is_private = 'd' in key_json
            if is_private:
                if 'alg' in key_json:
                    priv_key_obj = jwk.construct(key_json)
                else:
                    priv_key_obj = jwk.construct(key_json, ALGORITHMS.ES256)
                pub_key_obj = priv_key_obj.public_key()
                priv_key = key_json
                pub_key = pub_key_obj.to_dict()
                # Jose ignores 'kid' and 'use' fields in JWK, so
                # copy them from private key
                if 'kid' not in pub_key and 'kid' in priv_key:
                    pub_key['kid'] = priv_key['kid']
                if 'use' not in pub_key and 'use' in priv_key:
                    pub_key['use'] = priv_key['use']
                # Jose represents key tokens as bytes, so convert bytes to str
                for k, v in pub_key.items():
                    if isinstance(v, bytes):
                        pub_key[k] = v.decode('utf-8')
            else:
                priv_key = None
                pub_key = key_json
        except exceptions.JWKError:
            logger.error(f'Failed to load key {key}')
            priv_key = None
            pub_key = None
    else:
        # Input file may be JSON combined from private and public key
        for item in key_json:
            if 'priv_key' in item:
                priv_key = key_json[item]
                break
        for item in key_json:
            if 'pub_key' in item:
                pub_key = key_json[item]
                break

        # Input file does not contain JWK
        if not priv_key:
            ValueError(f'Private key not found in {key}')
        if not pub_key:
            if priv_key:
                pub_key = priv_key
                del pub_key["d"]
            else:
                ValueError(f'Public key not found in {key}')

    return priv_key, pub_key
