"""
Copyright 2019-2022 Cypress Semiconductor Corporation (an Infineon company)
or an affiliate of Cypress Semiconductor Corporation. All rights reserved.

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
import binascii
from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from ...core import strops
from ...core.json_helper import read_json
from ...core.key_helper import calc_key_hash
from ...core.key_handlers.rsa_handler import RSAHandler

logger = logging.getLogger(__name__)


def generate_key(key_size, template=None):
    """Either creates a new RSA key in PEM format or converts RSA key
    modulus and exponent to PEM if a template is specified
    @param key_size: Key size
    @param template: A template containing RSA key modulus and exponent
    @return: Private key, public key
    """
    if template:
        data = read_json(template)
        try:
            public_key = RSAHandler.populate_public_key(
                data['exponent'], data['modulus'])
            private_key = None
        except ValueError as e:
            raise ValueError(
                f'The template contains invalid data ({template})') from e
        except KeyError as e:
            raise KeyError(
                f'The template structure is invalid ({template})') from e
    else:
        private_key = rsa.generate_private_key(65537, key_size,
                                               default_backend())
        public_key = private_key.public_key()

    return private_key, public_key


def create_pubkey_hash(pubkey_path, hash_path):
    """Creates a file containing public key 16-bytes hash in the
    following format:
    '0x669173b0UL, 0xbed0e5bcUL, 0x907ee6feUL, 0x886b7848UL'
    """
    hash_bin = calc_key_hash(pubkey_path)
    hash_list = strops.split_by_n(hash_bin, 4)
    hash_fmt = ', '.join(
        [f'0x{binascii.hexlify(i[::-1]).decode()}UL' for i in hash_list])
    logger.info('Public key hash: %s', hash_fmt)
    Path(os.path.dirname(hash_path)).mkdir(parents=True, exist_ok=True)
    with open(hash_path, 'w', encoding='utf-8') as fp:
        fp.write(hash_fmt)
    logger.info("Saved public key hash to '%s'", hash_path)


def save_key(key, output, fmt, kid=None):
    """Saves the key to the file
    @param key: Private or public key object
    @param output: Key output path
    @param fmt: Defines key format PEM, DER, or JWK
    @param kid: Customer key ID
    """
    dirname = os.path.dirname(output)
    if dirname:
        os.makedirs(dirname, exist_ok=True)

    if fmt.upper() == 'PEM':
        _save_encoded(key, output, serialization.Encoding.PEM)
    elif fmt.upper() == 'DER':
        _save_encoded(key, output, serialization.Encoding.DER)
    elif fmt.upper() == 'JWK':
        _save_jwk(key, output, kid=kid)
    else:
        raise ValueError(f"Invalid key format '{fmt}'")


def _save_jwk(key, output, kid=None):
    dirname = os.path.dirname(output)
    if dirname:
        os.makedirs(dirname, exist_ok=True)

    if isinstance(key, rsa.RSAPrivateKey):
        jwk = RSAHandler.private_jwk(key, kid)
    elif isinstance(key, rsa.RSAPublicKey):
        jwk = RSAHandler.public_jwk(key, kid)
    else:
        raise TypeError(f"Invalid key type '{type(key)}'")

    with open(output, 'w', encoding='utf-8') as fp:
        fp.write(json.dumps(jwk, indent=4))


def _save_encoded(key, output, encoding):
    if isinstance(key, rsa.RSAPrivateKey):
        serialized = key.private_bytes(
            encoding=encoding,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption())
    elif isinstance(key, rsa.RSAPublicKey):
        serialized = key.public_bytes(
            encoding=encoding,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
    else:
        serialized = key.public_key().public_bytes(
            encoding=encoding,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    with open(output, 'wb') as fp:
        fp.write(serialized)
