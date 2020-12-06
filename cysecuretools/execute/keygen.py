"""
Copyright (c) 2019-2020 Cypress Semiconductor Corporation

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
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from jose.backends import ECKey
from jose.constants import ALGORITHMS
from jose.utils import long_to_base64

logger = logging.getLogger(__name__)


def generate_aes_key(aes_key_size=16, filename=None):
    """
    Creates a key using AES algorithm
    :param aes_key_size: Size of the AES key (in bytes)
    :param filename: The name of the file where to save the key.
           If None, do not save the key to a file
    :return:
    """
    key = os.urandom(aes_key_size)
    iv = os.urandom(16)
    key_str = key.hex() + '\n' + iv.hex()
    if filename:
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, 'w') as fp:
            fp.write(key_str)
        logger.info(f'Created key in {filename.name}')
    logger.debug(f'AES KEY: {key.hex()}')
    logger.debug(f'AES  IV: {iv.hex()}')
    return key_str


def generate_ecdsa_key(kid=6, jwkey=None, pem_priv=None, pem_pub=None):
    """
    Creates a key using ECDSA algorithm
    :param kid: Customer key ID. Key ID to define key slot number in
           the key storage. Key ID must be in range 6-10
    :param jwkey: Filename of the key in JWK format to create.
           If None, JWK file will not be created
    :param pem_priv: Filename of the private key in PEM format to
           create. If None, PEM file will not be created
    :param pem_pub: Filename of the public key in PEM format to
           create. If None, PEM file will not be created
    :return:
    """
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()

    key_json = {
        'alg': 'ES256',
        'kty': 'EC',
        'crv': 'P-256',
        'use': 'sig',
        'kid': str(kid),
        'x': long_to_base64(
                public_key.public_numbers().x,
                size=32
            ).decode('utf-8'),
        'y': long_to_base64(
                public_key.public_numbers().y,
                size=32
            ).decode('utf-8'),
        'd': long_to_base64(
                private_key.private_numbers().private_value,
                size=32
            ).decode('utf-8'),
        }
    key_str = json.dumps(key_json, indent=4)

    if jwkey:
        os.makedirs(os.path.dirname(jwkey), exist_ok=True)
        with open(jwkey, 'w') as fp:
            fp.write(key_str)
            logger.info(f'Created key in {jwkey}')

        key = ECKey(key_json, ALGORITHMS.ES256)
        if pem_priv:
            os.makedirs(os.path.dirname(pem_priv), exist_ok=True)
            with open(pem_priv, 'wb') as fp:
                fp.write(key.to_pem().strip())

        if pem_pub:
            os.makedirs(os.path.dirname(pem_pub), exist_ok=True)
            with open(pem_pub, 'wb') as fp:
                fp.write(key.public_key().to_pem().strip())

    return key_str


def generate_rsa_key(key_filename):
    """
    Creates a key using RSA algorithm
    """
    private_key = rsa.generate_private_key(65537, 2048, default_backend())
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption())

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)

    filename = "{0}_PRIV.pem".format(*os.path.splitext(key_filename))
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, 'wb') as fp:
        fp.write(private_pem)

    filename = "{0}_PUB.pem".format(*os.path.splitext(key_filename))
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, 'wb') as fp:
        fp.write(public_pem)

    return private_pem
