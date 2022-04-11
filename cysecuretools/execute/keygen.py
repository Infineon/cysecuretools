"""
Copyright (c) 2019-2021 Cypress Semiconductor Corporation

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
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from jose.backends import ECKey
from jose.constants import ALGORITHMS
from jose.utils import long_to_base64

from cysecuretools.core import strops
from cysecuretools.core.enums import KeyPair
from cysecuretools.core.json_helper import read_json
from cysecuretools.core.key_helper import calc_key_hash, AES_KEY_SIZE
from cysecuretools.core.key_handlers.ec_handler import ECHandler
from cysecuretools.core.key_handlers.rsa_handler import RSAHandler

logger = logging.getLogger(__name__)


def generate_aes_key(key_size=AES_KEY_SIZE, add_iv=True, fmt='bin', filename=None):
    """
    Creates an AES key
    :param key_size: Size of the AES key in bytes
    :param add_iv: Indicates whether to add IV to the generated key
    :param fmt: The format of the generated key - bin or hex
    :param filename: The name of the file where to save the key.
           If None, do not save the key to a file
    :return: Named tuple containing private and public key pair. The
             private key is either a bytes or string object containing
             random bytes suitable for cryptographic use. The type
             depends on the specified format. The public key is None
    """
    key = os.urandom(key_size)
    iv = os.urandom(AES_KEY_SIZE) if add_iv else None

    if fmt == 'hex':
        key = key.hex() + '\n' + iv.hex()
    elif fmt == 'bin':
        if iv:
            key = key + iv
    else:
        raise ValueError(f"Invalid format '{fmt}'")

    if filename is not None:
        dirname = os.path.dirname(filename)
        if dirname:
            os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, 'wb') as fp:
            fp.write(key)
        logger.info("Created key in '%s'", filename)
    return KeyPair(key, None)


def generate_ecdsa_key(kid=6, jwkey=None, pem_priv=None, pem_pub=None,
                       template=None):
    """Creates either private or public key using ECDSA algorithm
    :param kid: Customer key ID. Key ID to define key slot number in
           the key storage. Key ID must be in range 6-10
    :param jwkey: Filename of the key in JWK format to create.
           If None, JWK file will not be created
    :param pem_priv: Filename of the private key in PEM format to
           create. If None, PEM file will not be created
    :param pem_pub: Filename of the public key in PEM format to
           create. If None, PEM file will not be created
    :param template: JSON file containing public key numbers
    :return: A key in JWK format
    """
    if template:
        try:
            data = read_json(template)
            pubkey = ECHandler.populate_public_key(bytes.fromhex(data['pub']))
        except ValueError:
            logger.error('The template contains invalid data (%s)', template)
            return None
        except KeyError:
            logger.error('The template structure is invalid (%s)', template)
            return None
        key_json = ECHandler.public_jwk(pubkey, kid)
    else:
        key_json = _ecdsa_private_key(kid=kid)

    _save_ec_key(key_json, jwkey, pem_priv, pem_pub)

    return json.dumps(key_json, indent=4)


def _ecdsa_private_key(kid=6):
    """ Creates a private key using ECDSA algorithm """
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    key_json = ECHandler.private_jwk(private_key, kid)
    return key_json


def _save_ec_key(key_json, jwkey, pem_priv, pem_pub):
    if jwkey:
        os.makedirs(os.path.dirname(jwkey), exist_ok=True)
        with open(jwkey, 'w', encoding='utf-8') as fp:
            fp.write(json.dumps(key_json, indent=4))
            logger.info("Created a key in '%s'", jwkey)

        key = ECKey(key_json, ALGORITHMS.ES256)
        if pem_priv:
            os.makedirs(os.path.dirname(pem_priv), exist_ok=True)
            with open(pem_priv, 'wb') as fp:
                fp.write(key.to_pem().strip())

        if pem_pub:
            os.makedirs(os.path.dirname(pem_pub), exist_ok=True)
            with open(pem_pub, 'wb') as fp:
                fp.write(key.public_key().to_pem().strip())


def create_rsa_key(priv_key, pub_key, template=None, hash_path=None):
    """
    Either creates a new RSA key in PEM format or converts RSA key
    modulus and exponent to PEM if a template is specified
    @param priv_key: A path where to save private key
    @param pub_key: A path where to save public key
    @param template: A template containing RSA key modulus and exponent
    @param hash_path: A path where to save the public key hash
    :return: Named tuple containing private and public key pair
    """
    if template:
        data = read_json(template)
        try:
            key = RSAHandler.populate_public_key(
                data['exponent'], data['modulus'])
        except ValueError:
            logger.error('The template contains invalid data (%s)', template)
            return None
        except KeyError:
            logger.error('The template structure is invalid (%s)', template)
            return None
        RSAHandler.save_public_key(key, pub_key)
        logger.info("Created public key in '%s'", pub_key)
        keypair = KeyPair(None, key)
    else:
        keypair = _generate_rsa_key(priv_key, pub_key)

    if hash_path is not None:
        create_pubkey_hash(pub_key, hash_path)

    return keypair


def create_pubkey_hash(pubkey_path, hash_path):
    """
    Creates a file containing public key 16-bytes hash in the
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


def _generate_rsa_key(priv_key_path, pub_key_path):
    """ Creates a private-public key pair using RSA algorithm """
    private_key = rsa.generate_private_key(65537, 2048, default_backend())
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption())

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)

    key_dir = os.path.dirname(priv_key_path)
    if key_dir:
        os.makedirs(key_dir, exist_ok=True)
    with open(priv_key_path, 'wb') as fp:
        fp.write(private_pem)
        logger.info("Created private key '%s'", priv_key_path)

    key_dir = os.path.dirname(pub_key_path)
    if key_dir:
        os.makedirs(key_dir, exist_ok=True)
    with open(pub_key_path, 'wb') as fp:
        fp.write(public_pem)
        logger.info("Created public key '%s'", pub_key_path)

    return KeyPair(private_key, public_key)
