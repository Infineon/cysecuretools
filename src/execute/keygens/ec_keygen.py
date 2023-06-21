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
from typing import Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from ...core.json_helper import read_json
from ...core.key_handlers.ec_handler import ECHandler

logger = logging.getLogger(__name__)

CurveTypes = Union[ec.SECP256R1, ec.SECP384R1]


def generate_key(curve: CurveTypes, template=None):
    """Creates either private or public key using ECDSA algorithm
    @param curve: Elliptic curve
    @param template: Path to JSON file containing key public numbers
    @return: Private key, public key
    """
    if template:
        try:
            data = read_json(template)
            public_key = ECHandler.populate_public_key(
                bytes.fromhex(data['pub']))
            private_key = None
        except ValueError as e:
            raise ValueError(
                f'The template contains invalid data ({template})') from e
        except KeyError as e:
            raise KeyError(
                f'The template structure is invalid ({template})') from e
    else:
        if not isinstance(curve, (ec.SECP256R1, ec.SECP384R1)):
            raise TypeError(f"Unsupported curve '{type(curve)}'")

        private_key = ec.generate_private_key(curve, default_backend())
        public_key = private_key.public_key()

    return private_key, public_key


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

    if isinstance(key, ec.EllipticCurvePrivateKey):
        jwk = ECHandler.private_jwk(key, kid)
    elif isinstance(key, ec.EllipticCurvePublicKey):
        jwk = ECHandler.public_jwk(key, kid)
    else:
        raise TypeError(f"Invalid key type '{type(key)}'")

    with open(output, 'w', encoding='utf-8') as fp:
        fp.write(json.dumps(jwk, indent=4))


def _save_encoded(key, output, encoding):
    if isinstance(key, ec.EllipticCurvePrivateKey):
        serialized = key.private_bytes(
            encoding=encoding,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    elif isinstance(key, ec.EllipticCurvePublicKey):
        serialized = key.public_bytes(
            encoding=encoding,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    else:
        serialized = key.public_key().public_bytes(
            encoding=encoding,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    with open(output, 'wb') as fp:
        fp.write(serialized)
