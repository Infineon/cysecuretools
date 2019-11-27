"""
Copyright (c) 2019 Cypress Semiconductor Corporation

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
import click
import json
import logging
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from jose.backends import ECKey
from jose.constants import ALGORITHMS
from jose.utils import long_to_base64

CUSTOMER_KEY_ID_MIN = 6
CUSTOMER_KEY_ID_MAX = 10

kid_help = 'Key ID to define key slot number in the key storage. Key ID must be in range {}.'
logger = logging.getLogger(__name__)

@click.command()
@click.option('-k', '--kid', 'kId',
              type=click.IntRange(CUSTOMER_KEY_ID_MIN, CUSTOMER_KEY_ID_MAX),
              default=CUSTOMER_KEY_ID_MIN,
              help=kid_help.format(str(list(range(CUSTOMER_KEY_ID_MIN, CUSTOMER_KEY_ID_MAX+1)))))
@click.option('--jwk', 'jwKey',
              type=click.File('w'),
              default='key.json',
              help='Name of the key in JWK format to create.')
@click.option('--pem-priv', 'pemPriv',
              type=click.File('wb'),
              default=None,
              help='Name of the private key in PEM format to create. If it is not given PEM file will not be created.')
@click.option('--pem-pub', 'pemPub',
              type=click.File('wb'),
              default=None,
              help='Name of the public key in PEM format to create. If it is not given PEM file will not be created.')
@click.option('--aes', 'aes',
              type=click.File('w'),
              default=None,
              help='Name of the AES-128 key to create. If it is given only AES key wiil be created and JWK will not.')
def main(kId, jwKey, pemPriv, pemPub, aes):
    if aes is None:
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()

        keyJson = {
            'alg': 'ES256',
            'kty': 'EC',
            'crv': 'P-256',
            'use': 'sig',
            'kid': str(kId),
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
        keyStr = json.dumps(keyJson, indent=4)

        os.makedirs(os.path.dirname(jwKey.name), exist_ok=True)
        jwKey.write(keyStr)

        key = ECKey(keyJson, ALGORITHMS.ES256)
        if pemPriv is not None:
            os.makedirs(os.path.dirname(pemPriv.name), exist_ok=True)
            pemPriv.write(key.to_pem().strip())

        if pemPub is not None:
            os.makedirs(os.path.dirname(pemPub.name), exist_ok=True)
            pemPub.write(key.public_key().to_pem().strip())

        logger.info(keyStr)
    else:
        key = os.urandom(16)
        iv = os.urandom(16)
        file = key.hex() + '\n' + iv.hex()
        os.makedirs(os.path.dirname(aes.name), exist_ok=True)
        aes.write(file)
        logger.info(f'AES-128 KEY: {key.hex()}')
        logger.info(f'AES-128 IV: {iv.hex()}')


if __name__ == "__main__":
    main()
