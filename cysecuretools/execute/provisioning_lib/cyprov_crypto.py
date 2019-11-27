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
import json
import logging
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from jose import jws, jwt
from jose.backends import ECKey
from jose.constants import ALGORITHMS
from jose.utils import long_to_base64
from datetime import datetime

logger = logging.getLogger(__name__)


class Crypto:
    @staticmethod
    def create_jwk():
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()

        pub_key = {
            'alg': 'ES256',
            'kty': 'EC',
            'crv': 'P-256',
            'use': 'sig',
            'x': long_to_base64(
                    public_key.public_numbers().x,
                    size=32
                ).decode('utf-8'),
            'y': long_to_base64(
                    public_key.public_numbers().y,
                    size=32
                ).decode('utf-8'),
            }
        priv_key = dict(pub_key)
        priv_key['d'] = long_to_base64(
                            private_key.private_numbers().private_value,
                            size=32
                        ).decode('utf-8')

        logger.info("create_jwk()= " + json.dumps(pub_key, indent=4))
        return priv_key, pub_key

    @staticmethod
    def create_jwt(payload, ec_private_key):
        txt = jws.sign(payload, ec_private_key, algorithm=ALGORITHMS.ES256)

        logger.info("create_jwt()= " + txt)
        return txt

    @staticmethod
    def readable_jwt(txt):
        """
        Convert a JWT token in base64url into a readable dictionary object
        with decoded payload and header for printing and logging
        """
        signing_input, crypto_segment = txt.rsplit('.', 1)
        header, claims, signing_input, signature = jws._load(txt)
        readable = {
            'protected': header,
            'payload': json.loads(claims.decode('utf-8')),
            'signature': crypto_segment
        }

        # create readable timestamps for exp/iat claims
        payload = readable["payload"]
        if "iat" in payload:
            t = payload["iat"]
            if isinstance(t, int):
                t = datetime.fromtimestamp(t).isoformat(' ')
                payload["iat"] = t
        if "exp" in payload:
            t = payload["exp"]
            if isinstance(t, int):
                t = datetime.fromtimestamp(t).isoformat(' ')
                payload["exp"] = t

        logger.info(json.dumps(readable, indent=4, sort_keys=False))
        return readable

    @staticmethod
    def dump_jwt(txt, file_name):
        """
        Dumps a JWT dictionary object into a text file
        """
        with open(file_name, "w") as f:
            f.write(txt)
            f.close()

    @staticmethod
    def read_jwt(file_name):
        """
        Reads a JWT dictionary object from a text file
        """
        with open(file_name, "r") as f:
            txt = f.read()
            f.close()
        return txt

    @staticmethod
    def jwt_payload(txt):
        """
        Returns the payload of a JWT without validating it's signature.
        Sometimes used for tokens that contain a public key in its payload,
        where the signature proves possession of the corresponding private key.
        In that case, the payload is needed to obtain the public key
        with which to then validate the JWT.
        """
        return jwt.get_unverified_claims(txt)

    @staticmethod
    def validate_jwt(txt, ec_public_key):
        """
        Validates a signed JWT
        """
        try:
            jws.verify(txt, ec_public_key, ALGORITHMS.ES256, verify=True)
            logger.info('  JWT signature is valid')
            return True
        except Exception:
            logger.error('  JWT signature is not valid')
            return False

    @staticmethod
    def create_x509_cert(pub_key, priv_key, prod_id, die_id=None, dev_id=None):
        """
        TODO: create a X.509 certificate here certifying pub_key, signed with private_key
        """
        cert = "CertificateToBeDone(die_id={},dev_id={},prod_id={})".format(die_id, dev_id, prod_id)
        return cert
