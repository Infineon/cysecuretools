"""
Copyright (c) 2022 Cypress Semiconductor Corporation

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
import hashlib
from jose.utils import long_to_base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


class ECHandler:

    @staticmethod
    def populate_public_key(pub):
        """ Generates an EC public key from the public numbers """
        pubkey = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), pub)
        return pubkey

    @staticmethod
    def public_jwk(pubkey, kid):
        """ Gets EC public key is JSON format """
        key_json = {
            'alg': 'ES256',
            'kty': 'EC',
            'crv': 'P-256',
            'use': 'sig',
            'kid': str(kid),
            'x': long_to_base64(
                pubkey.public_numbers().x, size=32).decode('utf-8'),
            'y': long_to_base64(
                pubkey.public_numbers().y, size=32).decode('utf-8')
        }
        return key_json

    @staticmethod
    def private_jwk(privkey, kid):
        """ Gets EC private key is JSON format """
        pubkey = privkey.public_key()
        key_json = {
            'alg': 'ES256',
            'kty': 'EC',
            'crv': 'P-256',
            'use': 'sig',
            'kid': str(kid),
            'x': long_to_base64(
                pubkey.public_numbers().x,
                size=32
            ).decode('utf-8'),
            'y': long_to_base64(
                pubkey.public_numbers().y,
                size=32
            ).decode('utf-8'),
            'd': long_to_base64(
                privkey.private_numbers().private_value,
                size=32
            ).decode('utf-8'),
        }
        return key_json

    @staticmethod
    def key_hash(pubkey):
        pub = pubkey.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        sha = hashlib.sha256()
        sha.update(pub)
        key_hash = sha.digest()
        return key_hash
