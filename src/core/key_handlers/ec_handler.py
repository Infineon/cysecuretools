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
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes

from .pem_key import PemKey
from . import load_private_key, load_public_key


class ECHandler:
    """Handles EC signature and parse key data operations"""

    @staticmethod
    def populate_public_key(pub):
        """ Generates an EC public key from the public numbers """
        pubkey = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), pub)
        return pubkey

    @staticmethod
    def public_jwk(pubkey, kid=None):
        """ Gets EC public key is JSON format """
        alg, crv = ECHandler._jwk_alg(pubkey)
        key_json = {
            'alg': alg,
            'kty': 'EC',
            'crv': crv,
            'use': 'sig',
            'x': long_to_base64(pubkey.public_numbers().x).decode('utf-8'),
            'y': long_to_base64(pubkey.public_numbers().y).decode('utf-8')
        }
        if kid:
            key_json['kid'] = str(kid)
        return key_json

    @staticmethod
    def private_jwk(privkey, kid=None):
        """ Gets EC private key is JSON format """
        alg, crv = ECHandler._jwk_alg(privkey)
        pubkey = privkey.public_key()
        key_json = {
            'alg': alg,
            'kty': 'EC',
            'crv': crv,
            'use': 'sig',
            'x': long_to_base64(pubkey.public_numbers().x).decode('utf-8'),
            'y': long_to_base64(pubkey.public_numbers().y).decode('utf-8'),
            'd': long_to_base64(
                privkey.private_numbers().private_value).decode('utf-8'),
        }
        if kid:
            key_json['kid'] = str(kid)
        return key_json

    @staticmethod
    def _jwk_alg(privkey):
        if isinstance(privkey.curve, ec.SECP256R1):
            alg = 'ES256'
            crv = 'P-256'
        elif isinstance(privkey.curve, ec.SECP384R1):
            alg = 'ES384'
            crv = 'P-384'
        return alg, crv

    @staticmethod
    def key_hash(pubkey):
        """Encoding public key and return as byte sequence"""
        pub = pubkey.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        sha = hashlib.sha256()
        sha.update(pub)
        key_hash = sha.digest()
        return key_hash

    @staticmethod
    def is_private_key(key):
        """ Gets a value indicating whether the key is a private key """
        if isinstance(key, str):
            try:
                p_key = load_private_key(key)
            except ValueError:
                p_key = load_public_key(key)
        else:
            p_key = key

        if not isinstance(p_key, (ec.EllipticCurvePrivateKey,
                                  ec.EllipticCurvePublicKey)):
            raise ValueError("Using EC with unsupported key")

        return isinstance(p_key, ec.EllipticCurvePrivateKey)

    @staticmethod
    def sign(key_path, token):
        """ Signs a token using a key loaded from key_path """
        private_key = load_private_key(key_path)
        sig = private_key.sign(
            token,
            ec.ECDSA(hashes.SHA256())
        )
        return ECHandler.asn1_to_rs(sig)

    @staticmethod
    def jwk_to_pem(jwk_file, private_key=True):
        """Converts JWK file content to PEM format string"""
        pem = PemKey(jwk_file)
        pem_str = pem.to_str(private_key=private_key)
        return pem_str

    @staticmethod
    def asn1_to_rs(signature):
        """Converts ECDSA signature in ASN.1 format to R and S values"""
        r, s = decode_dss_signature(signature)
        return r.to_bytes(32, byteorder='big'), s.to_bytes(32, byteorder='big')
