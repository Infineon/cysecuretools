"""
Copyright (c) 2021 Cypress Semiconductor Corporation

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
import base64
import hashlib
from pathlib import Path
from collections import namedtuple
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import (
    load_der_public_key, load_der_private_key)
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric import rsa


class RSAHandler:

    @staticmethod
    def read_key(key_path):
        """ Reads key data without header and footer """
        with open(key_path, 'r', encoding='utf-8') as f:
            content = f.read()
            b64data = '\n'.join(content.splitlines()[1:-1])
        return b64data

    @staticmethod
    def decode(key_path):
        """ Decodes Base64 key into binary """
        b64data = RSAHandler.read_key(key_path)
        decoded = base64.b64decode(b64data)
        return decoded

    @staticmethod
    def is_private_key(key_path):
        """ Gets a value indicating whether the key is a private key """
        data = RSAHandler.decode(key_path)
        try:
            load_der_private_key(data, None, default_backend())
            is_private = True
        except ValueError:
            load_der_public_key(data, default_backend())
            is_private = False

        return is_private

    @staticmethod
    def public_numbers(key_path):
        """ Gets modulus, exponent, length of the RSA key """
        data = RSAHandler.decode(key_path)
        try:
            key = load_der_private_key(data, None, default_backend())
            pn = key.private_numbers().public_numbers
        except ValueError:
            key = load_der_public_key(data, default_backend())
            pn = key.public_numbers()

        PublicNumbers = namedtuple('PublicNumbers', 'modulus exponent length')

        return PublicNumbers(pn.n, pn.e, key.key_size)

    @staticmethod
    def sign(key_path, message):
        """ Signs a message using a key loaded from key_path """
        data = RSAHandler.decode(key_path)
        privkey = load_der_private_key(data, None, default_backend())
        digest = hashlib.sha256(message).digest()
        sig = privkey.sign(
                digest,
                padding.PSS(
                    mgf=padding.MGF1(SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
                utils.Prehashed(SHA256()))
        return sig

    @staticmethod
    def populate_public_key(exponent, modulus):
        """ Generates an RSA public key from the modulus and exponent """
        exponent = int(exponent, 16)
        modulus = int(modulus, 16)
        pubkey = rsa.RSAPublicNumbers(exponent, modulus).public_key(
            default_backend())
        return pubkey

    @staticmethod
    def save_public_key(pubkey, filename):
        """ Saves RSA public key to a PEM file """
        pem = pubkey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        Path(os.path.dirname(filename)).mkdir(parents=True, exist_ok=True)
        with open(filename, 'wb') as f:
            f.write(pem)
