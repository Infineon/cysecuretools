"""
Copyright 2021-2023 Cypress Semiconductor Corporation (an Infineon company)
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
import logging

from .debug_cert_parser_mxs40sv2 import DebugCertificateParserMXS40Sv2
from .....core.key_handlers.rsa_handler import RSAHandler

logger = logging.getLogger(__name__)


class DebugCertificateMXS40Sv2:
    """Create: debug, transit to RMA certificates"""

    def create(self, template, key, output, sign, **_):
        """
        Creates debug or RMA certificate binary from the
        certificate in JSON format
        :param template:
            Path to the certificate template in JSON format
        :param key:
            This key will be used to add public key to the certificate.
            If "non_signed" option was not specified this key will be also
            used to sign the certificate
        :param output:
            The certificate binary output file
        :param sign:
            Indicates that debug certificate will be signed
        """
        cert_fields = [
            'version',
            'device_id',
            'control_word',
            'die_id_min',
            'die_id_max',
            'public_key'
        ]
        cert_parser = DebugCertificateParserMXS40Sv2()
        template_data = cert_parser.load_template(template)
        json_cert = cert_parser.parse_template(template_data)
        json_cert = self.add_pub_key(json_cert, key)
        payload = b''.join([json_cert[field] for field in cert_fields])
        if sign:
            cert = self.sign_cert(payload, key)
        else:
            cert = payload
        self.save_cert(output, cert)
        logger.info('Debug certificate created (%s)', output)

    @staticmethod
    def add_pub_key(json_cert, priv_key):
        key = RSAHandler.convert_to_mbedtls(priv_key)
        json_cert['public_key'] = bytearray.fromhex(key)
        return json_cert

    @staticmethod
    def sign_cert(payload, priv_key):
        signature = RSAHandler.sign(priv_key, payload)
        cert = payload + signature

        return cert

    def add_signature(self, cert_file, signature_file, output):
        with open(cert_file, 'rb') as f:
            payload = f.read()
        with open(signature_file, 'rb') as f:
            signature = f.read()
        signed_cert = payload + signature
        self.save_cert(output, signed_cert)
        logger.info('Debug certificate has been signed (%s)', output)
        return signed_cert

    @staticmethod
    def save_cert(path, cert):
        with open(path, 'wb') as f:
            f.write(cert)
