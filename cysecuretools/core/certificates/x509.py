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
import logging
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cysecuretools.execute.enums import ProtectionState
from cysecuretools.core.strategy_context import Strategy
from cysecuretools.execute.provisioning_lib.cyprov_pem import PemKey
from cysecuretools.targets.common.silicon_data_parser import SiliconDataParser
from cysecuretools.execute.provision_device import read_silicon_data, read_public_key

HSM = os.path.join(os.path.dirname(__file__), '../../targets/common/prebuilt/hsm_private_key.json')
ROT_CMD_JWT = os.path.join(os.path.dirname(__file__), '../../targets/common/prebuilt/rot_cmd.jwt')
logger = logging.getLogger(__name__)


class X509Strategy(Strategy):
    def create_certificate(self, cert_name, cert_encoding, subject_name,
                           issuer_name,
                           country,
                           state,
                           organization,
                           public_key,
                           private_key,
                           not_valid_before=datetime.datetime.today(),
                           not_valid_after=datetime.datetime.today() + datetime.timedelta(days=365 * 5),
                           serial_number=x509.random_serial_number()):
        """
        Creates certificate in X.509 format.
        """
        # Check public key exists and convert to PEM if JWK passed
        if os.path.isfile(public_key):
            if public_key.lower().endswith('.json'):
                serialized_public = self.jwk_file_to_pem(public_key, private_key=False)
            else:
                serialized_public = self.load_pem(public_key)
        else:
            serialized_public = self.jwk_to_pem(public_key)

        # Check private key exists and convert to PEM if JWK passed
        if os.path.isfile(private_key):
            if private_key.lower().endswith('.json'):
                serialized_private = self.jwk_file_to_pem(private_key, private_key=True)
            else:
                serialized_private = self.load_pem(private_key)
        else:
            serialized_private = self.jwk_to_pem(private_key, private_key=True)

        # Create certificate
        public_key = serialization.load_pem_public_key(serialized_public, backend=default_backend())
        private_key = serialization.load_pem_private_key(serialized_private, password=None, backend=default_backend())

        builder = x509.CertificateBuilder()
        subj = [
            x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.SERIAL_NUMBER, str(serial_number))
        ]
        builder = builder.subject_name(x509.Name(subj))
        builder = builder.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)]))
        builder = builder.not_valid_before(not_valid_before)
        builder = builder.not_valid_after(not_valid_after)
        builder = builder.serial_number(serial_number)
        builder = builder.public_key(public_key)
        builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)

        certificate = builder.sign(private_key=private_key, algorithm=hashes.SHA256(), backend=default_backend())

        # Save certificate to the file
        with open(cert_name, 'wb') as f:
            f.write(certificate.public_bytes(cert_encoding))

    def default_certificate_data(self, tool, target, protection_state=ProtectionState.secure, probe_id=None):
        """
        Gets a dictionary with the default values.
        Default certificate requires device to be connected to read device public key and die ID,
        which are used as a certificate fields.
        :param tool: Programming tool to connect to device
        :param target: Target object
        :param protection_state: Device protection state
        :param probe_id: Probe ID. Need to be used if more than one device is connected to the computer.
        :return: Dictionary with the certificate fields.
        """
        # Read silicon data
        if tool.connect(target.name, probe_id=probe_id):
            data = read_silicon_data(tool, ROT_CMD_JWT, target.register_map, target.memory_map, protection_state)
            public_key = read_public_key(tool, target.register_map)
            tool.disconnect()
        else:
            logger.error('Failed to connect to device')
            return False

        # Get serial number
        silicon_data = SiliconDataParser(data)
        serial = silicon_data.get_serial()

        data = {
            'subject_name': 'Example Certificate',
            'country': 'US',
            'state': 'San Jose',
            'organization': 'Cypress Semiconductor',
            'issuer_name': 'Cypress Semiconductor',
            'public_key': public_key,
            'private_key': HSM,
            'serial_number': int(serial),
        }
        return data

    @staticmethod
    def load_pem(key_path):
        """
        Reads PEM file.
        :param key_path: Path to certificate.
        :return: File content as a string.
        """
        with open(key_path, 'rb') as f:
            key = f.read()
            return key

    @staticmethod
    def jwk_file_to_pem(jwk_file, private_key=True):
        """
        Converts JWK file content to PEM format string.
        """
        pem = PemKey(jwk_file)
        pem_str = pem.to_str(private_key=private_key)
        return pem_str

    @staticmethod
    def jwk_to_pem(jwk, private_key=True):
        """
        Converts JWK string to PEM format string.
        """
        pem = PemKey()
        pem.load_str(jwk)
        pem_str = pem.to_str(private_key=private_key)
        return pem_str
