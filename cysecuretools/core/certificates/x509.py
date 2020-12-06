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
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cysecuretools.execute.key_reader import load_key
from cysecuretools.core.enums import KeyId
from cysecuretools.core.strategy_context.cert_strategy_ctx \
    import CertificateStrategy
from cysecuretools.core.target_director import Target
from cysecuretools.execute.entrance_exam.exam_mxs40v1 \
    import EntranceExamMXS40v1
from cysecuretools.execute.provisioning_lib.cyprov_pem import PemKey
from cysecuretools.targets.common.silicon_data_parser import SiliconDataParser
from cysecuretools.execute.provision_device_mxs40v1 import read_silicon_data
from cysecuretools.execute.version_helper import VersionHelper

logger = logging.getLogger(__name__)


class X509CertificateStrategy(CertificateStrategy):
    def create_certificate(self, filename, encoding, overwrite=None, **kwargs):
        """
        Creates certificate in X.509 format.
        """
        filename = os.path.abspath(filename)

        if 'subject_name' in kwargs:
            subject_name = kwargs['subject_name']
        else:
            raise KeyError('Mandatory argument "subject_name" not specified')

        if 'issuer_name' in kwargs:
            issuer_name = kwargs['issuer_name']
        else:
            raise KeyError('Mandatory argument "issuer_name" not specified')

        if 'country' in kwargs:
            country = kwargs['country']
        else:
            raise KeyError('Mandatory argument "country" not specified')

        if 'state' in kwargs:
            state = kwargs['state']
        else:
            raise KeyError('Mandatory argument "state" not specified')

        if 'organization' in kwargs:
            organization = kwargs['organization']
        else:
            raise KeyError('Mandatory argument "organization" not specified')

        if 'public_key' in kwargs:
            public_key = kwargs['public_key']
        else:
            raise KeyError('Mandatory argument "public_key" not specified')

        if 'private_key' in kwargs:
            private_key = kwargs['private_key']
        else:
            raise KeyError('Mandatory argument "private_key" not specified')

        if 'not_valid_before' in kwargs:
            not_valid_before = kwargs['not_valid_before']
        else:
            not_valid_before = datetime.datetime.today()

        if 'not_valid_after' in kwargs:
            not_valid_after = kwargs['not_valid_after']
        else:
            not_valid_after = datetime.datetime.today() + datetime.timedelta(
                days=365 * 5)

        if 'serial_number' in kwargs:
            serial_number = kwargs['serial_number']
        else:
            serial_number = x509.random_serial_number()

        # Check public key exists and convert to PEM if JWK passed
        if os.path.isfile(str(public_key)):
            if public_key.lower().endswith('.json'):
                serialized_public = self.jwk_file_to_pem(public_key,
                                                         private_key=False)
            else:
                serialized_public = self.load_pem(public_key)
        else:
            serialized_public = self.jwk_to_pem(public_key)

        # Check private key exists and convert to PEM if JWK passed
        if os.path.isfile(str(private_key)):
            if private_key.lower().endswith('.json'):
                private_key, _ = load_key(private_key)
                serialized_private = self.jwk_file_to_pem(private_key,
                                                          private_key=True)
            else:
                serialized_private = self.load_pem(private_key)
        else:
            serialized_private = self.jwk_to_pem(private_key, private_key=True)

        # Create certificate
        public_key = serialization.load_pem_public_key(
            serialized_public, backend=default_backend())
        private_key = serialization.load_pem_private_key(
            serialized_private, password=None, backend=default_backend())

        builder = x509.CertificateBuilder()
        subj = [
            x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.SERIAL_NUMBER, str(serial_number))
        ]
        builder = builder.subject_name(x509.Name(subj))
        builder = builder.issuer_name(x509.Name([x509.NameAttribute(
            NameOID.COMMON_NAME, issuer_name)]))
        builder = builder.not_valid_before(not_valid_before)
        builder = builder.not_valid_after(not_valid_after)
        builder = builder.serial_number(serial_number)
        builder = builder.public_key(public_key)
        builder = builder.add_extension(x509.BasicConstraints(
            ca=False, path_length=None), critical=True)

        certificate = builder.sign(private_key=private_key,
                                   algorithm=hashes.SHA256(),
                                   backend=default_backend())

        # Save certificate to the file
        if overwrite is None:
            if os.path.isfile(filename):
                answer = input(f'File \'{filename}\' already exists. '
                               f'Overwrite? (y/n): ')
                if answer.lower() == 'y':
                    self._save_to_file(certificate, encoding, filename)
                else:
                    logger.info('Skip saving certificate to file')
            else:
                self._save_to_file(certificate, encoding, filename)
        elif overwrite:
            self._save_to_file(certificate, encoding, filename)
        else:
            logger.info('Skip saving certificate to file')
        return certificate

    @staticmethod
    def _save_to_file(certificate, encoding, filename):
        with open(filename, 'wb') as f:
            f.write(certificate.public_bytes(encoding))
        logger.info(f'Certificate created: {filename}')

    def default_certificate_data(self, tool, target: Target,
                                 entrance_exam: EntranceExamMXS40v1,
                                 probe_id=None):
        """
        Gets a dictionary with the default values.
        Default certificate requires device to be connected to read
        device public key and die ID, which are used as a certificate
        fields
        :param tool: Programming tool to connect to device
        :param target: Target object
        :param entrance_exam: The object used to execute entrance exam
               before provisioning.
        :param probe_id: Probe ID. Need to be used if more than one
               device is connected to the computer.
        :return: Dictionary with the certificate fields.
        """
        # Read silicon data
        if tool.connect(target.name, probe_id=probe_id, ap='sysap'):
            VersionHelper.log_version(tool, target)
            VersionHelper.verify_sfb_version(tool, target)
            data = read_silicon_data(tool, target)
            if data is None:
                logger.error('Failed to read silicon data')
                return None

            dev_pub_key = target.key_reader.read_public_key(tool, KeyId.DEVICE)
            tool.disconnect()
            if dev_pub_key is None:
                return None
        else:
            logger.error('Failed to connect to device')
            return None

        # Get HSM private key
        hsm_priv_key, hsm_pub_key = target.policy_parser.hsm_private_key()

        # Get serial number
        silicon_data = SiliconDataParser(data)
        serial = int(silicon_data.get_serial())
        if serial <= 0:
            max_serial = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
            logger.warning(f'Serial number created from die ID is {serial}, '
                           f'setting serial number to maximum available value '
                           f'{max_serial}')
            serial = max_serial

        data = {
            'subject_name': 'Example Certificate',
            'country': 'US',
            'state': 'San Jose',
            'organization': 'Cypress Semiconductor',
            'issuer_name': 'Cypress Semiconductor',
            'public_key': dev_pub_key,
            'private_key': hsm_priv_key,
            'serial_number': serial,
        }
        logger.debug(json.dumps(data))
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
        if type(jwk) is dict:
            jwk = json.dumps(jwk)
        pem.load_str(jwk)
        pem_str = pem.to_str(private_key=private_key)
        return pem_str
