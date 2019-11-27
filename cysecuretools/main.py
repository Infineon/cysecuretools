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
import sys
import logging
from cryptography.hazmat.primitives import serialization

import cysecuretools.execute.keygen as keygen
import cysecuretools.execute.provisioning_packet as provisioning_packet
from cysecuretools.execute.signtool import SignTool
from cysecuretools.targets.common.policy_parser import KeyType, ImageType
from cysecuretools.core.bootloader_provider import BootloaderProvider
from cysecuretools.execute.enums import ProtectionState, EntranceExamStatus, ProvisioningStatus
from cysecuretools.execute.programmer.programmer import ProgrammingTool
from cysecuretools.execute.entrance_exam import entrance_exam
from cysecuretools.execute.provision_device import provision_execution
from cysecuretools.execute.provisioning_lib.cyprov_pem import PemKey
from cysecuretools.core.target_director import TargetDirector
from cysecuretools.targets import target_map
from cysecuretools.core.logging_formatter import CustomFormatter
from cysecuretools.core.strategy_context import Context
from cysecuretools.core.certificates.x509 import X509Strategy

fmt = CustomFormatter()
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(fmt)
logger = logging.getLogger(__name__)
logger.root.addHandler(handler)
logger.root.setLevel(logging.INFO)
logging.getLogger('pyocd').setLevel(logging.WARNING)


class CySecureTools:
    """
    Class provides methods for creating keys, signing user application and device provisioning.
    """
    TOOLS_PATH = os.path.dirname(os.path.realpath(__file__))
    CY_AUTH_JWT = os.path.join(TOOLS_PATH, 'targets/common/prebuilt/cy_auth.jwt')
    OEM_STATE_JSON = os.path.join(TOOLS_PATH, 'targets/common/prebuilt/oem_state.json')
    HSM_STATE_JSON = os.path.join(TOOLS_PATH, 'targets/common/prebuilt/hsm_state.json')
    PROV_CMD_JWT = 'prov_cmd.jwt'
    PROGRAMMING_TOOL = 'pyocd'

    def __init__(self, target, policy=None):
        """
        Creates instance of the class
        :param target: Device manufacturing part number.
        :param policy: Provisioning policy file.
        """

        self.target_name = target.lower().strip()

        if policy is not None:
            self.policy = os.path.abspath(policy)
            if not os.path.exists(self.policy):
                raise ValueError(f'Cannot find file "{self.policy}"')

        self.target = self._get_target(self.target_name, policy)

        self.policy = self.target.policy
        self.memory_map = self.target.memory_map
        self.register_map = self.target.register_map
        self.policy_parser = self.target.policy_parser
        self.policy_validator = self.target.policy_validator
        self.policy_filter = self.target.policy_filter

        # Validate policy file
        if not self.policy_validator.validate():
            raise RuntimeError('Policy validation failed')

        self.bootloader_provider = BootloaderProvider(self.policy_parser, self.target_name)

    def create_keys(self, overwrite=None, out=None):
        """
        Creates keys specified in policy file for image signing and encryption.
        :param overwrite: Indicates whether overwrite keys in the output directory if they already exist.
        If the value is None, a prompt will ask whether to overwrite existing keys.
        :param out: Output directory for generated keys. By default keys location is as specified in the policy file.
        """
        # Find keys that have to be generated
        keys = self.policy_parser.get_keys(out)

        # Check whether keys exist
        if not overwrite:
            keys_exist = False
            for pair in keys:
                if pair.key_type is KeyType.signing:
                    keys_exist = keys_exist | os.path.isfile(pair.json_key_path)
                    keys_exist = keys_exist | os.path.isfile(pair.pem_key_path)
                elif pair.key_type is KeyType.encryption:
                    keys_exist = keys_exist | os.path.isfile(pair.json_key_path)
            if keys_exist:
                if overwrite is None:
                    answer = input('Keys directory is not empty. Overwrite? (y/n): ')
                    if answer.lower() != 'y':
                        return
                elif overwrite is False:
                    return

        # Generate keys
        for pair in keys:
            if pair.key_type is KeyType.signing:
                args = [
                    '--kid', pair.key_id,
                    '--jwk', pair.json_key_path,
                    '--pem-priv', pair.pem_key_path
                ]
            elif pair.key_type is KeyType.encryption:
                args = [
                    '--aes', pair.json_key_path
                ]
            else:
                continue

            logger.debug(f'Starting key generation with arguments: {args}')
            try:
                keygen.main(args)
            except SystemExit as e:
                if e.code != 0:
                    logger.error(f'An error occurred while running keygen with arguments: {args}')

    def sign_image(self, hex_file, image_id=4):
        """
        Signs firmware image with the certificates.
        :param hex_file: User application hex file.
        :param image_id: The ID of the firmware in policy file.
        :return: Signed (and encrypted if applicable) hex files path.
        """
        sign_tool = SignTool(self.policy, self.memory_map)
        result = sign_tool.sign_image(hex_file=hex_file, image_id=image_id)
        return result

    def create_provisioning_packet(self):
        """
        Creates JWT packet for provisioning device.
        :return: True if packet created successfully, otherwise False.
        """
        filtered_policy = self.policy_filter.filter_policy()

        # Get CyBootloader jwt
        cy_bootloader_jwt = self.bootloader_provider.get_jwt_path()
        if not os.path.isfile(cy_bootloader_jwt):
            logger.error(f'Cannot find bootloader file \'{cy_bootloader_jwt}\'')
            return False

        # Get certificates
        certs = self.policy_parser.get_chain_of_trust()

        # Get a key
        key = [x for x in self.policy_parser.get_keys() if x.image_type == ImageType.BOOT]
        if not key:
            logger.error('FAIL: Failed to create provisioning packet. Key not found')
            return False
        json_key_path = key[0].json_key_path
        if not os.path.isfile(json_key_path):
            logger.error(f'Cannot find the key \'{json_key_path}\'')
            return False

        packet_dir = self.policy_parser.get_provisioning_packet_dir()

        args = [
            '--policy', filtered_policy,
            '--cyboot', cy_bootloader_jwt,
            '--cyauth', self.CY_AUTH_JWT,
            '--out', packet_dir,
            '--ckey', json_key_path,
            '--oem', self.OEM_STATE_JSON,
            '--hsm', self.HSM_STATE_JSON,
        ]

        for cert in certs:
            args.append('--devcert')
            args.append(cert)

        logger.debug(f'Starting provisioning packet generation with the arguments: {args}')
        try:
            provisioning_packet.main(args)
        except SystemExit as e:
            if e.code != 0:
                logger.error(f'An error occurred while running provisioning packet generator with arguments: {args}')
            return e.code == 0

    def provision_device(self, probe_id=None, protection_state=ProtectionState.secure):
        """
        Executes device provisioning - the process of attaching a certificate to the device identity.
        :param probe_id: Probe serial number.
        :param protection_state: Expected target protection state. The argument is for Cypress internal use only.
        :return: Provisioning result. True if success, otherwise False.
        """
        pub_key = [x for x in self.policy_parser.get_keys() if x.key_type == KeyType.device_public]
        if not pub_key:
            logger.error('Failed to provision device. Device public key path not found')
            return False
        pub_key_json = pub_key[0].json_key_path
        pub_key_pem = pub_key[0].pem_key_path

        # Get CyBootloader hex
        cy_bootloader_hex = self.bootloader_provider.get_hex_path()
        if not os.path.isfile(cy_bootloader_hex):
            logger.error(f'Cannot find bootloader file \'{cy_bootloader_hex}\'')
            return False

        packet_dir = self.policy_parser.get_provisioning_packet_dir()
        prov_cmd = os.path.join(packet_dir, self.PROV_CMD_JWT)

        if not os.path.isfile(prov_cmd):
            logger.error(f'Cannot find provisioning packet file \'{prov_cmd}\'')
            return False

        tool = ProgrammingTool.create(self.PROGRAMMING_TOOL)
        if tool.connect(self.target_name, probe_id=probe_id):
            status = provision_execution(tool, pub_key_json, prov_cmd, cy_bootloader_hex, self.memory_map,
                                         self.register_map, ProtectionState(protection_state))
            tool.disconnect()

        if status == ProvisioningStatus.OK:
            # Read device public key from response file and save the key in pem format
            if os.path.exists(pub_key_json) and os.stat(pub_key_json).st_size > 0:
                pem = PemKey(pub_key_json)
                pem.save(pub_key_pem, private_key=False)
                return True
            else:
                logger.error('Failed to read device public key')
        elif status == ProvisioningStatus.FAIL:
            logger.error('Error occurred while provisioning device')

        return False

    def create_x509_certificate(self, cert_name='psoc_cert.pem', cert_encoding=serialization.Encoding.PEM,
                                probe_id=None, protection_state=ProtectionState.secure, **kwargs):
        """
        Creates certificate in X.509 format.
        :param cert_name: Filename
        :param cert_encoding: Certificate encoding
        :param probe_id: The probe ID. Used for default certificate generation
        :param protection_state: Device protection state. Used for default certificate generation
        :param kwargs: Dictionary with the certificate fields
        """
        # Create certificate
        context = Context(X509Strategy())
        if not kwargs:
            tool = ProgrammingTool.create(self.PROGRAMMING_TOOL)
            kwargs = context.default_certificate_data(tool, self.target, protection_state, probe_id)
        else:
            serial = kwargs.get('serial_number')
            public_key = kwargs.get('public_key')
            if not serial or not public_key:
                tool = ProgrammingTool.create(self.PROGRAMMING_TOOL)
                default = context.default_certificate_data(tool, self.target, protection_state, probe_id)
                if not serial:
                    kwargs['serial_number'] = default['serial_number']
                if not public_key:
                    kwargs['public_key'] = default['public_key']
        context.create_certificate(cert_name, cert_encoding, **kwargs)

    def entrance_exam(self):
        """
        Checks device life-cycle, Flashboot firmware and Flash state.
        :return True if the device is ready for provisioning, otherwise False.
        """
        status = False
        tool = ProgrammingTool.create(self.PROGRAMMING_TOOL)
        if tool.connect(self.target_name):
            status = entrance_exam(tool, self.register_map)
            tool.disconnect()

        return status == EntranceExamStatus.OK

    def flash_map(self, image_id=4):
        """
        Extracts information about slots from given policy.
        :param image_id: The ID of the firmware in policy file.
        :return: Address for specified image, size for specified image.
        """
        # Find keys that have to be generated
        address, size = self.policy_parser.get_image_data(image_id, ImageType.BOOT.name)

        if address is None or size is None:
            logger.error('Cannot find image address in the policy file')
            return None, None

        address = address + self.memory_map.MCUBOOT_HEADER_SIZE
        size = size - self.memory_map.MCUBOOT_HEADER_SIZE - self.memory_map.trailer_size()

        return address, size

    @staticmethod
    def _get_target(target_name, policy):
        director = TargetDirector()

        try:
            director.builder = target_map[target_name]()
        except KeyError:
            raise ValueError(f'Unknown target "{target_name}"')

        return director.get_target(policy, target_name)
