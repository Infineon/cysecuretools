"""
Copyright (c) 2019-2021 Cypress Semiconductor Corporation

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
import os
import sys
from cryptography.hazmat.primitives import serialization

import cysecuretools.execute.jwt as jwt
import cysecuretools.execute.keygen as keygen
from cysecuretools.core.certificates.x509 import X509CertificateStrategy
from cysecuretools.core.logging_formatter import CustomFormatter
from cysecuretools.core.strategy_context.cert_strategy_ctx \
    import CertificateContext
from cysecuretools.core.strategy_context.encrypted_programming_strategy_ctx \
    import EncryptedProgrammingContext
from cysecuretools.core.strategy_context.prov_packet_strategy_ctx \
    import ProvisioningPacketCtx
from cysecuretools.core.strategy_context.provisioning_strategy_ctx \
    import ProvisioningContext
from cysecuretools.core.target_director import TargetDirector
from cysecuretools.core.project import ProjectInitializer
from cysecuretools.execute.encrypted_programming.aes_header_strategy \
    import AesHeaderStrategy
from cysecuretools.core.enums import (EntranceExamStatus, ValidationStatus,
                                      ProvisioningStatus, KeyAlgorithm,
                                      ImageType, KeyType)
from cysecuretools.core.signtool_base import SignTool
from cysecuretools.execute.image_cert import ImageCertificate
from cysecuretools.execute.key_reader import get_aes_key
from cysecuretools.execute.programmer.programmer import ProgrammingTool
from .targets import print_targets, get_target_builder, is_psoc64, is_mxs40sv2
from cysecuretools.core.logging_configurator import LoggingConfigurator
from .core.ocd_settings import OcdSettings
from .core.connect_helper import ConnectHelper

# Initialize logger
logging.root.setLevel(logging.DEBUG)
fmt = CustomFormatter()
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(fmt)
console_handler.setLevel(logging.INFO)
logger = logging.getLogger(__name__)
logger.root.addHandler(console_handler)


class CySecureTools:
    """
    Class provides methods for creating keys, signing user
    application and device provisioning.
    """

    def __init__(self, target=None, policy=None, log_file=True,
                 skip_prompts=False, skip_validation=False):
        """
        Creates instance of the class
        :param target: Device manufacturing part number
        :param policy: Provisioning policy file
        :param log_file: Indicates whether to write log into a file
        :param skip_prompts: Indicates whether to skip user interactive
               prompts
        :param skip_validation: Indicates whether to skip policy validation
        """
        self.skip_validation = skip_validation

        if log_file:
            LoggingConfigurator.add_file_logging()

        settings = OcdSettings()
        self.ocd_name = settings.ocd_name
        self.tool = ProgrammingTool.create(self.ocd_name, settings.ocd_path)

        self.skip_prompts = skip_prompts
        if self.skip_prompts:
            self.tool.wait_for_target = False

        self.inited = True
        if not target:
            self.inited = False
            self.target = None
            return

        self.target_name = target.lower().strip()

        cwd = None
        self.policy = None
        if policy is not None:
            self.policy = os.path.abspath(policy)
        if ProjectInitializer.is_project():
            if policy is None:
                self.policy = ProjectInitializer.get_default_policy()
            cwd = os.getcwd()

        self.target = self._get_target(self.target_name, self.policy, cwd)
        self.policy = self.target.policy
        self.policy_parser = self.target.policy_parser
        self.version_provider = self.target.version_provider

    def create_keys(self, overwrite=None, out=None, kid=None,
                    user_key_alg=KeyAlgorithm.EC, **kwargs):
        """
        Creates keys specified in policy file for image signing
        :param overwrite: Indicates whether overwrite keys in the
               output directory if they already exist. If the value
               is None, a prompt will ask whether to overwrite
               existing keys.
        :param out: Output directory for generated keys. By default
               keys location is as specified in the policy file.
        :param kid: Key ID. Specified to generate the key with
               specific ID only.
        :param user_key_alg: User key algorithm
        :return: True if key(s) created successfully, otherwise False.
        """
        if not self._validate_policy(['pre_build', 'dap_disabling']):
            return False

        # Define key algorithm
        if user_key_alg is None:
            user_key_alg = self.target.key_algorithms[0]
        else:
            if user_key_alg not in self.target.key_algorithms:
                valid_algorithms = ",".join(self.target.key_algorithms)
                logger.error(
                    "Invalid key algorithm '%s'. Supported key algorithms for "
                    "the selected target: %s", user_key_alg, valid_algorithms)
                return False

        # Find key paths that have to be generated
        keys = self.target.key_source.get_keys(key_path=out, key_id=kid,
                                               key_alg=user_key_alg)

        # Check whether keys exist
        if not overwrite:
            keys_exist = False
            for pair in keys:
                if pair.key_type is KeyType.user:
                    if pair.image_type == ImageType.BOOTLOADER:
                        continue
                    if pair.json_key is not None:
                        keys_exist = keys_exist | os.path.isfile(pair.json_key)
                    if pair.pem_key is not None:
                        keys_exist = keys_exist | os.path.isfile(pair.pem_key)
                    if pair.pem_key_pub is not None:
                        keys_exist = keys_exist | os.path.isfile(pair.pem_key_pub)
            if keys_exist:
                if overwrite is None:
                    if self.skip_prompts:
                        logger.info('Keys already exist. Skip creating keys')
                        return True
                    else:
                        answer = input('Keys directory is not empty. '
                                       'Overwrite? (y/n): ')
                        while answer.lower() != 'y' and answer.lower() != 'n':
                            answer = input("Please use 'y' or 'n'")
                        if answer.lower() != 'y':
                            logger.info('Terminated by user')
                            return True
                elif overwrite is False:
                    logger.info('Keys already exist. Skip creating keys')
                    return True

        # Generate keys
        result = True
        seen = []
        for pair in keys:
            if pair.image_type == ImageType.BOOTLOADER:
                continue
            if pair.key_type is KeyType.user:
                if {pair.key_id, pair.json_key} in seen or \
                        (kid is not None and pair.key_id != kid):
                    continue
                else:
                    if pair.key_id is not None and pair.json_key is not None:
                        seen.append({pair.key_id, pair.json_key})

                keypair = None
                if user_key_alg == KeyAlgorithm.EC:
                    keypair = keygen.generate_ecdsa_key(
                        pair.key_id, pair.json_key, pair.pem_key, **kwargs)
                elif user_key_alg == KeyAlgorithm.RSA:
                    keypair = keygen.create_rsa_key(
                        pair.pem_key, pair.pem_key_pub, **kwargs)
                elif user_key_alg == KeyAlgorithm.AES:
                    keypair = keygen.generate_aes_key(
                        filename=pair.pem_key, add_iv=False)
                result &= keypair is not None
            else:
                continue

        return result

    def power_on(self, voltage=2500):
        """
        Turns on the power and sets voltage.
        :param voltage: Voltage level.
        :return: True if the target power was successfully set,
        False otherwise.
        """
        return ConnectHelper.power_on(self.tool, self.target, voltage)

    def power_off(self):
        """
        Turns on the target and sets voltage.
        :return: True if the target power was successfully powered off,
        False otherwise.
        """
        return ConnectHelper.power_off(self.tool, self.target)

    def image_metadata(self, image, **kwargs):
        """
        Creates a complete MCUboot format image.
        :param image: User application file.
        :return: Extended (and encrypted if applicable) file path.
        """
        return self.target.sign_tool.add_metadata(image, **kwargs)

    def extract_payload(self, image, output, **kwargs):
        """
        Creates a complete MCUboot format image
        :param image: User application file
        :param output: A file where to save the payload
        :return: Path to
        """
        self.target.sign_tool.extract_payload(image, output, **kwargs)

    @staticmethod
    def bin2hex(image, output, offset=0):
        """Converts bin to hex
        :param image: Input binary file
        :param output: Output hex file
        :param offset: Starting address offset for loading bin
        """
        result = SignTool.bin2hex(image, output, offset=offset)
        if result:
            logger.info("Saved bin file to '%s'", output)
        return result

    def add_signature(self, image, signature, output):
        """
        Adds signature to MCUboot format image
        :param image: User application file
        :param signature: Path to the binary file containing signature
        :param output: Path where to save the signed image
        :return: Path to
        """
        self.target.sign_tool.add_signature(image, signature, output)

    def sign_image(self, image, image_id=1, **kwargs):
        """
        Signs firmware image with the key specified in the policy file.
        :param image: User application file.
        :param image_id: The ID of the image in the policy file.
        :return: Signed (and encrypted if applicable) hex file path.
        """
        if not self._validate_policy(['pre_build', 'dap_disabling']):
            return None
        result = self.target.sign_tool.sign_image(image, image_id=image_id,
                                                  **kwargs)
        return result

    def extend_image(self, image, **kwargs):
        """
        Extends firmware image with the TLVs.
        :param image: User application file.
        :return: Extended (and encrypted if applicable) file path.
        """
        if not is_mxs40sv2(self.target_name):
            raise ValueError(
                'Method is not compatible with the selected target')
        result = self.target.sign_tool.extend_image(image, **kwargs)
        return result

    def create_provisioning_packet(self, **kwargs):
        """
        Creates JWT packet for provisioning device.
        :return: True if packet created successfully, otherwise False.
        """
        if not self._validate_policy():
            return False
        ctx = ProvisioningPacketCtx(self.target.provisioning_packet_strategy)
        return ctx.create(self.target, **kwargs)

    def prov_packets_to_policy(self, packets, output):
        """
        Reverse conversion of the provisioning packet to the policy file
        @param packets: List of the binary packets paths
        @param output: The file where to save the policy
        @return: True if packet converted successfully, otherwise False.
        """
        if not is_mxs40sv2(self.target_name):
            raise ValueError(
                'Method is not compatible with the selected target')
        ctx = ProvisioningPacketCtx(self.target.provisioning_packet_strategy)
        return ctx.reverse_conversion(self.target, packets, output)

    def provision_device(self, probe_id=None, ap='cm4', **kwargs):
        """
        Executes device provisioning - the process of creating device
        identity, attaching policy and bootloader.
        :param probe_id: Probe serial number.
        :param ap: The access port used for provisioning
        :return: Provisioning result. True if success, otherwise False.
        """
        if not self._validate_policy():
            return False

        # Get bootloader program file
        if self.target.bootloader_provider is None:
            bootloader = None
        else:
            bootloader = self.target.bootloader_provider.hex_path()
            if not os.path.isfile(bootloader):
                logger.error("Cannot find bootloader file '%s'", bootloader)
                return False

        if ConnectHelper.connect(self.tool, self.target, probe_id=probe_id,
                                 ap=ap):
            self.version_provider.log_version(self.tool)
            if not self.version_provider.verify_fw_version(self.tool):
                return False

            context = ProvisioningContext(self.target.provisioning_strategy)
            status = context.provision(
                self.tool, self.target,
                bootloader=bootloader,
                probe_id=self.tool.probe_id, ap=ap, skip_prompts=self.skip_prompts,
                **kwargs)
            ConnectHelper.disconnect(self.tool)
        else:
            status = ProvisioningStatus.FAIL

        if status == ProvisioningStatus.FAIL:
            logger.error('Error occurred while provisioning device')

        return status == ProvisioningStatus.OK

    def re_provision_device(self, probe_id=None, ap='sysap', **kwargs):
        """
        Executes device re-provisioning
        :param probe_id: Probe serial number.
        :param ap: The access port used for re-provisioning
        :return: Provisioning result. True if success, otherwise False.
        """
        if not self._validate_policy():
            return False

        # Get bootloader program file
        bootloader = None
        if not kwargs.get('skip_bootloader', False):
            if self.target.bootloader_provider is not None:
                bootloader = self.target.bootloader_provider.hex_path()
                if not os.path.isfile(bootloader):
                    logger.error(
                        "Cannot find bootloader file '%s'", bootloader)
                    return False

        context = ProvisioningContext(self.target.provisioning_strategy)

        if ConnectHelper.connect(self.tool, self.target, probe_id=probe_id,
                                 ap=ap):

            self.version_provider.log_version(self.tool)
            if not self.version_provider.verify_fw_version(self.tool):
                return False

            status = context.re_provision(
                self.tool, self.target,
                bootloader=bootloader, probe_id=self.tool.probe_id, ap=ap, **kwargs)
            ConnectHelper.disconnect(self.tool)
        else:
            status = ProvisioningStatus.FAIL

        if status == ProvisioningStatus.FAIL:
            logger.error('Error occurred while reprovisioning device')

        return status == ProvisioningStatus.OK

    def create_x509_certificate(self, cert_name='psoc_cert.pem',
                                cert_encoding=serialization.Encoding.PEM,
                                probe_id=None, **kwargs):
        """
        Creates certificate in X.509 format.
        :param cert_name: Filename
        :param cert_encoding: Certificate encoding
        :param probe_id: The probe ID. Used for default certificate generation
        :param kwargs: Dictionary with the certificate fields
        :return The certificate object.
        """
        if not is_psoc64(self.target_name):
            raise ValueError(
                'Method is not compatible with the selected target')

        context = CertificateContext(X509CertificateStrategy())

        expected_fields = ['subject_name', 'country', 'state', 'organization',
                           'issuer_name', 'private_key']
        all_fields_present = all(
            k in kwargs and kwargs[k] is not None for k in expected_fields)
        serial = kwargs.get('serial_number')
        public_key = kwargs.get('public_key')

        if not all_fields_present or not serial or not public_key:
            if not self._validate_policy(['pre_build', 'dap_disabling']):
                return None
            logger.info('Get default certificate data')

            default = context.default_certificate_data(self.tool, self.target,
                                                       probe_id)
            if not default:
                logger.error('Failed to get data for the certificate')
                return None

            for field in expected_fields:
                if field not in kwargs or kwargs[field] is None:
                    kwargs[field] = default[field]

            if not serial:
                kwargs['serial_number'] = default['serial_number']
            if not public_key:
                kwargs['public_key'] = default['public_key']

        logger.info('Start creating certificate')
        overwrite = True if self.skip_prompts else None
        return context.create_certificate(cert_name, cert_encoding,
                                          overwrite=overwrite, **kwargs)

    def entrance_exam(self, probe_id=None, ap='cm4', erase_flash=False):
        """
        Checks device life-cycle, Flashboot firmware and Flash state.
        :param probe_id: Probe serial number.
        :param ap: The access port used for entrance exam
        :param erase_flash: Indicates whether to erase flash before the
               entrance exam
        :return True if the device is ready for provisioning,
                otherwise False.
        """
        if not is_psoc64(self.target_name):
            raise ValueError(
                'Method is not compatible with the selected target')

        if not self._validate_policy(['pre_build', 'dap_disabling']):
            return False

        status = False
        if ConnectHelper.connect(self.tool, self.target, probe_id=probe_id,
                                 ap=ap, reset_and_halt=True):

            self.version_provider.log_version(self.tool)
            if not self.version_provider.verify_fw_version(self.tool):
                return False

            context = ProvisioningContext(self.target.provisioning_strategy)
            if erase_flash:
                context.erase_flash(self.tool, self.target)
            status = self.target.entrance_exam.execute(self.tool)
            if status == EntranceExamStatus.FLASH_NOT_EMPTY:
                if self.skip_prompts:
                    logger.error('Entrance exam failed. '
                                 'User firmware running on chip detected')
                    return ProvisioningStatus.FAIL
                else:
                    answer = input(
                        'Erase user firmware running on chip? (y/n): ')
                    if answer.lower() == 'y':
                        context.erase_flash(self.tool, self.target)
            ConnectHelper.disconnect(self.tool)
        return status == EntranceExamStatus.OK

    def flash_map(self, image_id=1, image_type=ImageType.BOOT.name):
        """
        Extracts information about slots from given policy.
        :param image_id: The ID of the firmware in policy file.
        :param image_type: The image type - BOOT or UPGRADE.
        :return: Address for specified image, size for specified image.
        """
        if not is_psoc64(self.target_name):
            raise ValueError(
                'Method is not compatible with the selected target')

        address, size = None, None

        if not self._validate_policy(['pre_build', 'dap_disabling']):
            return address, size

        # Find keys that have to be generated
        data = self.policy_parser.get_image_data(image_type.upper(), image_id)
        if len(data) > 0:
            address, size = data[0]
        else:
            logger.error("Cannot find image with id %s and type '%s' in "
                         "the policy file", image_id, image_type)
        return address, size

    def create_image_certificate(self, image, key, output, version, image_id=0,
                                 exp_date_str='Jan 1 2031'):
        """
        Creates Bootloader image certificate.
        :param image: Image path.
        :param key: Key path.
        :param output: Output certificate file path.
        :param version: Image version.
        :param image_id: Image ID.
        :param exp_date_str: Certificate expiration date.
        :return: True if certificate created successfully, otherwise False.
        """
        if not is_psoc64(self.target_name):
            raise ValueError(
                'Method is not compatible with the selected target')

        if key is None:
            if not self._validate_policy(['pre_build', 'dap_disabling']):
                return False
            policy_keys = self.policy_parser.get_keys(
                image_type=ImageType.BOOTLOADER)
            if not policy_keys:
                logger.error('Failed to create image certificate. Key not '
                             'specified neither in policy nor as an argument')
                return False
            key = os.path.abspath(policy_keys[0].json_key)

        if not os.path.isfile(key):
            logger.error("Cannot find the key '%s'", key)
            return False

        image = os.path.abspath(image)
        output = os.path.abspath(output)
        image_cert = ImageCertificate(image, key, output, version, image_id,
                                      exp_date_str)
        image_cert.create()
        logger.info('Image certificate was created successfully')
        logger.info('Image version: %s', version)
        logger.info('Certificate: %s', output)
        return True

    def encrypt_image(self,
                      image,
                      host_key_id,
                      dev_key_id,
                      algorithm='ECC',
                      key_length=16,
                      encrypted_image='encrypted_image.txt',
                      padding_value=0,
                      probe_id=None):
        """
        Creates encrypted image for encrypted programming.
        :param image: The image to encrypt.
        :param host_key_id: Host private key ID (4 - HSM, 5 - OEM).
        :param dev_key_id: Device public key ID (1 - device, 12 - group).
        :param algorithm: Asymmetric algorithm for key derivation function.
        :param key_length: Derived key length.
        :param encrypted_image: Output file of encrypted image for
               encrypted programming.
        :param padding_value: Value for image padding.
        :param probe_id: Probe serial number.
               Used to read device public key from device.
        """
        if not is_psoc64(self.target_name):
            raise ValueError(
                'Method is not compatible with the selected target')

        if not self._validate_policy(['dap_disabling']):
            return False

        # Get host private key
        logger.debug('Host key id = %d', host_key_id)
        try:
            _, host_key_pem = self.policy_parser.get_private_key(host_key_id)
        except ValueError as ex:
            logger.error(ex)
            return False

        # Get public key
        pub_key_pem = None
        logger.debug('Device key id = %d', dev_key_id)

        connected = ConnectHelper.connect(self.tool, self.target, ap='sysap',
                                          probe_id=probe_id, blocking=False)
        if connected:
            self.version_provider.log_version(self.tool)
            self.version_provider.verify_fw_version(self.tool)

            logger.info('Read device public key from device')
            pub_key_pem = self.target.key_reader.read_public_key(
                self.tool, dev_key_id, 'pem')
            ConnectHelper.disconnect(self.tool)

        if not connected or not pub_key_pem:
            logger.info('Read public key %d from file', dev_key_id)
            try:
                _, pub_key_pem = self.policy_parser.get_public_key(
                    dev_key_id, pre_build=True)
            except ValueError as ex:
                logger.error(ex)
                return False

        # Create AES key
        key_to_encrypt = get_aes_key(key_length, 'hex')

        # Create encrypted image
        context = EncryptedProgrammingContext(AesHeaderStrategy)
        aes_header = context.create_header(
            host_key_pem, pub_key_pem, key_to_encrypt, algorithm, key_length)
        context.create_encrypted_image(
            image, key_to_encrypt, aes_header, host_key_id, dev_key_id,
            encrypted_image, padding_value)
        return True

    def encrypted_programming(self, encrypted_image, probe_id=None):
        """
        Programs encrypted image.
        :param encrypted_image: The encrypted image to program.
        :param probe_id: Probe serial number.
        :return: True if the image programmed successfully, otherwise False.
        """
        if not is_psoc64(self.target_name):
            raise ValueError(
                'Method is not compatible with the selected target')

        result = False
        context = EncryptedProgrammingContext(AesHeaderStrategy)
        if ConnectHelper.connect(self.tool, self.target, probe_id=probe_id,
                                 ap='sysap'):

            self.version_provider.log_version(self.tool)
            self.version_provider.verify_fw_version(self.tool)

            result = context.program(self.tool, self.target, encrypted_image)
            ConnectHelper.disconnect(self.tool)
        return result

    def read_public_key(self, key_id, key_fmt, out_file=None, probe_id=None):
        """
        Reads public key from device and saves it to the file
        :param key_id: Key ID to read
        :param key_fmt: Key format (jwk or pem)
        :param out_file: Filename where to save the key
        :param probe_id: Probe serial number
        :return: Key if it read successfully, otherwise None
        """
        if not is_psoc64(self.target_name):
            raise ValueError(
                'Method is not compatible with the selected target')

        key = None
        if ConnectHelper.connect(self.tool, self.target, probe_id=probe_id,
                                 ap='sysap'):

            self.version_provider.log_version(self.tool)
            self.version_provider.verify_fw_version(self.tool)

            try:
                key = self.target.key_reader.read_public_key(
                    self.tool, key_id, key_fmt)
                if key is None:
                    logger.error('Cannot read public key (key_id=%d)', key_id)
                elif out_file:
                    out_file = os.path.abspath(out_file)
                    with open(out_file, 'w', encoding='utf-8') as fp:
                        if key_fmt == 'jwk':
                            json.dump(key, fp, indent=4)
                        elif key_fmt == 'pem':
                            fp.write(key.decode('utf-8'))
                        else:
                            fp.write(str(key))
                    logger.info('Key saved: %s', out_file)
                ConnectHelper.disconnect(self.tool)
            except (ValueError, FileNotFoundError) as e:
                logger.error(e)
        return key

    def read_die_id(self, probe_id=None, ap='sysap'):
        """
        Reads die ID
        :param probe_id: Probe serial number
        :param ap: The access port used to read the data
        :return: Die ID if success, otherwise None
        """
        die_id = None
        if ConnectHelper.connect(self.tool, self.target, probe_id=probe_id,
                                 ap=ap):
            self.version_provider.log_version(self.tool)
            self.version_provider.verify_fw_version(self.tool)

            die_id = self.target.silicon_data_reader.read_die_id(self.tool)
            ConnectHelper.disconnect(self.tool)
        return die_id

    def get_device_lifecycle(self, probe_id=None, ap='sysap'):
        """
        Reads device lifecycle stage
        :param probe_id: Probe serial number
        :param ap: The access port used to read the data
        :return: Lifecycle stage name if success, otherwise None
        """
        if not is_mxs40sv2(self.target_name):
            raise ValueError(
                'Method is not compatible with the selected target')

        lifecycle = None
        if ConnectHelper.connect(
                self.tool, self.target, probe_id=probe_id, ap=ap):
            lifecycle = self.version_provider.get_lifecycle_stage(self.tool)
            ConnectHelper.disconnect(self.tool)
        return lifecycle

    def get_voltage_volts(self, probe_id=None, ap='sysap'):
        """
        Reads device voltage
        :param probe_id: Probe serial number
        :param ap: The access port used to read the data
        :return: Lifecycle stage name if success, otherwise None
        """
        if not is_mxs40sv2(self.target_name):
            raise ValueError(
                'Method is not compatible with the selected target')
        voltage = None
        if ConnectHelper.connect(
                self.tool, self.target, probe_id=probe_id, ap=ap):
            try:
                voltage = self.target.voltage_tool.get_voltage(self.tool)
            except RuntimeError as e:
                logger.error(e)
            ConnectHelper.disconnect(self.tool)
        return voltage

    def sign_json(self, json_file, priv_key_id, output_file):
        """
        Signs JSON file with the private key
        :param json_file: JSON file to be signed
        :param priv_key_id: Private Key ID to sign the file
               with (1 - DEVICE, 4 - HSM, 5 - OEM, 12 - GROUP
        :param output_file: Filename where to save the JWT. If not
               specified, the input file name with "jwt" extension
               will be used
        :return: The JWT
        """
        logger.info('Signing file %s', os.path.abspath(json_file))
        if not self._validate_policy(['dap_disabling']):
            return False

        logger.debug('Private key id = %d', priv_key_id)
        try:
            jwk, _ = self.policy_parser.get_private_key(priv_key_id)
        except ValueError as ex:
            logger.error(ex)
            return None

        if not output_file:
            output_file = '{0}.jwt'.format(os.path.splitext(json_file)[0])
        output_file = os.path.abspath(output_file)
        jwt_text = jwt.json_to_jwt(json_file, jwk, output_file)
        logger.info('Created file %s', output_file)
        return jwt_text

    def print_version(self, probe_id=None, ap='sysap', **kwargs):
        """
        Outputs CyBootloader version bundled with the package. If
        device is connected outputs CyBootloader and Secure Flash
        Boot version programmed into device
        :param probe_id: Probe serial number
        :param ap: The access port used for to read CyBootloader and
               Secure Flash Boot version from device
        """
        connected = ConnectHelper.connect(self.tool, self.target, ap=ap,
                                          probe_id=probe_id, blocking=False,
                                          suppress_errors=True)
        self.version_provider.print_version(**kwargs)
        if connected:
            self.version_provider.print_fw_version(self.tool)
            self.version_provider.verify_fw_version(self.tool)
            ConnectHelper.disconnect(self.tool)

    def init(self, **kwargs):
        """
        Initializes new project
        """
        cwd = os.getcwd()
        overwrite = True if self.skip_prompts else None
        self.target.project_initializer.init(cwd, overwrite, **kwargs)

    def get_probe_list(self):
        """
        Gets list of all connected probes
        """
        return self.tool.get_probe_list()

    def get_device_info(self, probe_id=None, ap='sysap'):
        """
        Gets device information - silicon ID, silicon revision, family ID
        """
        connected = ConnectHelper.connect(self.tool, self.target,
                                          probe_id=probe_id, ap=ap)
        info = None
        if connected:
            info = self.target.silicon_data_reader.read_device_info(self.tool)
            ConnectHelper.disconnect(self.tool)
        return info

    def load_and_run_app(self, config, probe_id=None, ap='sysap'):
        """
        Loads and runs RAM application
        :param config: Path to the application configuration file
        :param probe_id: Probe serial number
        :param ap: The access port used to load the application
        :return: True if application loaded successfully, otherwise False
        """
        if not is_mxs40sv2(self.target_name):
            raise ValueError(
                'Method is not compatible with the selected target')

        if config is None:
            raise ValueError('Config file is not specified')
        if not os.path.isfile(config):
            raise FileNotFoundError(f'File \'{config}\' not found')

        context = ProvisioningContext(self.target.provisioning_strategy)

        if ConnectHelper.connect(self.tool, self.target, probe_id=probe_id,
                                 ap=ap):
            self.version_provider.log_version(self.tool)
            if not self.version_provider.verify_fw_version(self.tool):
                return False
            status = context.provision(self.tool, self.target,
                                       skip_prompts=self.skip_prompts,
                                       config=config)
            ConnectHelper.disconnect(self.tool)
        else:
            status = ProvisioningStatus.FAIL

        if status == ProvisioningStatus.FAIL:
            logger.error('An error occurred while loading the application')

        return status == ProvisioningStatus.OK

    def convert_to_rma(self, probe_id=None, ap='sysap', **kwargs):
        """
        Converts device to the RMA lifecycle stage
        @param probe_id: Probe serial number
        @param ap: The access port used for communication
        @return: True if success, otherwise False
        """
        if not is_mxs40sv2(self.target_name):
            raise ValueError(
                'Method is not compatible with the selected target')

        status = ProvisioningStatus.FAIL
        if ConnectHelper.connect(self.tool, self.target, probe_id=probe_id,
                                 ap=ap):
            self.version_provider.log_version(self.tool)
            context = ProvisioningContext(self.target.provisioning_strategy)
            status = context.convert_to_rma(self.tool, self.target, **kwargs)
            ConnectHelper.disconnect(self.tool)
        return status == ProvisioningStatus.OK

    def debug_certificate(self, template, output, key_id=0, key_path=None,
                          **kwargs):
        """
        Creates debug or RMA certificate binary from the
        certificate in JSON format
        :param template:
            Path to the certificate template in JSON format
        :param output:
            The certificate binary output file
        :param key_id:
            The key ID to sign the certificate. Uses key path from the policy.
        :param key_path:
            Path to the private key file used to sign the certificate.
            Overrides key_id argument
        :param kwargs:
            non_signed - Indicates that debug certificate will not be signed
            signature - Path to the signature which will be used to sign
                        an existing certificate
            unsigned_cert - Path to the unsigned certificate which was
                            generated with 'non_signed' option
        """
        if not is_mxs40sv2(self.target_name):
            raise ValueError(
                'Method is not compatible with the selected target')

        sign_cert = not kwargs.get('non_signed')
        signature = kwargs.get('signature')
        if signature:
            unsigned_cert = kwargs.get('unsigned_cert')
            self.target.debug_certificate.add_signature(unsigned_cert,
                                                        signature, output)
            logger.info('Debug certificate has been signed (%s)', output)
        else:
            if key_path is not None:
                key = key_path
            elif sign_cert:
                key = self.target.key_source.get_key(key_id, 'private')
            else:
                key = self.target.key_source.get_key(key_id, 'public')

            self.target.debug_certificate.create(template, key, output,
                                                 sign_cert)
            logger.info('Debug certificate created (%s)', output)
        return True

    def _validate_policy(self, skip_list=None):
        if self.policy and not os.path.isfile(self.policy):
            raise ValueError(f"Cannot find policy file '{self.policy}'")
        if self.target.is_default_policy:
            logger.warning('The policy is not specified. The default policy '
                           'will be used (%s)', self.target.policy)
        self.target.policy_validator.skip_validation = self.skip_validation
        validation_state = self.target.policy_validator.validate(
            skip=skip_list,
            skip_prompts=self.skip_prompts)
        return validation_state not in [ValidationStatus.ERROR,
                                        ValidationStatus.TERMINATED]

    def _get_target(self, target_name, policy, cwd):
        director = TargetDirector()
        self.target_builder = get_target_builder(director, target_name)
        return director.get_target(policy, target_name, cwd)

    @staticmethod
    def device_list():
        print_targets()
        return True
