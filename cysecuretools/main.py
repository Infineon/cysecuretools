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
import json
import logging
import os
import sys
from cryptography.hazmat.primitives import serialization

import cysecuretools.execute.jwt as jwt
import cysecuretools.execute.keygen as keygen
from cysecuretools.execute.version_helper import VersionHelper
from cysecuretools.core.exceptions import ValidationError
from cysecuretools.core.bootloader_provider import BootloaderProvider
from cysecuretools.core.certificates.x509 import X509CertificateStrategy
from cysecuretools.core.logging_formatter import CustomFormatter
from cysecuretools.core.strategy_context.cert_strategy_ctx \
    import CertificateContext
from cysecuretools.core.strategy_context.encrypted_programming_strategy_ctx \
    import EncryptedProgrammingContext
from cysecuretools.core.strategy_context.prov_packet_strategy_ctx \
    import ProvisioningPacketContext
from cysecuretools.core.strategy_context.provisioning_strategy_ctx \
    import ProvisioningContext
from cysecuretools.core.target_director import TargetDirector
from cysecuretools.core.project import ProjectInitializer
from cysecuretools.execute.encrypted_programming.aes_header_strategy \
    import AesHeaderStrategy
from cysecuretools.core.enums import (EntranceExamStatus, ValidationStatus,
                                      ProvisioningStatus, KeyAlgorithm,
                                      ImageType, KeyType, KeyId)
from cysecuretools.execute.image_cert import ImageCertificate
from cysecuretools.execute.key_reader import get_aes_key
from cysecuretools.execute.programmer.programmer import ProgrammingTool
from cysecuretools.execute.signtool import SignTool
from cysecuretools.targets import print_targets, get_target_builder
from cysecuretools.core.logging_configurator import LoggingConfigurator

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
    TOOLS_PATH = os.path.dirname(os.path.realpath(__file__))
    PROGRAMMING_TOOL = 'pyocd'

    def __init__(self, target=None, policy=None, log_file=True,
                 skip_prompts=False):
        """
        Creates instance of the class
        :param target: Device manufacturing part number
        :param policy: Provisioning policy file
        :param log_file: Indicates whether to write log into a file
        :param skip_prompts: Indicates whether to skip user interactive
               prompts
        """
        if log_file:
            LoggingConfigurator.add_file_logging()

        self.tool = ProgrammingTool.create(self.PROGRAMMING_TOOL)

        self.skip_prompts = skip_prompts
        if self.skip_prompts:
            self.tool.wait_for_target = False

        self.inited = True
        if not target:
            self.inited = False
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

        if self.policy and not os.path.isfile(self.policy):
            raise ValueError(f'Cannot find file "{self.policy}"')

        self.target = self._get_target(self.target_name, self.policy, cwd)

        self.policy = self.target.policy
        self.memory_map = self.target.memory_map
        self.register_map = self.target.register_map
        self.policy_parser = self.target.policy_parser
        self.policy_validator = self.target.policy_validator
        self.policy_filter = self.target.policy_filter
        self.target_dir = self.target.target_dir

        # Validate policy file
        validation_state = self.policy_validator.validate(
            skip=['pre_build', 'dap_disabling'],
            skip_prompts=self.skip_prompts)
        if validation_state in [ValidationStatus.ERROR,
                                ValidationStatus.TERMINATED]:
            raise ValidationError

        self.target.key_reader = self.target.key_reader(self.target)
        self.key_reader = self.target.key_reader
        self.bootloader_provider = BootloaderProvider(self.target)
        self.entr_exam = self.target.entrance_exam(self.target)
        self.project_initializer = self.target.project_initializer(self.target)

    def create_keys(self, overwrite=None, out=None, kid=None,
                    user_key_alg=KeyAlgorithm.EC):
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
        # Define key algorithm
        if user_key_alg is None:
            user_key_alg = self.target.key_algorithms[0]
        else:
            if user_key_alg not in self.target.key_algorithms:
                logger.error(f'Invalid key algorithm \'{user_key_alg}\'. '
                             f'Supported key algorithms for the selected '
                             f'target: {",".join(self.target.key_algorithms)}')
                return False

        # Find keys that have to be generated
        keys = self.policy_parser.get_keys(out)

        # Check whether keys exist
        if not overwrite:
            keys_exist = False
            for pair in keys:
                if pair.key_type is KeyType.user:
                    if pair.image_type == ImageType.BOOTLOADER:
                        continue
                    keys_exist = keys_exist | os.path.isfile(
                        pair.json_key_path)
                    keys_exist = keys_exist | os.path.isfile(
                        pair.pem_key_path)
            if keys_exist:
                if overwrite is None:
                    answer = input(
                        'Keys directory is not empty. Overwrite? (y/n): ')
                    if answer.lower() != 'y':
                        return
                elif overwrite is False:
                    return

        # Generate keys
        seen = []
        for pair in keys:
            if pair.image_type == ImageType.BOOTLOADER:
                continue
            if pair.key_type is KeyType.user:
                if {pair.key_id, pair.json_key_path} in seen or \
                        (kid is not None and pair.key_id != kid):
                    continue
                else:
                    seen.append({pair.key_id, pair.json_key_path})

                if user_key_alg == KeyAlgorithm.EC:
                    keygen.generate_ecdsa_key(pair.key_id, pair.json_key_path,
                                              pair.pem_key_path)
                elif user_key_alg == KeyAlgorithm.RSA:
                    keygen.generate_rsa_key(pair.pem_key_path)
            else:
                continue

        return True

    def sign_image(self, hex_file, image_id=4, image_type=None,
                   encrypt_key=None, erased_val=None, boot_record='default'):
        """
        Signs firmware image with the key specified in the policy file.
        :param hex_file: User application hex file.
        :param image_id: The ID of the firmware in policy file.
        :param image_type: Image type (BOOT or UPGRADE).
        :param encrypt_key: Path to public key file
               for the image encryption
        :param erased_val: The value that is read back from erased flash
        :param boot_record: Create CBOR encoded boot record TLV.
               The sw_type represents the role of the software component
               (e.g. CoFM for coprocessor firmware). [max. 12 characters]
        :return: Signed (and encrypted if applicable) hex files path.
        """
        sign_tool = SignTool(self.target)
        result = sign_tool.sign_image(hex_file=hex_file,
                                      image_id=image_id,
                                      image_type=image_type,
                                      encrypt_key=encrypt_key,
                                      erased_val=erased_val,
                                      boot_record=boot_record)
        return result

    def create_provisioning_packet(self):
        """
        Creates JWT packet for provisioning device.
        :return: True if packet created successfully, otherwise False.
        """
        validation_state = self.policy_validator.validate(
            skip_prompts=self.skip_prompts)
        if validation_state in [ValidationStatus.ERROR,
                                ValidationStatus.TERMINATED]:
            return False

        filtered_policy = self.policy_filter.filter_policy()

        # Get bootloader image certificate
        image_cert = self.bootloader_provider.jwt_path()
        if not os.path.isfile(image_cert):
            logger.error(f'Cannot find bootloader file \'{image_cert}\'')
            return False

        # Get user certificates
        certs = self.policy_parser.get_chain_of_trust()
        dev_certs = ()
        for cert in certs:
            dev_certs = dev_certs + (cert,)

        context = ProvisioningPacketContext(
            self.target.provisioning_packet_strategy)
        return context.create(filtered_policy=filtered_policy,
                              image_cert=image_cert, dev_cert=dev_certs)

    def provision_device(self, probe_id=None, ap='cm4'):
        """
        Executes device provisioning - the process of creating device
        identity, attaching policy and bootloader.
        :param probe_id: Probe serial number.
        :param ap: The access port used for provisioning
        :return: Provisioning result. True if success, otherwise False.
        """
        validation_state = self.policy_validator.validate(
            skip_prompts=self.skip_prompts)
        if validation_state in [ValidationStatus.ERROR,
                                ValidationStatus.TERMINATED]:
            return False

        # Get bootloader program file
        bootloader = self.bootloader_provider.hex_path()
        if not os.path.isfile(bootloader):
            logger.error(f'Cannot find bootloader file \'{bootloader}\'')
            return False

        context = ProvisioningContext(self.target.provisioning_strategy)

        if self.tool.connect(self.target_name, probe_id=probe_id, ap=ap):
            VersionHelper.log_version(self.tool, self.target)
            if not VersionHelper.verify_sfb_version(self.tool, self.target):
                return False
            status = context.provision(self.tool, self.target,
                                       self.entr_exam, bootloader,
                                       probe_id=probe_id, ap=ap,
                                       skip_prompts=self.skip_prompts)
            self.tool.disconnect()
        else:
            status = ProvisioningStatus.FAIL

        if status == ProvisioningStatus.FAIL:
            logger.error('Error occurred while provisioning device')
            return False

        return True

    def re_provision_device(self, probe_id=None, ap='sysap', erase_boot=False,
                            control_dap_cert=None, skip_bootloader=False):
        """
        Executes device re-provisioning
        :param probe_id: Probe serial number.
        :param ap: The access port used for re-provisioning
        :param erase_boot: Indicates whether erase BOOT slot
        :param control_dap_cert: The certificate that provides the
               access to control DAP
        :param skip_bootloader: Indicates whether to skip bootloader
               programming during reprovisioning
        :return: Provisioning result. True if success, otherwise False.
        """
        validation_state = self.policy_validator.validate(
            skip_prompts=self.skip_prompts)
        if validation_state in [ValidationStatus.ERROR,
                                ValidationStatus.TERMINATED]:
            return False

        # Get bootloader program file
        btldr = None
        if not skip_bootloader:
            btldr = self.bootloader_provider.hex_path()
            if not os.path.isfile(btldr):
                logger.error(f'Cannot find bootloader file \'{btldr}\'')
                return False

        context = ProvisioningContext(self.target.provisioning_strategy)

        if self.tool.connect(self.target_name, probe_id=probe_id, ap=ap):
            VersionHelper.log_version(self.tool, self.target)
            if not VersionHelper.verify_sfb_version(self.tool, self.target):
                return False
            status = context.re_provision(
                self.tool, self.target, btldr, erase_boot=erase_boot,
                control_dap_cert=control_dap_cert, ap=ap, probe_id=probe_id)
            self.tool.disconnect()
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
        context = CertificateContext(X509CertificateStrategy())

        expected_fields = ['subject_name', 'country', 'state', 'organization',
                           'issuer_name', 'private_key']
        all_fields_present = all(
            k in kwargs and kwargs[k] is not None for k in expected_fields)
        serial = kwargs.get('serial_number')
        public_key = kwargs.get('public_key')

        if not all_fields_present or not serial or not public_key:
            logger.info('Get default certificate data')

            default = context.default_certificate_data(
                self.tool, self.target, self.entr_exam, probe_id)
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
        status = False
        if self.tool.connect(self.target_name, probe_id=probe_id, ap=ap):
            VersionHelper.log_version(self.tool, self.target)
            if not VersionHelper.verify_sfb_version(self.tool, self.target):
                return False
            context = ProvisioningContext(self.target.provisioning_strategy)
            if erase_flash:
                context.erase_flash(self.tool, self.target)
            status = self.entr_exam.execute(self.tool)
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
            self.tool.disconnect()
        return status == EntranceExamStatus.OK

    def flash_map(self, image_id=4, image_type=ImageType.BOOT.name):
        """
        Extracts information about slots from given policy.
        :param image_id: The ID of the firmware in policy file.
        :param image_type: The image type - BOOT or UPGRADE.
        :return: Address for specified image, size for specified image.
        """
        # Find keys that have to be generated
        data = self.policy_parser.get_image_data(image_type.upper(), image_id)
        if len(data) > 0:
            address, size = data[0]
        else:
            logger.error(f'Cannot find image with id {image_id} and type '
                         f'\'{image_type}\' in the policy file')
            address, size = None, None

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
        if key is None:
            policy_keys = self.policy_parser.get_keys(
                image_type=ImageType.BOOTLOADER)
            if not policy_keys:
                logger.error('Failed to create image certificate. Key not '
                             'specified neither in policy nor as an argument')
                return False
            key = os.path.abspath(policy_keys[0].json_key_path)

        if not os.path.isfile(key):
            logger.error(f'Cannot find the key \'{key}\'')
            return False

        image = os.path.abspath(image)
        output = os.path.abspath(output)
        image_cert = ImageCertificate(image, key, output, version, image_id,
                                      exp_date_str)
        image_cert.create()
        logger.info(f'Image certificate was created successfully')
        logger.info(f'Image version: {version}')
        logger.info(f'Certificate: {output}')
        return True

    def encrypt_image(self,
                      image,
                      host_key_id: KeyId,
                      dev_key_id: KeyId,
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
        validation_state = self.policy_validator.validate(
            skip=['dap_disabling'], skip_prompts=self.skip_prompts)
        if validation_state in [ValidationStatus.ERROR,
                                ValidationStatus.TERMINATED]:
            return False

        # Get host private key
        logger.debug(f'Host key id = {host_key_id}')
        try:
            _, host_key_pem = self.policy_parser.get_private_key(host_key_id)
        except ValueError as ex:
            logger.error(ex)
            return False

        # Get public key
        pub_key_pem = None
        logger.debug(f'Device key id = {dev_key_id}')

        connected = self.tool.connect(self.target_name, probe_id=probe_id,
                                      blocking=False, ap='sysap')
        if connected:
            VersionHelper.log_version(self.tool, self.target)
            VersionHelper.verify_sfb_version(self.tool, self.target)
            logger.info('Read device public key from device')
            pub_key_pem = self.key_reader.read_public_key(
                self.tool, dev_key_id, 'pem')
            self.tool.disconnect()

        if not connected or not pub_key_pem:
            logger.info(f'Read public key {dev_key_id} from file')
            try:
                _, pub_key_pem = self.policy_parser.get_public_key(
                    dev_key_id, pre_build=True)
            except ValueError as ex:
                logger.error(ex)
                return False

        # Create AES key
        key_to_encrypt = get_aes_key(key_length)

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
        result = False
        context = EncryptedProgrammingContext(AesHeaderStrategy)
        if self.tool.connect(self.target_name, probe_id=probe_id, ap='sysap'):
            VersionHelper.log_version(self.tool, self.target)
            VersionHelper.verify_sfb_version(self.tool, self.target)
            result = context.program(self.tool, self.target, encrypted_image)
            self.tool.disconnect()
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
        key = None
        if self.tool.connect(self.target_name, probe_id=probe_id, ap='sysap'):
            VersionHelper.log_version(self.tool, self.target)
            VersionHelper.verify_sfb_version(self.tool, self.target)
            try:
                key = self.key_reader.read_public_key(self.tool, key_id, key_fmt)
                if out_file:
                    out_file = os.path.abspath(out_file)
                    with open(out_file, 'w') as fp:
                        if key_fmt == 'jwk':
                            json.dump(key, fp, indent=4)
                        elif key_fmt == 'pem':
                            fp.write(key.decode("utf-8"))
                        else:
                            fp.write(str(key))
                    logger.info(f'Key saved: {out_file}')
                self.tool.disconnect()
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
        if self.tool.connect(self.target_name, probe_id=probe_id, ap=ap):
            VersionHelper.log_version(self.tool, self.target)
            VersionHelper.verify_sfb_version(self.tool, self.target)
            reader = self.target.silicon_data_reader(self.target)
            die_id = reader.read_die_id(self.tool)
            self.tool.disconnect()
        return die_id

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
        logger.info(f'Signing file {os.path.abspath(json_file)}')
        validation_state = self.policy_validator.validate(
            skip=['dap_disabling'], skip_prompts=self.skip_prompts)
        if validation_state in [ValidationStatus.ERROR,
                                ValidationStatus.TERMINATED]:
            return False

        logger.debug(f'Private key id = {priv_key_id}')
        try:
            jwk, _ = self.policy_parser.get_private_key(priv_key_id)
        except ValueError as ex:
            logger.error(ex)
            return None

        if not output_file:
            output_file = '{0}.jwt'.format(os.path.splitext(json_file)[0])
        output_file = os.path.abspath(output_file)
        jwt_text = jwt.json_to_jwt(json_file, jwk, output_file)
        logger.info(f'Created file {output_file}')
        return jwt_text

    def print_version(self, probe_id=None, ap='sysap'):
        """
        Outputs CyBootloader version bundled with the package. If
        device is connected outputs CyBootloader and Secure Flash
        Boot version programmed into device
        :param probe_id: Probe serial number
        :param ap: The access port used for to read CyBootloader and
               Secure Flash Boot version from device
        """
        sfb_ver = 'unknown'
        connected = self.tool.connect(self.target_name, probe_id=probe_id,
                                      blocking=False, ap=ap)
        if connected:
            sfb_ver = VersionHelper.sfb_version(self.tool, self.target)
            bootloader_ver = VersionHelper.device_bootloader_version(self.tool, self.target)
            VersionHelper.verify_sfb_version(self.tool, self.target)
            self.tool.disconnect()

        VersionHelper.print_version([self.target_name])
        if connected:
            print('Device:')
            print(f'\tCyBootloader: {bootloader_ver}')
            print(f'\tSecure Flash Boot: {sfb_ver}')

    def init(self):
        """
        Initializes new project
        """
        cwd = os.getcwd()
        overwrite = True if self.skip_prompts else None
        self.project_initializer.init(cwd, overwrite)

    def get_probe_list(self):
        """
        Gets list of all connected probes
        """
        return self.tool.get_probe_list()

    def get_device_info(self, probe_id=None, ap='sysap'):
        """
        Gets device information - silicon ID, silicon revision, family ID
        """
        connected = self.tool.connect(self.target_name, probe_id=probe_id,
                                      ap=ap)
        dev_info = None
        if connected:
            dev_info = self.entr_exam.read_device_info(self.tool)
            self.tool.disconnect()
        return dev_info

    def _get_target(self, target_name, policy, cwd):
        director = TargetDirector()
        self.target_builder = get_target_builder(director, target_name)
        return director.get_target(policy, target_name, cwd)

    @staticmethod
    def device_list():
        print_targets()
        return True
