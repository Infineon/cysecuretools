"""
Copyright 2019-2023 Cypress Semiconductor Corporation (an Infineon company)
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
import os
import logging

from cryptography.hazmat.primitives.asymmetric import ec, rsa

from .core.connect_helper import ConnectHelper
from .core.deprecated import deprecated
from .core.key_handlers.rsa_handler import RSAHandler
from .core.target_director import TargetDirector
from .core.ocd_settings import OcdSettings
from .core.project_base import ProjectInitializerBase
from .core.logging_configurator import LoggingConfigurator
from .core.signtool_base import SignToolBase
from .core.strategy_context import ProvisioningPacketCtx
from .core.strategy_context import ProvisioningContext
from .core.enums import ValidationStatus, ProvisioningStatus
from .execute.keygens import ec_keygen, rsa_keygen
from .execute.image_signing.sign_tool import SignTool
from .execute.programmer.programmer import ProgrammingTool
from .targets import get_target_builder, print_targets, is_mxs40v1, is_mxs40sv2
from .core.key_handlers import emit_c_public

logger = logging.getLogger(__name__)


class CommonAPI:
    """A class containing common API for all targets"""

    def __init__(self, target=None, policy=None, log_file=True,
                 skip_prompts=False, skip_validation=False, rev=None):

        self.policy = None
        self.skip_validation = skip_validation
        self.skip_prompts = skip_prompts

        if log_file:
            LoggingConfigurator.add_file_logging()

        self.inited = True
        if not target:
            self.inited = False
            self.target = None
            return

        self.target_name = target.lower().strip()

        if policy is not None:
            self.policy = os.path.abspath(policy)
        if ProjectInitializerBase.is_project():
            if policy is None:
                self.policy = ProjectInitializerBase.get_default_policy()

        self.target = self._get_target(
            self.target_name, self.policy, os.getcwd(), rev=rev)
        self.tool = self._init_ocd()
        self.policy = self.target.policy
        self.policy_parser = self.target.policy_parser
        self.version_provider = self.target.version_provider

    def power_on(self, voltage=2500):
        """Turns on the power and sets voltage
        @param voltage: Voltage level
        @return: True if the target powering was successful,
        otherwise False
        """
        return ConnectHelper.power_on(self.tool, self.target, voltage)

    def power_off(self):
        """Turns on the target and sets voltage
        @return: True if the target was successfully powered off,
        otherwise False
        """
        return ConnectHelper.power_off(self.tool, self.target)

    @staticmethod
    def bin2hex(image, output, offset=0):
        """Converts bin to hex
        @param image: Input binary file
        @param output: Output hex file
        @param offset: Starting address offset for loading bin
        """
        result = SignToolBase.bin2hex(image, output, offset=offset)
        if result:
            logger.info("Saved bin file to '%s'", output)
        return result

    @staticmethod
    def convert_key(key, fmt, **kwargs):
        """Converts key to other formats
        @param key: Key cryptography object
        @param fmt: Output key file format
        @param kwargs:
            endian - Indicates byte order
            output - Path to output file
        @return: Boolean or Converted key in string format
        """

        output = kwargs.get('output')
        if output is None:
            raise ValueError('Output path is not specified')

        if isinstance(key, str):
            key = SignTool.load_key(key)

        if fmt.lower() == 'c_array':
            if not isinstance(
                    key, (ec.EllipticCurvePublicKey, rsa.RSAPublicKey)
            ):
                raise ValueError(
                    'The expected key type is RSA public or ECDSA public'
                )
            result = emit_c_public(key)
            with open(output, 'w', encoding='utf-8') as f:
                f.write(result)
            logger.info("Created a file '%s'", os.path.abspath(output))

        elif fmt.lower() == 'secure_boot':
            result = RSAHandler.rsa2secureboot(
                key, kwargs.get('endian') == 'little'
            )
            with open(output, 'w', encoding='utf-8') as f:
                f.write(result)
            logger.info("Created a file '%s'", os.path.abspath(output))

        elif fmt.lower() in ['pem', 'der', 'jwk']:
            if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
                rsa_keygen.save_key(key, output, fmt)
                logger.info("Created a key '%s'", os.path.abspath(output))
            elif isinstance(
                    key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)
            ):
                ec_keygen.save_key(key, output, fmt)
                logger.info("Created a key '%s'", os.path.abspath(output))
            else:
                raise ValueError('Unexpected key type')

        else:
            raise ValueError('Unknown conversion format')

    def sign_image(self, image, image_id=None, **kwargs):
        """Signs firmware image
        @param image: User application file
        @param image_id: The ID of the image in the policy file
        @return: A path to the signed (optionally encrypted) image
        """
        if self.target:
            if self.validate_policy(['pre_build', 'dap_disabling']):
                return self.target.sign_tool.sign_image(
                    image, image_id=image_id, **kwargs)
            return None
        return SignTool().sign_image(image, **kwargs)

    def image_metadata(self, image, **kwargs):
        """Creates a complete MCUboot format image
        @param image: User application file
        @return: Extended (and encrypted if applicable) file path
        """
        if self.target:
            return self.target.sign_tool.add_metadata(image, **kwargs)
        return SignTool().add_metadata(image, **kwargs)

    def extract_payload(self, image, output):
        """Extracts from the image a part that has to be signed
        @param image: User application file
        @param output: A file where to save the payload
        @return: Path to the image with the payload
        """
        if self.target:
            self.target.sign_tool.extract_payload(image, output)
        else:
            SignTool.extract_payload(image, output=output)

    def add_signature(self, image, signature, output, alg=None):
        """Adds signature to MCUboot format image
        @param image: User application file
        @param signature: Path to the binary file containing signature
        @param output: Path where to save the signed image
        @param alg: Signature algorithm
        @return: Path to the output image
        """
        if self.target:
            self.target.sign_tool.add_signature(image, signature, output=output)
        else:
            SignTool.add_signature(image, signature, alg, output=output)

    def verify_image(self, image, **kwargs):
        """Verifies image with a key
        @param image: Image path
        @param kwargs:
            :key: Verification key
        @return: True if success, otherwise False
        """
        return SignTool.verify_image(image, kwargs.get('key'))

    def create_provisioning_packet(self, **kwargs):
        """Creates a packet for device provisioning
        @return: True if packet created successfully, otherwise False
        """
        if not self.validate_policy(**kwargs):
            return False
        ctx = ProvisioningPacketCtx(self.target.provisioning_packet_strategy)
        return ctx.create(self.target, **kwargs)

    def provision_device(self, probe_id=None, ap='cm4', **kwargs):
        """Executes device provisioning - the process of creating device
        identity, attaching policy and bootloader
        @param probe_id: Probe serial number
        @param ap: The access port used for provisioning
        @return: Provisioning result. True if success, otherwise False
        """
        if not self.validate_policy():
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
            if not self.target.version_provider.check_compatibility(self.tool):
                ConnectHelper.disconnect(self.tool)
                return False
            self.target.version_provider.log_version(self.tool)

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
        """Executes device re-provisioning
        @param probe_id: Probe serial number
        @param ap: The access port used for re-provisioning
        @return: Re-provisioning result. True if success, otherwise False
        """
        if not self.validate_policy():
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

            if not self.target.version_provider.check_compatibility(self.tool):
                ConnectHelper.disconnect(self.tool)
                return False
            self.target.version_provider.log_version(self.tool)

            status = context.re_provision(
                self.tool, self.target, bootloader=bootloader,
                probe_id=self.tool.probe_id, **kwargs)
            ConnectHelper.disconnect(self.tool)
        else:
            status = ProvisioningStatus.FAIL

        if status == ProvisioningStatus.FAIL:
            logger.error('Error occurred while reprovisioning device')

        return status == ProvisioningStatus.OK

    def init(self, **kwargs):
        """Initializes new project"""
        cwd = os.getcwd()
        overwrite = True if self.skip_prompts else None
        self.target.project_initializer.init(cwd, overwrite, **kwargs)

    def print_version(self, probe_id=None, ap='sysap', **kwargs):
        """Outputs firmware version bundled with the package
        @param probe_id: Probe serial number
        @param ap: The access port used to read data from device
        """
        connected = False
        try:
            connected = ConnectHelper.connect(
                self.tool, self.target, ap=ap, probe_id=probe_id,
                ignore_errors=True)
        except ValueError as e:
            logger.error(e)
        self.target.version_provider.print_version(**kwargs)
        if connected:
            if self.target.version_provider.check_compatibility(
                    self.tool, check_si_rev=False):
                self.target.version_provider.print_fw_version(self.tool)
            ConnectHelper.disconnect(self.tool)

    def read_die_id(self, probe_id=None, ap='sysap'):
        """Reads die ID
        @param probe_id: Probe serial number
        @param ap: The access port used to read the data
        @return: Die ID if success, otherwise None
        """
        die_id = None
        if ConnectHelper.connect(self.tool, self.target, probe_id=probe_id,
                                 ap=ap):
            if self.target.version_provider.check_compatibility(
                    self.tool, check_si_rev=False):
                self.target.version_provider.log_version(self.tool)
                die_id = self.target.silicon_data_reader.read_die_id(self.tool)
            ConnectHelper.disconnect(self.tool)
        return die_id

    def get_device_info(self, probe_id=None, ap='sysap'):
        """Gets silicon ID, silicon revision, family ID"""
        connected = ConnectHelper.connect(self.tool, self.target,
                                          probe_id=probe_id, ap=ap)
        info = None
        if connected:
            info = self.target.silicon_data_reader.read_device_info(self.tool)
            ConnectHelper.disconnect(self.tool)
        return info

    def get_device_lifecycle(self, probe_id=None, ap='sysap'):
        """Reads device lifecycle stage
        @param probe_id: Probe serial number
        @param ap: The access port used to read the data
        @return: Lifecycle stage name if success, otherwise None
        """
        if is_mxs40v1(self.target_name):
            raise NotImplementedError('Not supported by the selected target')
        lifecycle = None
        if ConnectHelper.connect(
                self.tool, self.target, probe_id=probe_id, ap=ap):
            lifecycle = self.target.version_provider.get_lifecycle_stage(self.tool)
            ConnectHelper.disconnect(self.tool)
        return lifecycle

    def get_probe_list(self):
        """Gets list of all connected probes"""
        return self.tool.get_probe_list()

    def debug_certificate(self, template, output, key_id=0, key_path=None,
                          **kwargs):
        """Creates debug or RMA certificate binary from the
        certificate template
        @param template:
            Path to the certificate template in JSON format
        @param output:
            The certificate binary output file
        @param key_id:
            The key ID to sign the certificate. Uses key path from the policy.
        @param key_path:
            Path to the private key file used to sign the certificate.
            Overrides key_id argument
        @param kwargs:
            non_signed - Indicates that debug certificate will not be signed
            signature - Path to the signature which will be used to sign
                        an existing certificate
            unsigned_cert - Path to the unsigned certificate which was
                            generated with 'non_signed' option
        """
        sign_cert = not kwargs.get('non_signed')
        signature = kwargs.get('signature')
        if signature:
            unsigned_cert = kwargs.get('unsigned_cert')
            self.target.debug_certificate.add_signature(unsigned_cert,
                                                        signature, output)
        else:
            if key_path is not None:
                key = key_path
            elif sign_cert:
                if key_id is not None:
                    key = self.target.key_source.get_key(key_id, 'private')
            else:
                if key_id is not None:
                    key = self.target.key_source.get_key(key_id, 'public')

            self.target.debug_certificate.create(template, key, output,
                                                 sign_cert, **kwargs)
        return True

    @staticmethod
    def device_list():
        """Prints a list of supported devices"""
        print_targets()
        return True

    @deprecated('convert_to_rma() is deprecated. Use transit_to_rma() instead.')
    def convert_to_rma(self, probe_id=None, ap='sysap', **kwargs):
        """DEPRECATED: use transit_to_rma instead"""
        return self.transit_to_rma(probe_id=probe_id, ap=ap, **kwargs)

    def transit_to_rma(self, probe_id=None, ap='sysap', **kwargs):
        """
        Transits device to the RMA lifecycle stage
        @param probe_id: Probe serial number
        @param ap: The access port used for communication
        @param kwargs:
               :cert: Transit to RMA certificate
        @return: True if success, otherwise False
        """
        status = ProvisioningStatus.FAIL
        cert = kwargs.get('cert')
        del kwargs['cert']
        if ConnectHelper.connect(self.tool, self.target,
                                 probe_id=probe_id, ap=ap):
            self.version_provider.log_version(self.tool)
            context = ProvisioningContext(self.target.provisioning_strategy)
            status = context.transit_to_rma(self.tool, self.target, cert,
                                            **kwargs)
            ConnectHelper.disconnect(self.tool)
        return status == ProvisioningStatus.OK

    def open_rma(self, cert, probe_id=None):
        """
        Enables full access to device in RMA lifecycle stage
        @param cert: Open RMA certificate
        @param probe_id: Probe serial number
        @param ap: The access port used for communication
        @return: True if success, otherwise False
        """
        if is_mxs40sv2(self.target_name):
            raise NotImplementedError('Not supported by the selected target')
        status = ProvisioningStatus.FAIL
        if ConnectHelper.connect(self.tool, self.target, probe_id=probe_id,
                                 ignore_errors=True):
            context = ProvisioningContext(self.target.provisioning_strategy)
            status = context.open_rma(self.tool, self.target, cert)
            ConnectHelper.disconnect(self.tool)
        return status == ProvisioningStatus.OK

    def _init_ocd(self):
        settings = OcdSettings()
        try:
            tool = ProgrammingTool.create(settings.ocd_name, settings)
        except KeyError as e:
            error = f'Unsupported On-Chip debugger {e}'
            if ProjectInitializerBase.is_project():
                default_ocd = self.target.ocds[0]
                logger.warning(error)
                if self.skip_prompts:
                    logger.info('Skip user interactive prompts option enabled')
                    answer = 'y'
                else:
                    answer = input(f"Change to '{default_ocd}'? (y/n): ")
                if answer.lower() == 'y':
                    _, path = ProjectInitializerBase.get_ocd_data()
                    if not path and not self.skip_prompts:
                        path = input(f"Path to '{default_ocd}' root directory: ")
                    ProjectInitializerBase.set_ocd_data(default_ocd, path)
                    logger.info("Changed active OCD to '%s'", default_ocd)
                    settings = OcdSettings()
                    tool = ProgrammingTool.create(settings.ocd_name, settings)
                else:
                    raise ValueError(error) from e
            else:
                raise ValueError(error) from e
        return tool

    def validate_policy(self, skip_list=None, **kwargs):
        """Validates policy if specified and policy validator
        for the target is defined"""
        if self.policy and not os.path.isfile(self.policy):
            raise ValueError(f"Cannot find policy file '{self.policy}'")
        if self.target.policy_validator is None:
            return True
        if self.target.is_default_policy:
            logger.warning('The policy is not specified. The default policy '
                           'will be used (%s)', self.target.policy)
        self.target.policy_validator.skip_validation = self.skip_validation
        validation_state = self.target.policy_validator.validate(
            skip=skip_list,
            skip_prompts=self.skip_prompts, **kwargs)
        return validation_state not in [ValidationStatus.ERROR,
                                        ValidationStatus.TERMINATED]

    def _get_target(self, target_name, policy, cwd, rev=None):
        director = TargetDirector()
        self.target_builder = get_target_builder(director, target_name, rev=rev)
        return director.get_target(policy, target_name, cwd)
