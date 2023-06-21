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

from .api_common import CommonAPI
from .core.enums import KeyAlgorithm, ProvisioningStatus
from .core.connect_helper import ConnectHelper
from .core.strategy_context import ProvisioningContext
from .core.strategy_context import ProvisioningPacketCtx
from .execute.keygens import rsa_keygen, aes_keygen

logger = logging.getLogger(__name__)


class Mxs40sv2API(CommonAPI):
    """A class containing API for MXS40sv2 platform"""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def create_keys(self, overwrite=None, out=None, kid=None,
                    user_key_alg=KeyAlgorithm.RSA, **kwargs):
        """Creates keys either specified in policy file or
        in the output argument
        @param overwrite: Indicates whether overwrite keys in the
               output directory if they already exist. If the value
               is None, a prompt will ask whether to overwrite
               existing keys
        @param out: Output filenames for the private and public keys
        @param kid: Key ID to create keys in the paths specified in policy
        @param user_key_alg: User key algorithm
        @return: True if key(s) created successfully, otherwise False.
        """
        if not self.validate_policy(['pre_build', 'dap_disabling']):
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
                if pair.private is not None:
                    keys_exist = keys_exist | os.path.isfile(pair.private)
                if pair.public is not None:
                    keys_exist = keys_exist | os.path.isfile(pair.public)
            if keys_exist:
                if overwrite is None:
                    if self.skip_prompts:
                        logger.info('Keys already exist. Skip creating keys')
                        return True

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
        for pair in keys:
            if user_key_alg == KeyAlgorithm.RSA:
                private_key, public_key = rsa_keygen.generate_key(
                    2048, template=kwargs.get('template'))
                if pair.private:
                    rsa_keygen.save_key(private_key, pair.private, 'PEM',
                                        kid=kwargs.get('kid'))
                    logger.info("Created a key '%s'",
                                os.path.abspath(pair.private))
                if pair.public:
                    rsa_keygen.save_key(public_key, pair.public, 'PEM',
                                        kid=kwargs.get('kid'))
                    logger.info("Created a key '%s'",
                                os.path.abspath(pair.public))
                    if kwargs.get('hash_path'):
                        rsa_keygen.create_pubkey_hash(pair.public,
                                                      kwargs.get('hash_path'))
            elif user_key_alg == KeyAlgorithm.AES:
                aes_keygen.generate_key(output=pair.private, add_iv=False)
        return True

    def extend_image(self, image, **kwargs):
        """Extends firmware image with the TLVs
        @param image: User application file
        @return: Extended (and encrypted if applicable) file path
        """
        return self.target.sign_tool.extend_image(image, **kwargs)

    def prov_packets_to_policy(self, packets, output):
        """Reverse conversion of the provisioning packet to the policy file
        @param packets: List of the binary packets paths
        @param output: The file where to save the policy
        @return: True if packet converted successfully, otherwise False
        """
        ctx = ProvisioningPacketCtx(self.target.provisioning_packet_strategy)
        return ctx.reverse_conversion(self.target, packets, output)

    def load_and_run_app(self, config, probe_id=None, ap='sysap'):
        """Loads and runs RAM application
        @param config: Path to the application configuration file
        @param probe_id: Probe serial number
        @param ap: The access port used to load the application
        @return: True if application loaded successfully, otherwise False
        """
        if config is None:
            raise ValueError('Config file is not specified')
        if not os.path.isfile(config):
            raise FileNotFoundError(f'File \'{config}\' not found')

        context = ProvisioningContext(self.target.provisioning_strategy)

        if ConnectHelper.connect(self.tool, self.target, probe_id=probe_id,
                                 ap=ap):
            if not self.target.version_provider.check_compatibility(self.tool):
                ConnectHelper.disconnect(self.tool)
                return False
            self.target.version_provider.log_version(self.tool)
            status = context.provision(self.tool, self.target,
                                       skip_prompts=self.skip_prompts,
                                       config=config)
            ConnectHelper.disconnect(self.tool)
        else:
            status = ProvisioningStatus.FAIL

        if status == ProvisioningStatus.FAIL:
            logger.error('An error occurred while loading the application')

        return status == ProvisioningStatus.OK
