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
import cysecuretools.keys.keygen as keygen
import cysecuretools.prepare.provisioning_packet as provisioning_packet
import cysecuretools.provision_device_runner as provision_device_runner
import cysecuretools.execute.validators.policy_filter as policy_filter
import cysecuretools.execute.validators.policy_validator as policy_validator
import cysecuretools.entrance_exam_runner as entrance_exam_runner
from cysecuretools.signtool import SignTool
from cysecuretools.execute.validators.policy_parser import PolicyParser, KeyType, ImageType
from cysecuretools.execute.validators.cy_bootloader_map_parser import CyBootloaderMapParser
from cysecuretools.execute.enums import ProtectionState
from cysecuretools.execute.p6_memory_map import MCUBOOT_HEADER_SIZE, trailer_size

TOOLS_PATH = os.path.dirname(os.path.realpath(__file__))
DEFAULT_POLICY_PATH = os.path.join(TOOLS_PATH, 'prepare/policy_single_stage_CM4.json')
CY_BOOTLOADER_MAP = 'prebuild/cy_bootloader_map.json'
CY_AUTH_JWT = os.path.join(TOOLS_PATH, 'prebuild/cy_auth.jwt')
OEM_STATE_JSON = os.path.join(TOOLS_PATH, 'prebuild/oem_state.json')
HSM_STATE_JSON = os.path.join(TOOLS_PATH, 'prebuild/hsm_state.json')
PACKET_FOLDER = os.path.join(TOOLS_PATH, 'packet')
PROV_CMD_JWT = os.path.join(PACKET_FOLDER, 'prov_cmd.jwt')

logging.basicConfig(level=logging.INFO)
logging.getLogger('pyocd').setLevel(logging.WARNING)
logger = logging.getLogger(__name__)


def create_keys(policy=DEFAULT_POLICY_PATH, overwrite=None, out=None):
    """
    Creates keys specified in policy file for image signing and encryption.
    :param policy: Policy file.
    :param overwrite: Indicates whether overwrite keys in the output directory if they already exist.
    If the value is None, a prompt will ask whether to overwrite existing keys.
    :param out: Output directory for generated keys. By default keys location will be as specified in the policy file.
    """
    # Resolve paths
    policy = os.path.abspath(policy)

    # Validate policy file
    if not policy_validator.validate(policy):
        return

    # Find keys that have to be generated
    parser = PolicyParser(policy)
    keys = parser.get_keys(out)

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


def sign_image(hex_file, policy=DEFAULT_POLICY_PATH, image_id=4):
    """
    Signs firmware image with the certificates.
    :param hex_file: User application hex file.
    :param policy: Policy file applied to device.
    :param image_id: The ID of the firmware in policy file.
    :return: Signed (and encrypted if applicable) hex files path.
    :exception ValueError: Raised if key_id is out of range or specified policy file does not contain data for
    the specified key_id.
    :exception OSError: Raised if policy or hex file not found.
    """
    # Resolve paths
    policy = os.path.abspath(policy)

    # Validate policy file
    if not policy_validator.validate(policy):
        return None

    # Sign image
    sign_tool = SignTool(policy)
    result = sign_tool.sign_image(hex_file=hex_file, image_id=image_id)
    return result


def create_provisioning_packet(target, policy=DEFAULT_POLICY_PATH):
    """
    Creates JWT packet for provisioning device.
    :param target: The device to be provisioned.
    :param policy: Policy file that will be applied to device.
    :return: True if packet created successfully, otherwise False.
    :exception OSError: Raised if policy or key file not found.
    """
    # Resolve paths
    policy = os.path.abspath(policy)

    # Validate and filter policy file
    if not policy_validator.validate(policy):
        logger.error('FAIL: Policy validation failed')
        return False
    filtered_policy = policy_filter.filter_policy(policy)
    parser = PolicyParser(policy)

    # Get CyBootloader jwt
    mode = parser.get_cybootloader_mode()
    cy_bootloader_jwt = os.path.join(TOOLS_PATH, CyBootloaderMapParser.get_filename(target, mode, 'jwt'))
    if cy_bootloader_jwt is None:
        logger.error(f'FAIL: CyBootloader data not found for target {target}, mode "{mode}"')
        return False

    if not os.path.isfile(cy_bootloader_jwt):
        logger.error(f'FAIL: Cannot find "{cy_bootloader_jwt}"')
        return False

    key = [x for x in parser.get_keys() if x.image_type == ImageType.BOOT]
    if not key:
        logger.error('FAIL: Failed to create provisioning packet. Key not found')
        return False

    args = [
        '--policy', filtered_policy,
        '--cyboot', cy_bootloader_jwt,
        '--cyauth', CY_AUTH_JWT,
        '--out', PACKET_FOLDER,
        '--ckey', key[0].json_key_path,
        '--oem', OEM_STATE_JSON,
        '--hsm', HSM_STATE_JSON
    ]

    logger.debug(f'Starting provisioning packet generation with the arguments: {args}')
    try:
        provisioning_packet.main(args)
    except SystemExit as e:
        if e.code != 0:
            logger.error(f'An error occurred while running provisioning packet generator with arguments: {args}')
        return e.code == 0


def provision_device(target, policy=DEFAULT_POLICY_PATH, probe_id=None, protection_state=ProtectionState.secure):
    """
    Executes device provisioning - the process of attaching a certificate to the device identity.
    :param target: The device to be provisioned.
    :param policy: Policy file necessary to get a key path.
    :param probe_id: Probe serial number.
    :param protection_state: Expected target protection state. The argument is for Cypress internal use only.
    :return: Provisioning result. True if success, otherwise False.
    :exception OSError: Raised if provisioning packet file not found.
    """
    # Resolve paths
    policy = os.path.abspath(policy)

    # Validate policy file
    if not policy_validator.validate(policy):
        return False
    parser = PolicyParser(policy)

    pub_key = [x for x in parser.get_keys() if x.key_type == KeyType.device_public]
    if not pub_key:
        logger.error('Failed to provision device. Device public key path not found')
        return False

    # Get CyBootloader hex
    mode = parser.get_cybootloader_mode()
    cy_bootloader_hex = os.path.join(TOOLS_PATH, CyBootloaderMapParser.get_filename(target, mode, 'hex'))
    if cy_bootloader_hex is None:
        logger.error(f'CyBootloader data not found for target {target}, mode "{mode}"')
        return False

    if not os.path.isfile(cy_bootloader_hex):
        logger.error(f'Cannot find "{cy_bootloader_hex}"')
        return False

    args = [
        '--prov-jwt', PROV_CMD_JWT,
        '--hex', cy_bootloader_hex,
        '--pubkey-json', pub_key[0].json_key_path,
        '--pubkey-pem', pub_key[0].pem_key_path,
        '--target', target
    ]

    if probe_id:
        args.extend(['--probe-id', probe_id])

    if protection_state != ProtectionState.secure:
        args.extend(['--protection-state', protection_state])

    logger.debug(f'Starting provisioning device with the arguments: {args}')
    try:
        provision_device_runner.main(args)
    except SystemExit as e:
        if e.code != 0:
            logger.error(f'An error occurred while running provisioning device with arguments: {args}')
        return e.code == 0


def entrance_exam(target):
    """
    Checks device life-cycle, Flashboot firmware and Flash state.
    :param target: The device to be provisioned.
    :return True if the device is ready for provisioning, otherwise False.
    """
    try:
        entrance_exam_runner.main(target)
    except SystemExit as e:
        if e.code != 0:
            logger.error('An error occurred while running entrance exam')
        return e.code == 0


def flash_map(policy=DEFAULT_POLICY_PATH, image_id=4):
    """
    Extracts information about slots from given policy.
    :param policy: Policy file applied to device.
    :param image_id: The ID of the firmware in policy file.
    :return: Address for specified image, size for specified image.
    """
    # Resolve paths
    policy = os.path.abspath(policy)

    # Validate policy file
    if not policy_validator.validate(policy):
        return None, None

    # Find keys that have to be generated
    parser = PolicyParser(policy)
    address, size = parser.get_image_data(image_id, ImageType.BOOT.name)

    if address is None or size is None:
        logger.error('Cannot find image address in the policy file')
        return None, None

    address = address + MCUBOOT_HEADER_SIZE
    size = size - MCUBOOT_HEADER_SIZE - trailer_size()

    return address, size
