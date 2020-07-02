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
import logging
import cysecuretools.imgtool.main as imgtool
from shutil import copy2
from intelhex import hex2bin, bin2hex
from cysecuretools.execute.enums import ImageType
from cysecuretools.targets.common.policy_parser import PolicyParser

logger = logging.getLogger(__name__)


class SignTool:
    def __init__(self, policy_file, memory_map):
        # Resolve paths
        self.PKG_PATH = os.path.dirname(os.path.realpath(__file__))
        self.IMG_TOOL_PATH = os.path.join(self.PKG_PATH, '../imgtool/main.py')
        self.parser = PolicyParser(policy_file)
        self.policy = PolicyParser.get_json(policy_file)
        self.memory_map = memory_map
        self.policy_file = policy_file

    def sign_image(self, hex_file, image_id, image_type, encrypt_key=None):
        """
        Signs hex file with the key specified in the policy file.
        Converts binary file of the signed image.
        Creates copy of unsigned hex file.
        Encrypts UPGRADE image if the policy file contains encryption key
        :param hex_file: The hex file to sign.
        :param image_id: The ID of the firmware in policy file.
        :param image_type: The image type.
        :param encrypt_key: path to public key file for the image encryption
        :return: Path to the signed files. One file per slot.
        """
        result = []
        slot = self.parser.get_slot(image_id)
        if slot is None:
            logger.error(f'Image with ID {image_id} not found in \'{self.policy_file}\'')
            return None
        unsigned_hex = '{0}_{2}{1}'.format(*os.path.splitext(hex_file) + ('unsigned',))
        copy2(hex_file, unsigned_hex)

        for image in slot['resources']:
            if image_type:
                if image['type'] != image_type.upper():
                    continue # skip generating hex file if sign type defined and not same as current image type
            if image['type'] == ImageType.UPGRADE.name:
                if 'upgrade' not in slot or not slot['upgrade']:
                    continue  # skip generating hex file for UPGRADE slot if it is disabled

            if image['type'] == ImageType.BOOT.name:
                hex_out = self.sign_single_hex(slot, image['type'], unsigned_hex, hex_file)
            else:
                if 'encrypt' in slot and slot['encrypt']:
                    if encrypt_key is None:
                        if 'encrypt_peer' in slot and slot['encrypt_peer']:
                            encrypt_key = slot['encrypt_peer']
                            if not os.path.isabs(encrypt_key):
                                encrypt_key = os.path.join(self.parser.policy_dir, encrypt_key)
                        else:
                            logger.error('Image must be encrypted! Specify encrypt_key_file path.')
                            return None
                else:
                    if encrypt_key is not None:
                        encrypt_key = None

                output_name = '{0}_{2}{1}'.format(*os.path.splitext(hex_file) + ('upgrade',))
                hex_out = self.sign_single_hex(slot, image['type'], unsigned_hex, output_name, encrypt_key)
                bin_out = '{0}.bin'.format(os.path.splitext(hex_out)[0])
                hex2bin(hex_out, bin_out)
                bin2hex(bin_out, output_name, offset=int(image['address']))
                os.remove(bin_out)
            result.append(hex_out)

        if image_type:
            if ImageType.UPGRADE.name == image_type.upper():
                os.remove(hex_file)
        result = tuple(result) if len(result) > 0 else None
        return result

    def sign_single_hex(self, slot, image_type, hex_in, hex_out=None, encrypt_key=None):
        """
        Signs single hex file with a single key using imgtool.
        :param slot: Slot data from policy file.
        :param image_type: The type of the image.
        :param hex_in: The hex file to sign.
        :param hex_out: The name of the output file. If not specified,
                        the default name will be used.
        :param encrypt_key: path to public key file for the image encryption
        :return: The name of the signed hex file.
        """
        # Find in policy data necessary for image signing
        data = self.parser.get_image_data(image_type, slot['id'])
        if len(data) > 0:
            address, size = data[0]
        else:
            raise ValueError('Invalid image ID.')

        for key_pair in self.parser.get_keys():
            if key_pair.image_type is not None and \
               key_pair.image_type.name in ('BOOT', 'UPGRADE') and \
               key_pair.key_id in slot["boot_auth"]:

                key = key_pair
                break

        # Define signed hex file name
        if hex_out is None:
            hex_out = '{0}_{2}{1}'.format(*os.path.splitext(hex_in) + ('signed',))

        is_smif = image_type == 'UPGRADE' and slot['smif_id'] > 0
        erased_val = '0xff' if is_smif else '0'

        args = [
            '--key', key.pem_key_path,
            '--header-size', hex(self.memory_map.MCUBOOT_HEADER_SIZE),
            '--pad-header',
            '--align', '8',
            '--version', slot['version'],
            '--slot-size', hex(size),
            '--overwrite-only',
            '--erased-val', erased_val,
            '--security-counter', str(slot['rollback_counter']),
            hex_in,
            hex_out,

            # Add Cypress TLV
            '--custom-tlv', '0x81', 'B', str(slot['id']),
        ]

        if encrypt_key is not None:
            args.append('--encrypt')
            args.append(encrypt_key)

        if image_type != ImageType.BOOT.name:
            args.append('--pad')
        logger.debug(f'Run imgtool with arguments: {args}')

        try:
            imgtool.sign(args)
        except SystemExit as e:
            rc = e.code

        if rc != 0:
            logger.error('Signature is not added!')
            logger.error('imgtool finished execution with errors!')
        else:
            logger.info(f'Image for slot {image_type} signed successfully! ({hex_out})')
            return hex_out
