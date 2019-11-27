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
import subprocess
from shutil import copy2
from pathlib import Path
from intelhex import hex2bin, bin2hex
import cysecuretools.execute.encrypted_image_runner as encryptor
from cysecuretools.targets.common.policy_parser import PolicyParser, ImageType, KeyType

logger = logging.getLogger(__name__)


class SignTool:
    def __init__(self, policy_file, memory_map):
        # Resolve paths
        self.policy_dir = os.path.dirname(Path(policy_file).absolute())
        self.PKG_PATH = os.path.dirname(os.path.realpath(__file__))
        self.IMG_TOOL_PATH = os.path.join(self.PKG_PATH, '../imgtool/imgtool.py')
        self.parser = PolicyParser(policy_file)
        self.policy = PolicyParser.get_json(policy_file)
        self.memory_map = memory_map

    def sign_image(self, hex_file, image_id):
        """
        Signs hex file with the key specified in the policy file.
        Converts binary file of the signed image.
        Creates copy of unsigned hex file.
        Encrypts UPGRADE image if the policy file contains encryption key
        :param hex_file: The hex file to sign.
        :param image_id: The ID of the firmware in policy file.
        :return: Path to the signed files. One file per slot.
        """
        result = []
        slot = self.parser.get_slot(image_id)
        for image in slot['resources']:
            # Sign BOOT image and encrypt+sign UPGRADE image
            if 'encrypt' in slot and slot['encrypt'] and image['type'] == ImageType.UPGRADE.name:
                hex_out = self.encrypt_image(slot, image['type'], unsigned_boot_hex)
            else:
                if image['type'] == ImageType.UPGRADE.name:
                    if 'upgrade' not in slot or not slot['upgrade']:
                        continue  # skip generating hex file for UPGRADE slot if it is disabled

                # Preserve hex file for cm4 image
                if slot['id'] == self.memory_map.NSPE_IMAGE_ID:
                    out_cm4_hex = '{0}_{2}{1}'.format(*os.path.splitext(hex_file) + ('cm4',))
                    copy2(hex_file, out_cm4_hex)

                # Sign image
                if image['type'] == ImageType.BOOT.name:
                    unsigned_boot_hex = '{0}_{2}{1}'.format(*os.path.splitext(hex_file) + ('unsigned',))
                    copy2(hex_file, unsigned_boot_hex)
                    hex_out = self.sign_single_hex(slot, image['type'], hex_file, hex_file)

                # Produce hex file for slot1
                if image['type'] == ImageType.UPGRADE.name:
                    output_name = '{0}_{2}{1}'.format(*os.path.splitext(hex_file) + ('upgrade',))
                    hex_out = self.sign_single_hex(slot, image['type'], unsigned_boot_hex, output_name)
                    bin_out = '{0}.bin'.format(os.path.splitext(hex_out)[0])
                    hex2bin(hex_out, bin_out)
                    bin2hex(bin_out, output_name, offset=int(image['address']))
                    os.remove(bin_out)
                    logger.info(f'Image UPGRADE: {hex_out}\n')

                # Replace input hex file with the
            result.append(hex_out)
        os.remove(unsigned_boot_hex)
        result = tuple(result) if len(result) > 0 else None
        return result

    def sign_single_hex(self, slot, image_type, hex_in, hex_out=None):
        """
        Signs single hex file with a single key using imgtool.
        :param slot: Slot data from policy file.
        :param image_type: The type of the image.
        :param hex_in: The hex file to sign.
        :param hex_out: The name of the output file. If not specified, the default name will be used.
        :return: The name of the signed hex file.
        """
        # Find in policy data necessary for image signing
        address, size = self.parser.get_image_data(slot['id'], image_type)
        for key_pair in self.parser.get_keys():
            if key_pair.image_type.name == image_type:
                key = key_pair
                break

        # Define signed hex file name
        if hex_out is None:
            hex_out = '{0}_{2}{1}'.format(*os.path.splitext(hex_in) + ('signed',))

        args = [
             sys.executable, self.IMG_TOOL_PATH,
             'sign',
             '--key', key.pem_key_path,
             '--header-size', hex(self.memory_map.MCUBOOT_HEADER_SIZE),
             '--pad-header',
             '--align', '8',
             '--version', slot['version'],
             '--image-id', str(slot['id']),
             '--rollback_counter', str(slot['rollback_counter']),
             '--slot-size', hex(size),
             '--overwrite-only',
             hex_in,
             hex_out
        ]
        if image_type != ImageType.BOOT.name:
            args.append('--pad')
        logger.debug(f'Run imgtool with arguments: {args}')

        process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stderr = process.communicate()[1]  # catch stderr outputs
        rc = process.wait()

        if rc != 0:
            logger.error('Signature is not added!')
            logger.error(f'Message from imgtool: {stderr.decode("utf-8")}')
            logger.error('imgtool finished execution with errors!')
        else:
            logger.info(f'Image for slot {image_type} signed successfully!')
            return hex_out

    def encrypt_image(self, slot, image_type, hex_in):
        """
        Signs image, encrypts image and signs it again.
        :param slot: Slot data from policy file.
        :param image_type: The type of the image.
        :param hex_in: The hex file to encrypt and sign.
        :return: Encrypted and signed file path.
        """
        # Find in policy data necessary for image signing
        address, size = self.parser.get_image_data(slot['id'], image_type)
        for key_pair in self.parser.get_keys():
            if key_pair.key_type == KeyType.signing and key_pair.image_type.name == image_type:
                sign_key = key_pair.pem_key_path
            elif key_pair.key_type == KeyType.encryption:
                encrypt_key = key_pair.json_key_path
            elif key_pair.key_type == KeyType.device_public:
                pub_key = key_pair.pem_key_path

        args = [
            '--sdk-path', self.PKG_PATH,
            '--hex-file', hex_in,
            '--key-priv', sign_key,
            '--key-pub', pub_key,
            '--key-aes', encrypt_key,
            '--ver', slot['version'],
            '--img-id', str(slot['id']),
            '--rlb-count', str(slot['rollback_counter']),
            '--slot-size', hex(size),
            '--img-offset', address,
            '--pad', 1
        ]

        logger.debug(f'Run encryption with arguments: {args}')
        try:
            encryptor.main(args)
        except SystemExit as e:
            if e.code != 0:
                logger.error('Image encryption failed.')
            else:
                hex_out = encryptor.get_final_hex_name(hex_in)
                return hex_out
