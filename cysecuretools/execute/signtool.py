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
import pathlib
import imgtool.main as imgtool
from shutil import copy2
from intelhex import hex2bin, bin2hex, IntelHex
from cysecuretools.core.enums import ImageType

logger = logging.getLogger(__name__)


class SignTool:
    def __init__(self, target):
        self.header_size = target.memory_map.VECTOR_TABLE_ADDR_ALIGNMENT
        self.parser = target.policy_parser
        self.policy_file = target.policy
        self.erased_val = None

    def sign_image(self, hex_file, image_id, image_type, encrypt_key=None,
                   erased_val=None, boot_record='default'):
        """
        Signs hex file with the key specified in the policy file.
        Converts binary file of the signed image.
        Creates copy of unsigned hex file.
        Encrypts UPGRADE image if the policy file contains encryption key
        :param hex_file: The hex file to sign.
        :param image_id: The ID of the firmware in policy file.
        :param image_type: The image type.
        :param encrypt_key: path to public key file for the image encryption
        :param erased_val: The value that is read back from erased flash
        :param boot_record: Create CBOR encoded boot record TLV.
               The sw_type represents the role of the software component
               (e.g. CoFM for coprocessor firmware). [max. 12 characters]
        :return: Path to the signed files. One file per slot.
        """
        result = []
        slot = self.parser.get_slot(image_id)

        if erased_val:
            self.erased_val = erased_val
            ih_padding = int(erased_val, 0)
            logger.warning(f'Custom value {erased_val} will be used as an '
                           f'erased value for all regions and memory types. '
                           f'Typical correct values for internal and '
                           f'external Flash memory are 0x00 and 0xFF '
                           f'respectively.')
        else:
            default_erased_val = self._default_erased_value(image_type, slot)
            ih_padding = int(default_erased_val, 0)

        if slot is None:
            logger.error(f'Image with ID {image_id} not found in \'{self.policy_file}\'')
            return None
        unsigned_hex = '{0}_{2}{1}'.format(*os.path.splitext(hex_file) + ('unsigned',))
        copy2(hex_file, unsigned_hex)

        boot_ih = IntelHex()
        boot_ih.padding = ih_padding
        boot_ih.loadfile(hex_file, 'hex')
        base_addr = boot_ih.minaddr()
        boot_bin = f'{hex_file}.bin'
        hex2bin(boot_ih, boot_bin)

        encrypted_boot = False
        first_image_result = None  # indicates first image signing success
        for image in slot['resources']:
            if image_type:
                if image['type'] != image_type.upper():
                    continue  # skip generating hex file if sign type defined and not same as current image type
            if image['type'] == ImageType.UPGRADE.name:
                if 'upgrade' not in slot or not slot['upgrade']:
                    continue  # skip generating hex file for UPGRADE slot if it is disabled

            encryption = self.parser.encryption_enabled(slot['id'])
            if encryption:
                if encrypt_key is None:
                    encrypt_key = self.parser.encrypt_key(slot['id'])
                    if encrypt_key is None:
                        raise ValueError('Encryption key not specified')
                    else:
                        if not os.path.isfile(encrypt_key):
                            raise FileNotFoundError(
                                f'Encryption key \'{encrypt_key}\' not found')
            else:
                encrypt_key = None

            if image['type'] == ImageType.BOOT.name:
                if first_image_result is False:
                    continue

                hex_out = self.sign_single_hex(slot, image['type'], boot_bin,
                                               hex_file, start_addr=base_addr,
                                               boot_record=boot_record,
                                               encrypt_key=encrypt_key)
                encrypted_boot = encrypt_key is not None
                first_image_result = hex_out is not None
                os.remove(boot_bin)
            else:
                if first_image_result is False:
                    continue

                output_name = '{0}_{2}{1}'.format(
                    *os.path.splitext(hex_file) + ('upgrade',))

                hex_out = self.sign_single_hex(
                    slot, image['type'], unsigned_hex, output_name,
                    encrypt_key, boot_record=boot_record)
                first_image_result = hex_out is not None
                if hex_out:
                    bin_out = '{0}.bin'.format(os.path.splitext(hex_out)[0])

                    if not erased_val:
                        default_erased_val = self._default_erased_value(
                            image_type, slot)
                        ih_padding = int(default_erased_val, 0)

                    upgrade_ih = IntelHex()
                    upgrade_ih.padding = ih_padding
                    upgrade_ih.loadfile(hex_out, 'hex')

                    hex2bin(upgrade_ih, bin_out)
                    bin2hex(bin_out, output_name, offset=int(image['address']))
                    os.remove(bin_out)
            if hex_out:
                result.append(hex_out)

        if encrypted_boot:
            self.replace_image_body(hex_file, unsigned_hex, ih_padding)

        if image_type:
            if ImageType.UPGRADE.name == image_type.upper():
                os.remove(hex_file)
        result = tuple(result) if len(result) > 0 else None

        return result

    def sign_single_hex(self, slot, image_type, hex_in, hex_out=None,
                        encrypt_key=None, start_addr=None, boot_record='default'):
        """
        Signs single hex file with a single key using imgtool.
        :param slot: Slot data from policy file.
        :param image_type: The type of the image.
        :param hex_in: The hex file to sign.
        :param hex_out: The name of the output file. If not specified,
                        the default name will be used.
        :param encrypt_key: path to public key file for the image encryption
        :param start_addr: Image start address
        :param boot_record: The role of the software component
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

        if self.erased_val:
            erased_val = self.erased_val
        else:
            erased_val = self._default_erased_value(image_type, slot)

        args = [
            '--key', key.pem_key_path,
            '--header-size', hex(self.header_size),
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
            '--custom-tlv', '0x81', self._align_tlv_value(slot['id']),
        ]

        if start_addr:
            args.extend(['--hex-addr', hex(start_addr - self.header_size)])

        if boot_record:
            args.extend(['--boot-record', boot_record])

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

    def replace_image_body(self, orig, repl, padding):
        """
        Replaces original image with the replacement image
        :param orig: The image to be replaced
        :param repl: The image to replace with
        :param padding: Padding value
        """
        orig_ih = IntelHex()
        orig_ih.padding = padding
        orig_ih.loadhex(orig)

        repl_ih = IntelHex()
        repl_ih.padding = padding
        repl_ih.loadhex(repl)
        minaddr = repl_ih.minaddr()
        maxaddr = repl_ih.maxaddr()

        # This adds padding if the image is not aligned to 16 Bytes
        pad_len = (maxaddr - minaddr + self.header_size) % 16
        if pad_len > 0:
            pad_len = 16 - pad_len

        for i in range(repl_ih.minaddr(), repl_ih.maxaddr() + pad_len):
            orig_ih[i] = repl_ih[i]

        orig_ih.tofile(orig, pathlib.Path(orig).suffix[1:])

    @staticmethod
    def _default_erased_value(image_type, slot):
        is_smif = image_type == 'UPGRADE' and slot['smif_id'] > 0
        return '0xff' if is_smif else '0'

    @staticmethod
    def _align_tlv_value(value):
        hex_val = str("{:02x}".format(value))
        return f'0x0{hex_val}' if len(hex_val) % 2 else f'0x{hex_val}'
