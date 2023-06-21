"""
Copyright 2023 Cypress Semiconductor Corporation (an Infineon company)
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
import tempfile
from typing import Union

from ...core.signtool_base import SignToolBase
from ...execute.imgtool.image import TLV_VALUES
from ...execute.image_signing.image import Image, TLV
from ...execute.image_signing.image_config_parser import ImageConfigParser

logger = logging.getLogger(__name__)


class SignTool(SignToolBase):
    """Image signing and manipulations with its data"""

    def __init__(self):
        self.output = None
        self.key_path = None
        self.key_type = None
        self.erased_val = 0
        self.header_size = 32
        self.slot_size = 0x100000
        self.image_version = '0.0.0'
        self.security_counter = None
        self.align = 8
        self.pad = False
        self.confirm = False
        self.overwrite_only = False
        self.hex_addr = 0
        self.dependencies = None
        self.encrypt = None
        self.decrypted = None
        self.endian = 'little'
        self.tlv = {}
        self.prot_tlv = {}

    def initialize(self, kwargs):
        """Initializes class attributes with the keyword arguments"""
        if kwargs.get('output'):
            self.output = os.path.abspath(kwargs.get('output'))
        if kwargs.get('key_path'):
            self.key_path = os.path.abspath(kwargs.get('key_path'))
        if kwargs.get('key_type'):
            self.key_type = kwargs.get('key_type')
        if kwargs.get('erased_val'):
            self.erased_val = int(str(kwargs.get('erased_val')), 0)
        if kwargs.get('slot_size'):
            self.slot_size = int(str(kwargs.get('slot_size')), 0)
        if kwargs.get('header_size'):
            self.header_size = int(str(kwargs.get('header_size')), 0)
        if kwargs.get('align'):
            self.align = int(str(kwargs.get('align')), 0)
        self.pad = kwargs.get('pad', self.pad)
        self.confirm = kwargs.get('confirm', self.confirm)
        self.overwrite_only = kwargs.get('overwrite_only', self.overwrite_only)
        if kwargs.get('hex_addr'):
            self.hex_addr = int(str(kwargs.get('hex_addr')), 0)
        self.image_version = kwargs.get('image_version', self.image_version)
        self.security_counter = kwargs.get('security_counter')
        self.dependencies = kwargs.get('dependencies')
        self.encrypt = kwargs.get('encrypt')
        self.decrypted = kwargs.get('decrypted')
        self.endian = kwargs.get('endian', self.endian)
        if kwargs.get('tlv'):
            self.tlv.update(kwargs.get('tlv'))
        self.prot_tlv.update(self._get_config_tlvs(kwargs))
        if kwargs.get('prot_tlv'):
            self.prot_tlv.update(kwargs.get('prot_tlv'))

    def sign_image(self, image: str, **kwargs) -> Union[str, Image]:
        """Signs image. Optionally encrypts the image
        @param image: The path to the image to sign
        @param kwargs:
            :output: The path where to save signed image
            :key_path: The key used to sign the image
            :erase_val: The value, which is read back from erased flash
            :slot_size: Maximum slot size
            :header_size: Header size of the MCUboot format image
            :align: Flash alignment
            :pad: Add padding to the image trailer
            :hex_addr: Adjust the address in the hex output file
            :image_version: Sets image version in the image header
            :dependencies: Add dependence on another image.
                           Format: "(<image_ID>,<image_version>), ... "
            :encrypt: Encrypt image using the provided public key
            :prot_tlv: Protected TLVs
            :tlv: Non-Protected TLVs
            :allow_signed: Allows signing already signed image
        @return: Either path to the signed file if 'output' argument is
        specified, otherwise the image object
        """
        if not kwargs.get('allow_signed'):
            img = Image(image)
            if img.is_signed:
                raise ValueError(
                    'Signature not added. The image has been already signed')

        self.initialize(kwargs)

        if not self.is_private_key(self.key_path):
            raise ValueError(f"Signing image with public key '{self.key_path}'")

        img = self._sign(image, self.key_path)

        if isinstance(img, str):
            logger.info('Image signed successfully (%s)', img)

        return img

    def add_metadata(self, image, **kwargs):
        """Adds MCUboot metadata to the image. Optionally encrypts
        the image
        @param image: The path to the image to add the metadata
        @param kwargs:
            :output: The path where to save signed image
            :erase_val: The value, which is read back from erased flash
            :slot_size: Maximum slot size
            :header_size: Header size of the MCUboot format image
            :align: Flash alignment
            :pad: Add padding to the image trailer
            :hex_addr: Adjust the address in the hex output file
            :image_version: Sets image version in the image header
            :dependencies: Add dependence on another image.
                           Format: "(<image_ID>,<image_version>), ... "
            :encrypt: Encrypt image using the provided public key
            :decrypted: The path where to save decrypted image payload
            :prot_tlv: Protected TLVs
            :tlv: Non-Protected TLVs
        @return: Different results based on input parameters:
                  - (output, None) - if the 'output' argument is provided
                  - (output, decrypted) - if the 'output' argument is provided
                    and encryption is used
                  - (Image, None) - if the 'output' argument is not provided
                  - (Image, Image) - if the 'output' argument is not
                    provided and encryption is used
        """
        self.initialize(kwargs)

        if self.encrypt and not isinstance(self.output, type(self.decrypted)):
            raise ValueError("Arguments 'output' and 'decrypted' must be "
                             "initialized together")

        img = self._sign(image, None)

        if isinstance(img, str):
            logger.info("Image saved to '%s'", img)

        decrypted = None
        if self.encrypt:
            if isinstance(img, Image):
                with open(image, 'rb') as rf:
                    repl = rf.read()
                decrypted = self.replace_image_body(img.data, repl,
                                                    self.header_size)
                decrypted = Image(decrypted)
            else:
                if image.endswith('.hex'):
                    with tempfile.NamedTemporaryFile(dir=os.path.dirname(image),
                                                     suffix='.bin',
                                                     delete=False) as tf:
                        temp_bin = tf.name
                    self.hex2bin(image, temp_bin)
                    self.replace_image_body(img, temp_bin, self.header_size,
                                            output=self.decrypted)
                    os.unlink(temp_bin)
                else:
                    self.replace_image_body(
                        img, image, self.header_size, output=self.decrypted)
                decrypted = self.decrypted
                logger.info(
                    "Saved decrypted image to '%s'", os.path.abspath(decrypted))
                logger.info(
                    'Image signature is calculated based on decrypted data. '
                    'Ensure the decrypted image is used for signing with HSM')

        return img, decrypted

    @staticmethod
    def extract_payload(image, output=None) -> Union[str, bytes]:
        """Extracts a part to be signed from MCUboot image
        @param image: Path to the image with MCUboot metadata or the image bytes
        @param output: The path where to save the payload
        @return: Payload bytes
        """
        img = Image(image)
        if not img.has_metadata:
            raise ValueError('The image does not have metadata')
        if output:
            with open(output, 'wb') as f:
                f.write(img.payload)
            logger.info("Saved image payload to '%s'", os.path.abspath(output))
        return img.payload

    @staticmethod
    def add_signature(image, signature, alg, output=None):
        """Adds ECDSA256 signature into MCUboot image
        @param image: Path to the image with MCUboot metadata or the image bytes
        @param signature: Path to the binary containing signature or
        the signature bytes
        @param alg: Signature algorithm
        @param output: The path where to save the payload
        @return: Signed image bytes
        """
        img = Image(image)
        if isinstance(signature, bytes):
            sig_bytes = signature
        else:
            with open(signature, 'rb') as f:
                sig_bytes = f.read()

        if alg == 'ECDSA-P256':
            tag = TLV_VALUES['ECDSA256']
        elif alg == 'RSA2048':
            tag = TLV_VALUES['RSA2048']
        elif alg == 'RSA4096':
            tag = TLV_VALUES['RSA4096']
        else:
            raise ValueError('Unsupported signature algorithm')

        img.remove_tlv(tag)
        img.add_tlv(TLV(tag, sig_bytes))

        if output:
            with open(output, 'wb') as f:
                f.write(img.data)
            logger.info("Saved image to '%s'", os.path.abspath(output))
        return img.data

    @staticmethod
    def verify_image(image, key):
        """Verifies the image with a key
        @param image: The file to verify
        @param key: Verification key
        @return: True if success, otherwise False
        """
        img = image if isinstance(image, Image) else Image(image)

        if not img.is_signed:
            if isinstance(image, Image):
                raise ValueError('Image is not signed')
            raise ValueError(f"Image is not signed '{os.path.abspath(image)}'")

        pubkey = SignTool.load_public_key(key)
        result = img.verify(pubkey)

        if result:
            logger.info('Image verified successfully')
        else:
            logger.error('Invalid image signature')

        return result

    def _sign(self, image, key):
        temp_out = None
        if not self.output:
            temp_out = tempfile.NamedTemporaryFile(suffix='.bin', delete=False)
            temp_out.close()
            self.output = temp_out.name
            logger.debug("Created temporary file '%s'", self.output)

        args = {
            'key': self.load_key(key) if key else None,
            'public_key_format': 'hash',
            'align': self.align,
            'version': self.image_version,
            'pad_sig': False,
            'header_size': self.header_size,
            'pad_header': True,
            'slot_size': self.slot_size,
            'pad': self.pad,
            'confirm': self.confirm,
            'max_sectors': None,
            'overwrite_only': self.overwrite_only,
            'endian': self.endian,
            'infile': image,
            'outfile': self.output,
            'dependencies': self.dependencies,
            'load_addr': None,
            'hex_addr': self.hex_addr,
            'erased_val': str(self.erased_val),
            'save_enctlv': False,
            'security_counter': self.security_counter,
            'boot_record': None,
            'custom_tlv': list(self.prot_tlv.items()),
            'custom_tlv_unprotected': list(self.tlv.items()),
            'rom_fixed': None,
            'use_random_iv': False,
            'encrypt': self.load_key(self.encrypt) if self.encrypt else None,
            'image_addr': 0
        }

        try:
            self._call_imgtool_sign(args)
        except Exception:
            logger.error('Signature not added')
            logger.error('imgtool finished execution with errors')
            raise

        img = None
        if temp_out:
            img = Image(self.output)
            os.unlink(self.output)
            logger.debug("Deleted temporary file '%s'", self.output)
            self.output = None

        return self.output if self.output else img

    @staticmethod
    def _get_config_tlvs(kwargs):
        image_config = kwargs.get('image_config')
        tlvs = {}
        if image_config:
            if os.path.isfile(image_config):
                tlvs = ImageConfigParser.get_image_tlvs(image_config)
            else:
                raise FileNotFoundError(
                    f"Image configuration file '{image_config}' not found")
        return tlvs
