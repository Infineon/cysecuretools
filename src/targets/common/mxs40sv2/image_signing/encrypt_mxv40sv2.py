"""
Copyright 2021-2023 Cypress Semiconductor Corporation (an Infineon company)
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
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

NONCE_SIZE = 12


class EncryptorMXS40Sv2:
    def __init__(self, key):
        if isinstance(key, bytes):
            self.key = key
        else:
            with open(key, 'rb') as f:
                self.key = f.read()
        cipher = Cipher(algorithms.AES(self.key), modes.ECB())
        self.encryptor = cipher.encryptor()

    @staticmethod
    def _load(image_path):
        with open(image_path, 'rb') as f:
            image = f.read()
        return image

    @staticmethod
    def _save(data, output_path):
        with open(output_path, 'wb') as f:
            f.write(data)

    def encrypt(self, image, initial_counter, nonce=None):
        """
        Encrypts a byte array using a customized AES-CTR mode
        where a counter is incremented by 16 per block.
        A nonce format is (128 bit):
            bits 0...31 - counter + initial values
            bits 32...127 - random nonce
        """
        if nonce is None:
            nonce = os.urandom(NONCE_SIZE)
        chunk_size = 16
        counter = 0
        ciphertext = bytes()
        for i in range(0, len(image), chunk_size):
            indata = struct.pack('<I', initial_counter + counter) + nonce[:12]
            counter += chunk_size
            cipher_block = self.encryptor.update(indata)
            chunk = image[i:i + chunk_size]
            ciphertext += bytes(a ^ b for a, b in zip(chunk, cipher_block))
        self.encryptor.finalize()
        return ciphertext, nonce

    def encrypt_image(self, input_path, initial_counter=None, output_path=None,
                      nonce_path=None):
        """
        Encrypts an image each time using new random nonce.
        Saves the nonce and the encrypted image to specified locations.
        If the output locations are not given the output files are saved
        in the same location as the input image with predefined names.
        """
        image = self._load(input_path)

        init = 0 if initial_counter is None else initial_counter
        ciphertext, nonce = self.encrypt(image, init)

        if output_path is None:
            output_path = '{0}_{2}{1}'.format(
                *os.path.splitext(input_path) + ('encrypted',))

        if nonce_path is None:
            nonce_path = '{0}_{2}{1}'.format(
                *os.path.splitext(input_path) + ('nonce',))

        self._save(ciphertext, output_path)
        self._save(nonce, nonce_path)

        return output_path, nonce_path
