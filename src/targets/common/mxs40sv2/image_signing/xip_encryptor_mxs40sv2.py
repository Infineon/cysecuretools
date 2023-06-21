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
from .encrypt_mxv40sv2 import EncryptorMXS40Sv2
from .....execute.imgtool.custom_encryptor import CustomEncryptor


class XipEncryptor(CustomEncryptor):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.header_size = kwargs.get('header_size')
        self.image_addr = kwargs.get('image_addr')

    def encrypt(self, image, **kwargs) -> bytes:
        nonce = kwargs.get('nonce')
        plainkey = kwargs.get('plainkey')

        encryptor = EncryptorMXS40Sv2(plainkey)
        ciphertext, _ = encryptor.encrypt(
            image, self.image_addr + self.header_size, nonce=nonce)
        return ciphertext
