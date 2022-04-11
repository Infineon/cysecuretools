"""
Copyright (c) 2022 Cypress Semiconductor Corporation

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
from abc import ABC, abstractmethod

from intelhex import hex2bin, bin2hex


class SignTool(ABC):
    """Base class for the classes that implement
    image signing behaviour
    """

    @abstractmethod
    def sign_image(self, image_path, **kwargs):
        """Signs firmware image"""

    @staticmethod
    def bin2hex(fin, fout, offset=0):
        """Converts bin to hex"""
        return bin2hex(fin, fout, offset) == 0

    @staticmethod
    def hex2bin(fin, fout, start=None, end=None, size=None, pad=None):
        """Converts hex to bin"""
        return hex2bin(fin, fout, start=start, end=end, size=size, pad=pad) == 0
