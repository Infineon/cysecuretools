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
import cysecuretools
from cysecuretools.core.cy_bootloader_map_parser import CyBootloaderMapParser

logger = logging.getLogger(__name__)


class BootloaderProvider:
    def __init__(self, policy_parser, target):
        self.policy_parser = policy_parser
        self.target = target
        self.mode = self.policy_parser.get_cybootloader_mode()
        self.pkg_path = os.path.dirname(os.path.abspath(cysecuretools.__file__))

    def get_hex_path(self):
        """
        Gets CyBootloader hex-file path.
        :return: File path.
        """
        if self.mode == 'custom':
            path = self.policy_parser.get_cybootloader_hex()
        else:
            filename = CyBootloaderMapParser.get_filename(self.target, self.mode, 'hex')
            if filename is None:
                logger.error(f'CyBootloader data not found for target {self.target}, mode \'{self.mode}\'')
                return ''
            path = os.path.join(self.pkg_path, filename)
        return path

    def get_jwt_path(self):
        """
        Gets CyBootloader jwt-file path.
        :return: File path.
        """
        if self.mode == 'custom':
            path = self.policy_parser.get_cybootloader_jwt()
        else:
            filename = CyBootloaderMapParser.get_filename(self.target, self.mode, 'jwt')
            if filename is None:
                logger.error(f'CyBootloader data not found for target {self.target}, mode \'{self.mode}\'')
                return ''
            path = os.path.join(self.pkg_path, filename)
        return path
