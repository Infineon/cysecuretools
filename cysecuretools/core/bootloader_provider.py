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
from cysecuretools.core.project import ProjectInitializer
from cysecuretools.core.cy_bootloader_map_parser import CyBootloaderMapParser

logger = logging.getLogger(__name__)


class BootloaderProvider:
    def __init__(self, target):
        self.target = target
        self.policy_parser = target.policy_parser
        self.mode = self.policy_parser.get_cybootloader_mode()
        self.cb_dir = ProjectInitializer.prebuilt_dir_name

    def get_hex_path(self):
        """
        Gets CyBootloader hex-file path.
        :return: File path.
        """
        if self.mode == 'custom':
            filename = self.policy_parser.get_cybootloader_hex()
        else:
            filename = CyBootloaderMapParser.get_filename(
                self.target.name, self.mode, 'hex')
            if filename is None:
                logger.error(f'CyBootloader data not found for target '
                             f'{self.target.name}, mode \'{self.mode}\'')
                return ''
            if self.target.cwd:
                filename = os.path.join(self.target.cwd, self.cb_dir, filename)
            else:
                filename = os.path.join(self.target.target_dir, self.cb_dir,
                                        filename)
        return os.path.abspath(filename)

    def get_jwt_path(self, mode=None):
        """
        Gets CyBootloader jwt-file path.
        :param mode: CyBootloader mode (release or debug). If not
               specified, the mode specified in policy will be used
        :return: File path.
        """
        if not mode:
            mode = self.mode
        if mode == 'custom':
            filename = self.policy_parser.get_cybootloader_jwt()
        else:
            filename = CyBootloaderMapParser.get_filename(
                self.target.name, mode, 'jwt')
            if filename is None:
                logger.error(f'CyBootloader data not found for target '
                             f'{self.target.name}, mode \'{mode}\'')
                return ''

            if self.target.cwd:
                filename = os.path.join(self.target.cwd, self.cb_dir, filename)
            else:
                filename = os.path.join(self.target.target_dir, self.cb_dir,
                                        filename)
        return os.path.abspath(filename)
