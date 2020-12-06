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
        self.build_mode = self.policy_parser.get_cybootloader_mode()
        self.upgrade_mode = self.policy_parser.get_upgrade_mode()
        self.cb_dir = ProjectInitializer.prebuilt_dir_name

    def hex_path(self):
        """
        Gets CyBootloader hex-file path.
        :return: File path.
        """
        if self.build_mode == 'custom':
            filename = self.policy_parser.get_cybootloader_hex()
        else:
            filename = self._get_filename_from_map('hex')

        return os.path.abspath(filename)

    def jwt_path(self, build_mode=None):
        """
        Gets CyBootloader jwt-file path.
        :param build_mode: CyBootloader mode (release or debug). If not
               specified, the mode specified in policy will be used
        :return: File path.
        """
        if not build_mode:
            build_mode = self.build_mode

        if build_mode == 'custom':
            filename = self.policy_parser.get_cybootloader_jwt()
        else:
            filename = self._get_filename_from_map('jwt')

        return os.path.abspath(filename)

    def _get_filename_from_map(self, file_type):
        try:
            filename = CyBootloaderMapParser.get_filename(
                self.target.name, self.upgrade_mode, self.build_mode, file_type)
            if self.target.cwd:
                filename = os.path.join(self.target.cwd, self.cb_dir, filename)
            else:
                filename = os.path.join(self.target.target_dir, self.cb_dir, filename)
        except KeyError as e:
            logger.error(e)
            filename = ''

        return filename
