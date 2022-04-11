"""
Copyright (c) 2020-2021 Cypress Semiconductor Corporation

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
import json
import logging
from os import path
from packaging import version
from cysecuretools import __path__ as site_packages
from cysecuretools.version import __version__
from cysecuretools.core.project import ProjectInitializer
from cysecuretools.execute.image_cert import ImageCertificate
from cysecuretools.execute.bootloader_provider_mxs40v1 import (
    BootloaderProviderMXS40v1)

logger = logging.getLogger(__name__)


class VersionProviderMXS40v1:
    """
    Helper class that encapsulates the routine for getting a version
    of different parts of the package
    """

    CST_2_1_0_SFB_VER = '4.0.1.1267'

    def __init__(self, target):
        self.target = target

    def package_bootloader_version(self):
        """
        Gets a bootloader version bundled with the package
        :return: Version of the cybootloader bundled with the package
        """
        bootloader_provider = BootloaderProviderMXS40v1(self.target)
        jwt_path = bootloader_provider.jwt_path(build_mode='release',
                                                from_project=False)
        if not os.path.isfile(jwt_path):
            logger.error('File %s not found', jwt_path)
        try:
            bootloader_version = ImageCertificate.get_version(jwt_path)
        except KeyError:
            bootloader_version = 'unknown'
        return bootloader_version

    def project_bootloader_version(self):
        """
        Gets a bootloader version in the project dir
        :return: Version of the cybootloader from the project if it was
                 initialized, otherwise None
        """
        bootloader_provider = BootloaderProviderMXS40v1(self.target)
        jwt_path = bootloader_provider.jwt_path(build_mode='release',
                                                from_project=True)
        if ProjectInitializer.is_project():
            if not os.path.isfile(jwt_path):
                logger.error('File %s not found', jwt_path)
            try:
                bootloader_version = ImageCertificate.get_version(jwt_path)
            except KeyError:
                bootloader_version = 'unknown'
        else:
            return None
        return bootloader_version

    def device_sfb_version(self, tool):
        """
        Reads Secure Flash Boot version from device
        """
        return self.target.entrance_exam.read_sfb_version(tool)

    def device_bootloader_version(self, tool):
        """
        Reads CyBootloader version from device
        """
        bootloader_version = 'unknown'
        cert = ImageCertificate.read_image_certificate(tool, self.target)
        if cert:
            try:
                bootloader_version = ImageCertificate.get_version(cert)
            except KeyError:
                pass
        return bootloader_version

    def print_fw_version(self, tool):
        """
        Prints Secure Flash Boot and CyBootloader versions from the device
        """
        bootloader_ver = self.device_bootloader_version(tool)
        sfb_ver = self.device_sfb_version(tool)
        print('\tDevice:')
        print(f'\t\tCyBootloader: {bootloader_ver}')
        print(f'\t\tSecure Flash Boot: {sfb_ver}')

    def print_version(self):
        """
        Prints the package version and CyBootloader version bundled with
        the package for the specified targets. Find installation source
        and build version information in verbose mode [-v] [--verbose]
        """
        package_ver = self.package_bootloader_version()
        print(f'\nCySecureTools: {__version__}')
        print('\tPackage:')
        print(f'\t\tCyBootloader: {package_ver}')
        if ProjectInitializer.is_project():
            project_ver = self.project_bootloader_version()
            print('\tProject:')
            print(f'\t\tCyBootloader: {project_ver}')

        direct_url = os.path.join(
            f'{site_packages[0]}-{__version__}.dist-info', 'direct_url.json')
        logger.debug(
            'Searching package installation source in: %s', direct_url)

        if path.isfile(direct_url):
            f = open(direct_url, 'r', encoding='utf-8')
            load_data = json.load(f)
            f.close()

            url = load_data.get('url')
            if url is not None:
                logger.debug('URL: %s', url)
                vcs_info = load_data.get('vcs_info')
                if vcs_info is not None:
                    revision = vcs_info.get('requested_revision')
                    commit = vcs_info.get('commit_id')
                    if revision is not None:
                        logger.debug('Branch/tag: %s', revision)
                    if commit is not None:
                        logger.debug('Commit: %s', commit)
        else:
            logger.debug('Not able to find installation source details')

    def log_version(self, tool):
        """
        Logs SFB and CyBootloader versions
        """
        sfb_version = self.device_sfb_version(tool)
        logger.info('Secure Flash Boot version: %s', sfb_version)

        dev_bootloader_ver = self.device_bootloader_version(tool)
        logger.info('Device CyBootloader version: %s', dev_bootloader_ver)

        pkg_bootloader_ver = self.package_bootloader_version()
        logger.info('Package CyBootloader version: %s', pkg_bootloader_ver)

        self.target.entrance_exam.log_protection_state(tool)

    def verify_fw_version(self, tool):
        """ Verifies Secure Flash Boot version compatibility """
        sfb_version = self.device_sfb_version(tool)
        result = True
        if version.parse(sfb_version) <= version.parse(self.CST_2_1_0_SFB_VER):
            result = False
            logger.error("Early Production Units detected, please get earlier "
                         "version of tools by running 'pip install --upgrade "
                         "--force-reinstall cysecuretools==2.1.0'")
        return result
