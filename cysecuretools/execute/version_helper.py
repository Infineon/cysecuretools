"""
Copyright (c) 2020 Cypress Semiconductor Corporation

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
from packaging import version
from cysecuretools.version import __version__
from cysecuretools.targets import target_map, get_target_builder
from cysecuretools.core.target_director import TargetDirector
from cysecuretools.execute.image_cert import ImageCertificate
from cysecuretools.core.bootloader_provider import BootloaderProvider

logger = logging.getLogger(__name__)


class VersionHelper:
    """
    Helper class that encapsulates the routine for getting a version
    of different parts of the package
    """

    CST_2_1_0_SFB_VER = '4.0.1.1267'

    @staticmethod
    def device_bootloader_version(tool, target):
        """
        Reads bootloader version from device
        """
        version = 'unknown'
        cert = ImageCertificate.read_image_certificate(tool, target)
        if cert:
            try:
                version = ImageCertificate.get_version(cert)
            except KeyError:
                pass
        return version

    @staticmethod
    def package_bootloader_version(targets):
        """
        Gets a list of bootloader version(s) bundled with the package
        """
        versions = []
        for target_name in targets:
            director = TargetDirector()
            get_target_builder(director, target_name)
            target = director.get_target(None, target_name, None)
            bootloader_provider = BootloaderProvider(target)
            jwt_filename = bootloader_provider.jwt_path(build_mode='release')
            if not os.path.isfile(jwt_filename):
                logger.error(f'File {jwt_filename} not found')
                continue
            try:
                version = ImageCertificate.get_version(jwt_filename)
            except KeyError:
                version = 'unknown'
            if len(targets) == 1:
                versions.append(f'{version}')
            else:
                target_name = target_map[target.name]["display_name"]
                versions.append(f'\t\t{target_name}: {version}')
        return versions

    @staticmethod
    def sfb_version(tool, target):
        """
        Reads Secure Flash Boot version from device
        """
        entrance_exam = target.entrance_exam(target)
        return entrance_exam.read_sfb_version(tool)

    @staticmethod
    def print_version(targets):
        """
        Prints the package version and CyBootloader version bundled with
        the package for the specified targets
        """
        versions = VersionHelper.package_bootloader_version(targets)
        print('\nPackage:')
        print(f'\tCySecureTools: {__version__}')
        end_str = '' if len(versions) == 1 or not versions else '\n'
        print('\tCyBootloader: ', end=end_str)
        if versions:
            unique = list(dict.fromkeys(versions))
            for item in unique:
                print(item)
        else:
            print('unknown')

    @staticmethod
    def log_version(tool, target):
        """
        Logs SFB and CyBootloader versions
        """
        _vh = VersionHelper
        sfb_version = _vh.sfb_version(tool, target)
        logger.info(f'Secure Flash Boot version: {sfb_version}')

        dev_bootloader_ver = _vh.device_bootloader_version(tool, target)
        logger.info(f'Device CyBootloader version: {dev_bootloader_ver}')

        pkg_bootloader_ver = _vh.package_bootloader_version([target.name])[0]
        logger.info(f'Package CyBootloader version: {pkg_bootloader_ver}')

        target.entrance_exam(target).log_protection_state(tool)

    @staticmethod
    def verify_sfb_version(tool, target):
        """ Verifies Secure Flash Boot version compatibility """
        sfb_version = VersionHelper.sfb_version(tool, target)
        result = True
        if version.parse(sfb_version) <= version.parse(VersionHelper.CST_2_1_0_SFB_VER):
            result = False
            logger.error("Early Production Units detected, please get earlier "
                         "version of tools by running 'pip install --upgrade "
                         "--force-reinstall cysecuretools==2.1.0'")
        return result
