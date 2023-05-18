"""
Copyright (c) 2021 Cypress Semiconductor Corporation

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
import re
import json
import logging
from os import path
from cysecuretools import __path__ as site_packages
from cysecuretools.version import __version__
from cysecuretools.targets.common.mxs40sv2.enums import LifecycleStage
from cysecuretools.targets.common.mxs40sv2.flow_parser import FlowParser

logger = logging.getLogger(__name__)


class VersionProviderMXS40Sv2:
    """
    This class encapsulates the routine for getting a version
    of different parts of the package
    """

    def __init__(self, target):
        self.target = target
        self.project = target.project_initializer

    def device_bootrom_version(self, tool):
        """ Reads a BootROM version from the device """
        version = tool.read32(self.target.register_map.BOOTROM_VERSION)
        build = tool.read32(self.target.register_map.BOOTROM_BUILD)
        return f'{self.convert_version(version)}.{build}'

    @staticmethod
    def convert_version(version):
        """ Converts BootRom version from int to string """
        patch = 0xff & version
        minor = 0xff & (version >> 8)
        major = 0xff & (version >> 16)
        return f'{major}.{minor}.{patch}'

    def print_fw_version(self, tool):
        """ Prints a BootROM version from the device """
        bootrom_ver = self.device_bootrom_version(tool)
        print('\tDevice:')
        print(f'\t\tBootROM: {bootrom_ver}')

    def print_version(self, **kwargs):
        """
        Prints the package version and RAMApps versions bundled with
        the package
        """
        package_apps = self.package_ramapp_versions()
        print(f'\nCySecureTools: {__version__}')
        print('\tPackage:')
        print('\t\tRAM Applications:')
        for app_name in package_apps:
            print(f'\t\t{app_name}: {package_apps.get(app_name)}')
        if self.project.is_project():
            project_apps = self.project_ramapp_versions(kwargs.get('testapps'))
            print('\tProject:')
            print('\t\tRAM Applications:')
            for app_name in project_apps:
                print(f'\t\t{app_name}: {project_apps.get(app_name)}')

        direct_url = os.path.join(
            f'{site_packages[0]}-{__version__}.dist-info', 'direct_url.json')
        logger.debug(
            'Searching package installation source in: %s', direct_url)

        if path.isfile(direct_url):
            with open(direct_url, 'r', encoding='utf-8') as f:
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
        """ Logs lifecycle stage of the device """
        self.log_lifecycle_stage(tool)

    @staticmethod
    def check_compatibility(_tool, **_):
        """
        Verifies HW compatibility.
        N/A for MXS40Sv2 platform
        """
        return True

    def log_lifecycle_stage(self, tool):
        """
        Reads device lifecycle stage and creates a
        logger info message
        """
        stage = self.get_lifecycle_stage(tool)
        logger.info('Chip lifecycle stage: %s', stage.upper())

    def get_lifecycle_stage(self, tool):
        """ Gets a lifecycle stage name """
        value = self.target.silicon_data_reader.read_lifecycle_stage(tool)
        try:
            stage = LifecycleStage(value).name
        except ValueError:
            stage = f'UNKNOWN ({value})'
        return stage

    def project_ramapp_versions(self, test_pkg_type=False):
        """ Gets a list of RAM Apps version(s) in the project """
        versions = None
        if self.project.is_project():
            versions = self._ramapp_versions(
                self.project.apps_dir, test_pkg_type=test_pkg_type)
        return versions

    def package_ramapp_versions(self):
        """
        Gets a list of RAM Apps version(s) bundled with the package
        """
        return self._ramapp_versions(self.project.pkg_apps_dir)

    def _ramapp_versions(self, apps_path, test_pkg_type=None):
        """
        Gets a dictionary with a RAM application
        name and version pairs
        """
        flow_parser = FlowParser(self.target, test_pkg_type=test_pkg_type)
        apps = flow_parser.get_apps_paths()
        versions = {}
        for app_name, config_path in apps.items():
            app_dir = os.path.basename(os.path.dirname(config_path))
            info_path = os.path.join(apps_path, app_dir, 'info.txt')
            try:
                with open(info_path, 'r', encoding='utf-8') as f:
                    info = f.read()
                    version = re.search(r'version:\s([0-9.]+)', info)[1]
            except (FileNotFoundError, TypeError):
                version = 'unknown'
            versions.update({app_name: version})
        return versions
