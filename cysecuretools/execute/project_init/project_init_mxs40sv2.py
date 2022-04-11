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
import logging
import importlib
from pathlib import Path
from cysecuretools.core.project import ProjectInitializer
from cysecuretools.targets.common.mxs40sv2.flow_parser import FlowParser

logger = logging.getLogger(__name__)

project_files = {
    'packets': {
        'templates': [
            'debug_cert.json',
            'rsa_key_tmpl.json',
        ]
    }
}


class ProjectInitializerMXS40Sv2(ProjectInitializer):
    """
    A class that implements project creation logic for
    MXS40Sv2 platform
    """

    def __init__(self, target):
        super().__init__(target)
        self.packets_src = os.path.join(self.target_dir, self.packets_dir_name)
        self.apps_src = os.path.join(self.target_dir, self.packets_dir_name)
        self.keys_src = os.path.join(self.target_dir, self.keys_dir_name)
        self.flow_parser = FlowParser(self.target)
        if self.policy_parser.policy_dir is None:
            if self.is_project():
                self.policy_dir = os.path.join(self.cwd, self.policy_dir_name)
            else:
                self.policy_dir = os.path.join(target.target_dir, self.policy_dir_name)
        else:
            self.policy_dir = self.policy_parser.policy_dir
        self.test_packages = target.test_packages
        self.test_pkg_type = None

    @property
    def packets_dir(self):
        """ Gets a path to the packets directory in the project """
        return os.path.abspath(os.path.join(
            self.policy_dir, '..', self.packets_dir_name))

    @property
    def apps_dir(self):
        """ Gets a path to the apps directory in the project """
        return os.path.join(self.packets_dir, self.apps_dir_name)

    @property
    def pkg_apps_dir(self):
        """ Gets a path to the apps directory in the package """
        return os.path.join(
            self.target_dir, self.packets_dir_name, self.apps_dir_name)

    @property
    def test_policies_dir(self):
        """ A path to a directory containing test policies """
        if self.test_pkg_type is not None:
            package_data = self.test_packages.get(self.test_pkg_type)
            package_name = package_data['package']
            try:
                module = importlib.import_module(package_name)
                if module.__file__ is None:
                    raise ImportError(f"No module named '{package_name}'")
            except ImportError as e:
                raise ImportError(
                    f'Test applications not found. {e.msg}') from e
            return module.TEST_POLICY_DIR
        return None

    def init(self, cwd=None, overwrite=None, **kwargs):
        """
        Initializes new project
        :param cwd: Current working directory
        :param overwrite: Indicates whether to overwrite project files
               if already exist. If the value is None, an interactive prompt
               will ask whether to overwrite existing files
        """
        if cwd:
            self.cwd = cwd

        self.test_pkg_type = kwargs.get('testapps')
        self.flow_parser.test_pkg_type = self.test_pkg_type
        apps_paths = self.flow_parser.get_apps_paths()

        packets_dst = os.path.join(self.cwd, os.path.basename(
            os.path.normpath(self.packets_src)))

        if overwrite is None:
            exist = []

            # Check apps existence
            for d, f in apps_paths.items():
                files = self._filenames_from_dir(os.path.dirname(f))
                app_dst = os.path.join(packets_dst, self.apps_dir_name, d)
                exist.extend(self.get_existent(app_dst, files))

            # Check templates
            exist.extend(self.get_existent(
                packets_dst, project_files['packets']['templates']))

            # Check policies existence
            policy_dst = os.path.join(self.cwd, self.policy_dir_name)
            files = self.get_policy_src_files(self.policy_src)
            exist.extend(self.get_existent(policy_dst, files))

            # Check keys existence
            keys_dst = os.path.join(self.cwd, self.keys_dir_name)
            files = self._filenames_from_dir(self.keys_src, 'pem')
            exist.extend(self.get_existent(keys_dst, files))

            # Create a project
            if exist:
                print('%s' % '\n'.join(exist))
                answer = input(f'{len(exist)} files exist and will be '
                               f'overwritten. Continue? (y/n): ')
                if answer.strip() == 'y':
                    self.create_project(packets_dst)
                else:
                    logger.info('Skip project creation')
            else:
                self.create_project(packets_dst)
        elif overwrite is True:
            self.create_project(packets_dst)
        else:
            logger.info('Skip project creation')

    def create_project(self, packets_dst):
        """
        Creates project in cwd
        :param packets_dst: Packets destination directory
        """
        self.copy_apps()
        Path(os.path.join(self.cwd, 'keys')).mkdir(parents=True, exist_ok=True)
        self.copy_files(self.packets_src, packets_dst,
                        project_files['packets']['templates'])
        self.copy_policies()
        if self.test_pkg_type is not None:
            self.copy_policies(src=self.test_policies_dir)
        self.copy_keys()
        self.create_config_file()

    def copy_policies(self, src=None):
        """
        Copies policy files from the package directory to the
        project directory
        """
        src = self.policy_src if src is None else src
        dst = os.path.join(self.cwd, self.policy_dir_name)
        files = self.get_policy_src_files(src)
        self.copy_files(src, dst, files)

    def copy_keys(self):
        """
        Copies key files from the package directory to the
        project directory
        """
        src = self.keys_src
        dst = os.path.join(self.cwd, self.keys_dir_name)
        files = self._filenames_from_dir(self.keys_src, ext='pem')
        self.copy_files(src, dst, files)

    def copy_apps(self):
        """
        Copies ram applications data from the package directory to the
        project directory
        """
        apps_paths = self.flow_parser.get_apps_paths()
        apps_dir_dst = os.path.join(
            self.cwd, self.packets_dir_name, self.apps_dir_name)
        for app_name, file_name in apps_paths.items():
            dst = os.path.join(apps_dir_dst, app_name)
            src = os.path.dirname(file_name)
            files = self._filenames_from_dir(src)
            self.copy_files(src, dst, files)

    def create_config_file(self):
        """ Creates project configuration file """
        self.create_config(self.target.default_policy)
