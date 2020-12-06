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
import posixpath
import json
import logging
from pathlib import Path
from shutil import copyfile
import cysecuretools.core.jsonpath as jsonpath
from cysecuretools.core.project import ProjectInitializer

logger = logging.getLogger(__name__)


# The sufficient list of files to initialize the
# project. The policy directory is copied entirely
project_files = {
    'packets': {
        'control_dap_cert.json',
        'cy_auth_1m_b0_sample.jwt',
        'cy_auth_2m_b0_sample.jwt',
        'cy_auth_2m_s0_sample.jwt',
        'cy_auth_512k_b0_sample.jwt',
        'entrance_exam.jwt',
    },
    'keys': {
        'hsm_state.json',
        'oem_state.json',
    }
}


class ProjectInitializerMXS40V1(ProjectInitializer):
    def __init__(self, target):
        super().__init__()
        self.policy_parser = target.policy_parser
        self.packets_dir_name = os.path.basename(os.path.normpath(
            self.policy_parser.get_provisioning_packet_dir()))
        self.cwd = os.getcwd()
        self.target_dir = target.target_dir
        self.default_policy_file_name = os.path.basename(os.path.normpath(
            target.policy))

        self.packets_src = os.path.join(self.target_dir, self.packets_dir_name)
        self.policy_src = os.path.join(self.target_dir, self.policy_dir_name)
        self.keys_src = os.path.abspath(os.path.join(
            self.target_dir, self.common_prebuilt_dir_name))
        self.prebuilt_src = os.path.join(
            self.target_dir, self.prebuilt_dir_name)

    def init(self, cwd=None, overwrite=None):
        """
        Initializes new project
        :param cwd: Current working directory
        :param overwrite: Indicates whether to overwrite project files
               if already exist. If the value is None, an interactive prompt
               will ask whether to overwrite existing files
        """
        if cwd:
            self.cwd = cwd
        exist = list()

        keys_dst = os.path.join(self.cwd, self.keys_dir_name)
        packets_dst = os.path.join(self.cwd, os.path.basename(
            os.path.normpath(self.packets_src)))

        if overwrite is None:
            # Check packets existence
            exist.extend(self.get_existent(packets_dst,
                                           project_files['packets']))

            # Check policies existence
            policy_dst = os.path.join(self.cwd, self.policy_dir_name)
            files = self.get_policy_src_files()
            try:
                for entry in os.scandir(policy_dst):
                    if entry.name in files:
                        exist.extend([entry.path])
            except FileNotFoundError:
                pass

            # Check prebuilt existence
            src_files = self.get_prebuilt_files(self.prebuilt_src)
            prebuilt_dst = os.path.join(self.cwd, self.prebuilt_dir_name)
            dst_files = self.get_prebuilt_files(prebuilt_dst)
            try:
                for item in dst_files:
                    if item in src_files:
                        exist.extend([os.path.join(prebuilt_dst, item)])
            except FileNotFoundError:
                pass

            # Check keys existence
            exist.extend(self.get_existent(keys_dst, project_files['keys']))

            # Create a project
            if exist:
                for file in exist:
                    print(file)
                answer = input('Above files exist and will be overwritten. '
                               'Continue? (y/n): ')
                if answer.strip() == 'y':
                    self.create_project(packets_dst, keys_dst)
                else:
                    logger.info('Skip project creation')
            else:
                self.create_project(packets_dst, keys_dst)
        elif overwrite is True:
            self.create_project(packets_dst, keys_dst)
        else:
            logger.info('Skip project creation')

    def create_project(self, packets_dst, keys_dst):
        """
        Creates project in cwd
        :param packets_dst: Packets destination directory
        :param keys_dst: Keys destination directory
        """
        self.copy_files(self.packets_src, packets_dst,
                        project_files['packets'], False)
        self.copy_files(self.keys_src, keys_dst, project_files['keys'])
        self.copy_policies()
        self.copy_prebuilt()
        self.update_policies()
        self.create_config_file()

    @staticmethod
    def get_existent(dst, files):
        """
        Gets the list of the project files existent in the cwd
        :param dst: Directory where to search
        :param files: Name of files to search
        :return: List of the existent files
        """
        existent_files = []
        try:
            for entry in os.scandir(dst):
                if entry.name in files:
                    existent_files.append(entry.path)
        except FileNotFoundError:
            pass
        return existent_files

    def get_policy_src_files(self):
        """
        Gets names of the policy files in the source directory
        """
        files = [f for f in os.listdir(self.policy_src) if f.endswith('.json')]
        return files

    @staticmethod
    def get_prebuilt_files(directory):
        """
        Gets names of the prebuilt files in the specified directory
        """
        files = [os.path.join(dp, f) for dp, dn, fn in
                 os.walk(directory) for f in fn
                 if f.endswith('hex') or f.endswith('jwt')]

        files = [os.path.relpath(f, directory) for f in files]
        return files

    def copy_policies(self):
        """
        Copies policy files from the package directory to the
        project directory
        """
        src = self.policy_src
        dst = os.path.join(self.cwd, self.policy_dir_name)
        files = self.get_policy_src_files()
        self.copy_files(src, dst, files)

    def copy_prebuilt(self):
        """
        Copies prebuilt files from the package directory to the
        project directory
        """
        src = self.prebuilt_src
        dst = os.path.join(self.cwd, self.prebuilt_dir_name)
        files = self.get_prebuilt_files(src)
        self.copy_files(src, dst, files)

    @staticmethod
    def copy_files(src_dir, dst_dir, file_names, warn=True):
        """
        Copies files with the names specified in the list from
        source to destination directory
        :param src_dir: The source directory
        :param dst_dir: The destination directory
        :param file_names: List of of the file names
        :param warn: Warn if file does not exist
        """
        Path(dst_dir).mkdir(parents=True, exist_ok=True)
        for name in file_names:
            src_file = os.path.join(src_dir, name)
            dst_file = os.path.join(dst_dir, name)
            try:
                Path(os.path.dirname(dst_file)).mkdir(parents=True,
                                                      exist_ok=True)
                copyfile(src_file, dst_file)
                logger.info(f'Copy \'{dst_file}\'')
            except FileNotFoundError:
                if warn:
                    logger.warning(f'File \'{src_file}\' does not exist')

    def create_config_file(self):
        new_path = os.path.join(self.policy_dir_name,
                                self.default_policy_file_name)
        ProjectInitializer.set_default_policy(new_path)

    def update_policies(self):
        """
        Updates paths pointing to the package to the paths
        pointing to the project in policy destination files.
        """
        policy_files = self.get_policy_src_files()
        for policy in policy_files:
            policy_path = os.path.join(self.cwd, self.policy_dir_name, policy)
            with open(policy_path) as f:
                json_str = f.read()
                policy = json.loads(json_str)

            self.update_bootloader_keys_section(policy)
            self.update_pre_build_section(policy)

            with open(policy_path, 'w') as f:
                json.dump(policy, f, indent=4)

    def update_pre_build_section(self, policy):
        update_nodes = ['oem_public_key', 'oem_private_key', 'hsm_public_key',
                        'hsm_private_key']
        for k, v in policy['pre_build'].items():
            if k in update_nodes:
                filename = os.path.basename(os.path.normpath(v))
                new_path = posixpath.join('../', self.keys_dir_name, filename)
                policy['pre_build'][k] = new_path

    def update_bootloader_keys_section(self, policy):
        path = 'boot_upgrade.firmware.0.bootloader_keys.0.key'
        old_value = jsonpath.get_node_value(policy, path)
        filename = os.path.basename(os.path.normpath(old_value))
        new_value = posixpath.join('../', self.keys_dir_name, filename)
        jsonpath.set_node_value(policy, path, new_value)
