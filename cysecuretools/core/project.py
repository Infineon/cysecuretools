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
from pathlib import Path
from shutil import copyfile
from abc import ABC, abstractmethod
from .. import pkg_globals

logger = logging.getLogger(__name__)


class ProjectInitializer(ABC):
    """ A base class for concrete targets projects initializers """

    config_file = '.cysecuretools'
    keys_dir_name = 'keys'
    policy_dir_name = 'policy'
    prebuilt_dir_name = 'prebuilt'
    packets_dir_name = 'packets'
    apps_dir_name = 'apps'

    @abstractmethod
    def __init__(self, target):
        self.target = target
        self.policy_parser = target.policy_parser
        self.target_dir = target.target_dir
        self.policy_src = os.path.join(self.target_dir, self.policy_dir_name)
        self.cwd = os.getcwd()

    @abstractmethod
    def init(self, cwd, overwrite):
        """ Initializes new project """

    @staticmethod
    def is_project(cwd=None):
        """
        Checks whether project config file exists in the cwd
        :param cwd: Current working directory
        :return: The value indicating whether project initialized in cwd
        """
        if not cwd:
            cwd = os.getcwd()
        return os.path.isfile(os.path.join(
            cwd, ProjectInitializer.config_file))

    def create_config(self, policy):
        """ Creates a project configuration file """
        ocd_name = self.target.ocds[0]
        ocd_path = None

        # Get OCD path from global settings if OCD name match
        from ..execute.programmer.programmer import ProgrammingTool
        tool = ProgrammingTool.create(ocd_name)
        if tool.require_path:
            with open(pkg_globals.SETTINGS_FILE, 'r', encoding='utf-8') as f:
                file_content = f.read()
                global_data = json.loads(file_content)
            if ocd_name == global_data['programming_tool']['name']:
                ocd_path = global_data['programming_tool']['path']

        data = {
            'user_settings': {
                'target': self.target.name,
                'ocd_name': ocd_name,
                'ocd_path': ocd_path,
                'default_policy': policy
            }
        }

        with open(ProjectInitializer.config_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)

    @staticmethod
    def get_ocd_data(cwd=None):
        """ Gets OCD name and path from the project config
        :return: A tuple (ocd_name, ocd_path)
        """
        if not cwd:
            cwd = os.getcwd()
        config_path = os.path.join(cwd, ProjectInitializer.config_file)
        with open(config_path, 'r', encoding='utf-8') as f:
            json_str = f.read()
            data = json.loads(json_str)
        try:
            ocd_name = data['user_settings']['ocd_name']
            ocd_path = data['user_settings']['ocd_path']
        except KeyError:
            ocd_name = None
            ocd_path = None
        if ocd_path:
            ocd_path = os.path.abspath(ocd_path)
        return ocd_name, ocd_path

    @staticmethod
    def set_ocd_data(ocd_name, ocd_path, cwd=None):
        """ Sets OCD name and path in the project config """
        if not cwd:
            cwd = os.getcwd()
        config_path = os.path.join(cwd, ProjectInitializer.config_file)
        with open(config_path, 'r+', encoding='utf-8') as f:
            data = json.load(f)
            try:
                data['user_settings']['ocd_name'] = ocd_name
                data['user_settings']['ocd_path'] = ocd_path
            except KeyError as e:
                raise KeyError(f'Invalid project configuration file structure '
                               f'({config_path})') from e
            f.seek(0)
            json.dump(data, f, indent=4)
            f.truncate()

    @staticmethod
    def get_default_policy():
        """ Gets a path to the default policy file """
        with open(ProjectInitializer.config_file, encoding='utf-8') as f:
            json_str = f.read()
            data = json.loads(json_str)
        policy = data['user_settings']['default_policy']
        return None if policy is None else os.path.abspath(policy)

    @staticmethod
    def get_policy_src_files(policy_src):
        """ Gets names of the policy files in the source directory """
        return ProjectInitializer._filenames_from_dir(policy_src, ext='json')

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
                logger.info("Copy '%s'", dst_file)
            except FileNotFoundError:
                if warn:
                    logger.warning("File '%s' does not exist", src_file)

    @staticmethod
    def _filenames_from_dir(dir_path, ext=None):
        """ Gets a list of filenames from the specified directory """
        if ext:
            files = [f for f in os.listdir(dir_path) if f.endswith(f'.{ext}')]
        else:
            files = os.listdir(dir_path)
        return files
