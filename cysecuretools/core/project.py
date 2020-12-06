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
import json
from abc import ABC, abstractmethod


class ProjectInitializer(ABC):
    config_file = '.cysecuretools'
    keys_dir_name = 'keys'
    policy_dir_name = 'policy'
    prebuilt_dir_name = 'prebuilt'
    common_prebuilt_dir_name = '../common/prebuilt'

    @abstractmethod
    def __init__(self):
        pass

    @abstractmethod
    def init(self):
        pass

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

    @staticmethod
    def set_default_policy(policy):
        data = {
            'user_settings': {
                'default_policy': policy
            }
        }
        with open(ProjectInitializer.config_file, 'w') as f:
            json.dump(data, f, indent=4)

    @staticmethod
    def get_default_policy():
        with open(ProjectInitializer.config_file) as f:
            json_str = f.read()
            data = json.loads(json_str)
        return os.path.abspath(data['user_settings']['default_policy'])
