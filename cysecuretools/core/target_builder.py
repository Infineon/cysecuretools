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
from abc import abstractmethod


class TargetBuilder:
    def __init__(self):
        self._target_dir = None

    @property
    def target_dir(self):
        return self._target_dir

    @target_dir.setter
    def target_dir(self, target_dir):
        self._target_dir = target_dir

    @abstractmethod
    def get_default_policy(self): pass

    @abstractmethod
    def get_memory_map(self): pass

    @abstractmethod
    def get_register_map(self): pass

    @abstractmethod
    def get_policy_parser(self, policy): pass

    @abstractmethod
    def get_policy_validator(self, policy_parser, memory_map): pass

    @abstractmethod
    def get_policy_filter(self, policy_parser): pass

    @abstractmethod
    def get_provisioning_strategy(self): pass

    @abstractmethod
    def get_provisioning_packet_strategy(self, policy_parser): pass

    @abstractmethod
    def get_entrance_exam(self): pass

    @abstractmethod
    def get_voltage_tool(self): pass

    @abstractmethod
    def get_key_reader(self): pass

    @abstractmethod
    def get_project_initializer(self): pass

    @abstractmethod
    def get_silicon_data_reader(self): pass

    @abstractmethod
    def get_key_algorithms(self): pass
