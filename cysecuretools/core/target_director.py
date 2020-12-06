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
import inspect
from cysecuretools.core.target_builder import TargetBuilder


class TargetDirector:
    """
    The Director is only responsible for executing the building steps
    in a particular sequence. It is helpful when producing products
    according to a specific order or configuration.
    """
    def __init__(self):
        self._builder = None
        self._target_dir = None

    @property
    def builder(self):
        return self._builder

    @builder.setter
    def builder(self, builder: TargetBuilder):
        """
        The Director works with any builder instance that the client
        code passes to it. This way, the client code may alter the
        final type of the newly assembled product.
        """
        self._builder = builder
        self._builder.target_dir = os.path.dirname(os.path.realpath(
            inspect.getfile(builder.__class__)))

    def get_target(self, policy, name, cwd):
        target = Target()

        # Target directory
        target.name = name
        target.cwd = cwd
        target.target_dir = self._builder.target_dir

        # Memory map
        memory_map = self._builder.get_memory_map()
        target.memory_map = memory_map

        # Register map
        register_map = self._builder.get_register_map()
        target.register_map = register_map

        # Policy parser
        policy_file = self.builder.get_default_policy() if policy is None \
            else policy
        target.policy = policy_file
        policy_parser = self._builder.get_policy_parser(policy_file)
        target.policy_parser = policy_parser

        # Policy validator
        policy_validator = self._builder.get_policy_validator(policy_parser,
                                                              memory_map)
        target.policy_validator = policy_validator

        # Policy filter
        policy_filter = self._builder.get_policy_filter(policy_parser)
        target.policy_filter = policy_filter

        # Provisioning strategy
        target.provisioning_strategy = \
            self._builder.get_provisioning_strategy()

        # Provisioning packet strategy
        target.provisioning_packet_strategy = \
            self._builder.get_provisioning_packet_strategy(policy_parser)

        # Entrance exam
        target.entrance_exam = self._builder.get_entrance_exam()

        # Voltage tool
        target.voltage_tool = self._builder.get_voltage_tool()

        # Key reader
        target.key_reader = self._builder.get_key_reader()

        # Project initializer
        target.project_initializer = self._builder.get_project_initializer()

        # Silicon data reader
        target.silicon_data_reader = self._builder.get_silicon_data_reader()

        # Key algorithms
        target.key_algorithms = self._builder.get_key_algorithms()

        return target


class Target:
    def __init__(self):
        self._name = None
        self._policy = None
        self._memory_map = None
        self._register_map = None
        self._policy_validator = None
        self._policy_parser = None
        self._policy_filter = None
        self._target_dir = None
        self._provisioning_strategy = None
        self._provisioning_packet_strategy = None
        self._entrance_exam = None
        self._voltage_tool = None
        self._key_reader = None
        self._project_initializer = None
        self._cwd = None
        self._silicon_data_reader = None
        self._key_algorithms = None

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, name):
        self._name = name

    @property
    def policy(self):
        return self._policy

    @policy.setter
    def policy(self, policy):
        self._policy = policy

    @property
    def memory_map(self):
        return self._memory_map

    @memory_map.setter
    def memory_map(self, memory_map):
        self._memory_map = memory_map

    @property
    def register_map(self):
        return self._register_map

    @register_map.setter
    def register_map(self, register_map):
        self._register_map = register_map

    @property
    def policy_parser(self):
        return self._policy_parser

    @policy_parser.setter
    def policy_parser(self, policy_parser):
        self._policy_parser = policy_parser

    @property
    def policy_validator(self):
        return self._policy_validator

    @policy_validator.setter
    def policy_validator(self, policy_validator):
        self._policy_validator = policy_validator

    @property
    def policy_filter(self):
        return self._policy_filter

    @policy_filter.setter
    def policy_filter(self, policy_filter):
        self._policy_filter = policy_filter

    @property
    def target_dir(self):
        return self._target_dir

    @target_dir.setter
    def target_dir(self, target_dir):
        self._target_dir = target_dir

    @property
    def provisioning_strategy(self):
        return self._provisioning_strategy

    @provisioning_strategy.setter
    def provisioning_strategy(self, strategy):
        self._provisioning_strategy = strategy

    @property
    def provisioning_packet_strategy(self):
        return self._provisioning_packet_strategy

    @provisioning_packet_strategy.setter
    def provisioning_packet_strategy(self, strategy):
        self._provisioning_packet_strategy = strategy

    @property
    def entrance_exam(self):
        return self._entrance_exam

    @entrance_exam.setter
    def entrance_exam(self, obj_type):
        self._entrance_exam = obj_type

    @property
    def voltage_tool(self):
        return self._voltage_tool

    @voltage_tool.setter
    def voltage_tool(self, tool_type):
        self._voltage_tool = tool_type

    @property
    def key_reader(self):
        return self._key_reader

    @key_reader.setter
    def key_reader(self, reader_type):
        self._key_reader = reader_type

    @property
    def project_initializer(self):
        return self._project_initializer

    @project_initializer.setter
    def project_initializer(self, initializer_type):
        self._project_initializer = initializer_type

    @property
    def cwd(self):
        return self._cwd

    @cwd.setter
    def cwd(self, cwd):
        self._cwd = cwd

    @property
    def silicon_data_reader(self):
        return self._silicon_data_reader

    @silicon_data_reader.setter
    def silicon_data_reader(self, reader):
        self._silicon_data_reader = reader

    @property
    def key_algorithms(self):
        return self._key_algorithms

    @key_algorithms.setter
    def key_algorithms(self, algorithms):
        self._key_algorithms = algorithms
