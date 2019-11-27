"""
Copyright (c) 2019 Cypress Semiconductor Corporation

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


class TargetBuilder:
    def get_default_policy(self): pass
    def get_memory_map(self): pass
    def get_register_map(self): pass
    def get_policy_parser(self): pass
    def get_policy_validator(self, policy_parser, memory_map): pass
    def get_policy_filter(self, policy_parser): pass


class TargetDirector:
    """
    The Director is only responsible for executing the building steps in a
    particular sequence. It is helpful when producing products according to a
    specific order or configuration.
    """
    def __init__(self):
        self._builder = None

    @property
    def builder(self):
        return self._builder

    @builder.setter
    def builder(self, builder: TargetBuilder):
        """
        The Director works with any builder instance that the client code passes
        to it. This way, the client code may alter the final type of the newly
        assembled product.
        """
        self._builder = builder

    def get_target(self, policy, name):
        target = Target()

        target.name = name

        memory_map = self._builder.get_memory_map()
        target.memory_map = memory_map

        register_map = self._builder.get_register_map()
        target.register_map = register_map

        policy_file = self.builder.get_default_policy() if policy is None else policy
        target.policy = policy_file
        policy_parser = self._builder.get_policy_parser(policy_file)
        target.policy_parser = policy_parser

        policy_validator = self._builder.get_policy_validator(policy_parser, memory_map)
        target.policy_validator = policy_validator

        policy_filter = self._builder.get_policy_filter(policy_parser)
        target.policy_filter = policy_filter

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
