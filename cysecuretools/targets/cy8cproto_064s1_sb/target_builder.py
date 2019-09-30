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
from cysecuretools.core import TargetBuilder


class CY8CPROTO_064S1_SB_Builder(TargetBuilder):
    def __init__(self, policy):
        self.__policy = policy
        self.__policy_parser = None
        self.__memory_map = None

    def get_memory_map(self):
        from cysecuretools.targets.cy8cproto_064s1_sb.maps.memory_map import MemoryMap_cy8cproto_064s1_sb
        memory_map = MemoryMap_cy8cproto_064s1_sb()
        self.__memory_map = memory_map
        return memory_map

    def get_register_map(self):
        from cysecuretools.targets.cy8cproto_064s1_sb.maps.register_map import RegisterMap_cy8cproto_064s1_sb
        register_map = RegisterMap_cy8cproto_064s1_sb()
        return register_map

    def get_policy_parser(self):
        from cysecuretools.targets.common.policy_parser import PolicyParser
        policy_parser = PolicyParser(self.__policy)
        self.__policy_parser = policy_parser
        return policy_parser

    def get_policy_validator(self, policy_parser, memory_map):
        from cysecuretools.targets.common.policy_validator import PolicyValidator
        policy_validator = PolicyValidator(policy_parser, memory_map)
        return policy_validator

    def get_policy_filter(self, policy_parser):
        from cysecuretools.targets.common.policy_filter import PolicyFilter
        policy_filter = PolicyFilter(policy_parser)
        return policy_filter
