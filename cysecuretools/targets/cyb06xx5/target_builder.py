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
import os
from cysecuretools.core import TargetBuilder


class CYB06xx5_Builder(TargetBuilder):
    def get_default_policy(self):
        target_dir = os.path.dirname(os.path.realpath(__file__))
        return os.path.join(target_dir, 'policy/policy_single_stage_CM4.json')

    def get_memory_map(self):
        from cysecuretools.targets.cyb06xx5.maps.memory_map import MemoryMap_cyb06xx5
        memory_map = MemoryMap_cyb06xx5()
        return memory_map

    def get_register_map(self):
        from cysecuretools.targets.cyb06xx5.maps.register_map import RegisterMap_cyb06xx5
        register_map = RegisterMap_cyb06xx5()
        return register_map

    def get_policy_parser(self, policy):
        from cysecuretools.targets.common.policy_parser import PolicyParser
        policy_parser = PolicyParser(policy)
        return policy_parser

    def get_policy_validator(self, policy_parser, memory_map):
        from cysecuretools.targets.common.policy_validator import PolicyValidator
        policy_validator = PolicyValidator(policy_parser, memory_map)
        return policy_validator

    def get_policy_filter(self, policy_parser):
        from cysecuretools.targets.common.policy_filter import PolicyFilter
        policy_filter = PolicyFilter(policy_parser)
        return policy_filter
