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
from cysecuretools.core import TargetBuilder
from cysecuretools.core.enums import KeyAlgorithm
from cysecuretools.targets.cyb06xxa.maps.memory_map import MemoryMap_cyb06xxa
from cysecuretools.targets.cyb06xxa.maps.register_map import \
    RegisterMap_cyb06xxa
from cysecuretools.targets.common.policy_filter import PolicyFilter
from cysecuretools.targets.common.policy_parser import PolicyParser
from cysecuretools.targets.common.policy_validator import PolicyValidator
from cysecuretools.execute.provision_device_mxs40v1 import ProvisioningMXS40V1
from cysecuretools.execute.provisioning_packet_mxs40v1 import \
    ProvisioningPacketMXS40V1
from cysecuretools.execute.entrance_exam.exam_mxs40v1 import \
    EntranceExamMXS40v1
from cysecuretools.execute.project_init_mxs40v1 import \
    ProjectInitializerMXS40V1
from cysecuretools.execute.voltage_tool_mxs40v1 import VoltageToolMXS40v1
from cysecuretools.execute.key_reader import KeyReaderMXS40V1
from cysecuretools.execute.silicon_data_reader_mxs40v1 import \
    SiliconDataReaderMXS40v1


class CYS06xxA_Builder(TargetBuilder):
    def get_default_policy(self):
        return os.path.join(self.target_dir, 'policy',
                            'policy_single_CM0_CM4_swap.json')

    def get_memory_map(self):
        memory_map = MemoryMap_cyb06xxa()
        return memory_map

    def get_register_map(self):
        register_map = RegisterMap_cyb06xxa()
        return register_map

    def get_policy_parser(self, policy):
        policy_parser = PolicyParser(policy)
        return policy_parser

    def get_policy_validator(self, policy_parser, memory_map):
        policy_validator = PolicyValidator(policy_parser, memory_map)
        return policy_validator

    def get_policy_filter(self, policy_parser):
        policy_filter = PolicyFilter(policy_parser)
        return policy_filter

    def get_provisioning_strategy(self):
        return ProvisioningMXS40V1()

    def get_provisioning_packet_strategy(self, policy_parser):
        return ProvisioningPacketMXS40V1(policy_parser)

    def get_entrance_exam(self):
        return EntranceExamMXS40v1

    def get_voltage_tool(self):
        return VoltageToolMXS40v1

    def get_key_reader(self):
        return KeyReaderMXS40V1

    def get_project_initializer(self):
        return ProjectInitializerMXS40V1

    def get_silicon_data_reader(self):
        return SiliconDataReaderMXS40v1

    def get_key_algorithms(self):
        return [KeyAlgorithm.EC]
