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
from cysecuretools.core import TargetBuilder
from cysecuretools.core.enums import KeyAlgorithm
from cysecuretools.targets.cyb06xxa.maps.memory_map import MemoryMap_cyb06xxa
from cysecuretools.targets.cyb06xxa.maps.register_map import \
    RegisterMap_cyb06xxa
from cysecuretools.targets.common.p64.policy_filter import PolicyFilter
from cysecuretools.targets.common.p64.policy_parser import PolicyParser
from cysecuretools.targets.common.p64.policy_validator import PolicyValidator
from cysecuretools.execute.provisioning import ProvisioningMXS40v1
from cysecuretools.execute.provisioning_packet import ProvisioningPacketMXS40v1
from cysecuretools.execute.entrance_exam.exam_mxs40v1 import \
    EntranceExamMXS40v1
from cysecuretools.execute.project_init.project_init_mxs40v1 import \
    ProjectInitializerMXS40V1
from cysecuretools.execute.voltage_tool.voltage_tool_mxs40v1 import VoltageToolMXS40v1
from cysecuretools.execute.key_reader_mxs40v1 import KeyReaderMXS40V1
from cysecuretools.execute.silicon_data_reader import SiliconDataReaderMXS40v1
from cysecuretools.execute.image_signing.signtool_mxs40v1 import \
    SignToolMXS40v1
from cysecuretools.execute.key_source.key_source_mxs40v1 import (
    KeySourceMXS40v1)


class CYS06xxA_Builder(TargetBuilder):
    """ CYS06xxA target builder """

    def get_default_policy(self):
        return os.path.join(
            self.target_dir, 'policy', 'policy_single_CM0_CM4_swap.json')

    def get_ocds(self):
        return ['pyocd', 'openocd']

    def get_ocd_config(self):
        return {
            'openocd': {
                'before_init': '',
                'after_init': 'targets'
            }
        }

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
        return ProvisioningMXS40v1()

    def get_provisioning_packet_strategy(self, policy_parser):
        return ProvisioningPacketMXS40v1(policy_parser)

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

    def get_sign_tool(self):
        return SignToolMXS40v1

    def get_key_source(self, **kwargs):
        return KeySourceMXS40v1(kwargs['policy_parser'])

    def get_bootloader_provider(self):
        from cysecuretools.execute.bootloader_provider_mxs40v1 import (
            BootloaderProviderMXS40v1)
        return BootloaderProviderMXS40v1

    def get_version_provider(self):
        from cysecuretools.execute.version_provider.version_provider_mxs40v1 \
            import VersionProviderMXS40v1
        return VersionProviderMXS40v1

    def get_debug_certificate(self):
        """ N/A for MXS40v1 platform """
        return None

    def get_policy_generator(self, policy_parser):
        """ N/A for MXS40v1 platform """
        return None

    def get_test_packages(self):
        """ N/A for MXS40v1 platform """
        return None
