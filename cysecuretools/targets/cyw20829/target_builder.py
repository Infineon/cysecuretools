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
from cysecuretools.core import TargetBuilder
from cysecuretools.core.enums import KeyAlgorithm
from cysecuretools.targets.cyw20829.maps.memory_map import MemoryMapCYW20829
from cysecuretools.targets.cyw20829.maps.register_map import (
    RegisterMap_cyw20829)
from cysecuretools.targets.common.mxs40sv2 import PolicyParser
from cysecuretools.targets.common.mxs40sv2 import PolicyValidator
from cysecuretools.execute.provisioning import ProvisioningMXS40Sv2
from cysecuretools.execute.provisioning_packet.provisioning_packet_mxs40sv2 \
    import ProvisioningPacketMXS40Sv2
from cysecuretools.execute.project_init.project_init_mxs40sv2 import (
    ProjectInitializerMXS40Sv2)
from cysecuretools.execute.silicon_data_reader import SiliconDataReaderMXS40Sv2
from cysecuretools.execute.key_reader_mxs40v1 import KeyReaderMXS40V1
from cysecuretools.execute.image_signing.signtool_mxv40sv2 import (
    SignToolMXS40Sv2)
from cysecuretools.execute.key_source.key_source_mxs40sv2 import (
    KeySourceMXS40Sv2)
from cysecuretools.execute.debug_cert import DebugCertificateMXS40Sv2
from .policy_generator import PolicyGenerator


class CYW20829Builder(TargetBuilder):
    """ CYW20829 target builder """

    def get_default_policy(self):
        return None

    def get_ocds(self):
        return ['openocd']

    def get_ocd_config(self):
        return {
            'openocd': {
                'before_init': 'cyw20829.cm33 configure -defer-examine',
                'after_init': 'targets cyw20829.sysap'
            }
        }

    def get_memory_map(self):
        memory_map = MemoryMapCYW20829()
        return memory_map

    def get_register_map(self):
        register_map = RegisterMap_cyw20829()
        return register_map

    def get_policy_parser(self, policy):
        policy_parser = PolicyParser(policy)
        return policy_parser

    def get_policy_validator(self, policy_parser, memory_map):
        policy_validator = PolicyValidator(policy_parser)
        return policy_validator

    def get_policy_filter(self, policy_parser):
        pass

    def get_provisioning_strategy(self):
        from cysecuretools.targets.cyw20829.flows.load_app_data import (
            LoadAppData)
        return ProvisioningMXS40Sv2(load_app_data=LoadAppData)

    def get_provisioning_packet_strategy(self, policy_parser):
        return ProvisioningPacketMXS40Sv2(policy_parser)

    def get_entrance_exam(self):
        return None

    def get_voltage_tool(self):
        return None

    def get_key_reader(self):
        return KeyReaderMXS40V1

    def get_project_initializer(self):
        return ProjectInitializerMXS40Sv2

    def get_silicon_data_reader(self):
        return SiliconDataReaderMXS40Sv2

    def get_key_algorithms(self):
        return [KeyAlgorithm.RSA, KeyAlgorithm.AES]

    def get_sign_tool(self):
        return SignToolMXS40Sv2

    def get_key_source(self, **kwargs):
        return KeySourceMXS40Sv2(kwargs['policy_parser'])

    def get_bootloader_provider(self):
        return None

    def get_version_provider(self):
        from cysecuretools.execute.version_provider.version_provider_mxs40sv2 \
            import VersionProviderMXS40Sv2
        return VersionProviderMXS40Sv2

    def get_debug_certificate(self):
        return DebugCertificateMXS40Sv2()

    def get_policy_generator(self, policy_parser):
        return PolicyGenerator(policy_parser)

    def get_test_packages(self):
        return {
            'testapps': {
                'package': 'testapps_cyw20829', 'flow_name': 'testapps'
            },
            'testapps_si': {
                'package': 'testapps_cyw20829', 'flow_name': 'testapps_si'
            }
        }
