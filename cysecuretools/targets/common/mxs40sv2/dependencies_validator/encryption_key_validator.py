"""
Copyright (c) 2021 Cypress Semiconductor Corporation

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
from cysecuretools.core.dependecy_validator import DependencyValidator


class EncryptionAndProgramOemKey1Validator(DependencyValidator):
    def validate(self):
        _pp = self.policy_parser

        encryption = _pp.get_encryption()
        program_pub_key_1 = _pp.get_program_oem_key_1_hash()

        if program_pub_key_1 and encryption:
            self.add_msg('Either the OEM key_1 hash or the '
                         'AES key can be used. If encryption is enabled, '
                         'the AES key will be programmed. '
                         '"program_oem_key_1_hash" and "encryption" '
                         'can not be enabled at once. '
                         'Please edit the policy')
