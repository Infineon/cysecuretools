"""
Copyright 2022 Cypress Semiconductor Corporation (an Infineon company)
or an affiliate of Cypress Semiconductor Corporation. All rights reserved.

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
from .dependencies_validator.hci_mode_validator import HciModeValidator
from .dependencies_validator.nv_counter_validator import NvCounterValidator
from .dependencies_validator.pre_build_keys_exist_validator import (
    PreBuildKeysExistValidator)
from .dependencies_validator.encryption_key_validator import (
    EncryptionAndProgramOemKey1Validator)
from .dependencies_validator.revoke_oem_encryption_validator import (
    RevocationAndEncryptionValidator)
from .dependencies_validator.access_restrictions_validator import (
    AccessRestrictionsValidator)
from ..dependencies_validation import DependenciesValidatorRunner


class DependencyValidatorMXS40v2(DependenciesValidatorRunner):
    """Validates policy dependencies for mxs40v2 platform"""

    validators = {
        'pre_build': [
            PreBuildKeysExistValidator,
            HciModeValidator,
            EncryptionAndProgramOemKey1Validator,
            RevocationAndEncryptionValidator,
            AccessRestrictionsValidator,
            NvCounterValidator
        ]
    }

    def __init__(self, policy_parser):
        super().__init__(policy_parser, self.validators)
