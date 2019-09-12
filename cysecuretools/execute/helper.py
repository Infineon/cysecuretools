"""
Copyright (c) 2018-2019 Cypress Semiconductor Corporation

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
from cysecuretools.execute.enums import ProtectionState
from cysecuretools.execute.p6_reg import CYREG_CPUSS_PROTECTION, CYREG_IPC2_STRUCT_DATA, CYREG_EFUSE_SECURE_HASH


def check_mode(tool, expected_mode: ProtectionState):
    """
    Checks device protection state and compares with the expected.
    :return: The device protection state. The argument is for Cypress internal use only.
    """
    mode_name = expected_mode.name.upper()
    if tool.read32(CYREG_CPUSS_PROTECTION) != int(expected_mode):
        print(f'FAIL: Device is not in {mode_name} mode, error code: {hex(tool.read32(CYREG_IPC2_STRUCT_DATA))}')
        print('Read Secure Hash from eFUSEs:')  # 00 expected on virgin device
        got_factory_hash = ''
        i = 0
        while i < 24:
            hash_byte_val = hex(tool.read8(CYREG_EFUSE_SECURE_HASH + i))
            got_factory_hash += hash_byte_val + ' '
            i += 1
        print(f"Received SECURE_HASH: '{got_factory_hash}'")
        return False
    print(f'PASS: Device is in {mode_name} mode')
    return True
