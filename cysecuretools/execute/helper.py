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
import logging
from cysecuretools.execute.enums import ProtectionState
from cysecuretools.execute.sys_call import read_lifecycle

logger = logging.getLogger(__name__)


def check_mode(tool, reg_map, expected_mode: ProtectionState):
    """
    Checks device protection state and compares with the expected.
    :param tool: Programming/debugging tool used for communication with device.
    :param reg_map: Device register map.
    :param expected_mode: The device protection state. The argument is for Cypress internal use only.
    :return: True if device mode matches specified expected mode, otherwise False.
    """
    mode_name = expected_mode.name.upper()
    lifecycle = read_lifecycle(tool, reg_map)
    if lifecycle != int(expected_mode):
        logger.error(f'Device is not in {mode_name} mode, error code: {hex(tool.read32(reg_map.CYREG_IPC2_STRUCT_DATA))}')
        logger.info('Read Secure Hash from eFUSEs:')  # 00 expected on virgin device
        got_factory_hash = ''
        i = 0
        while i < 24:
            hash_byte_val = hex(tool.read8(reg_map.CYREG_EFUSE_SECURE_HASH + i))
            got_factory_hash += hash_byte_val + ' '
            i += 1
        logger.info(f"Received SECURE_HASH: '{got_factory_hash}'\n")
        return False
    logger.info(f'PASS: Device is in {mode_name} mode\n')
    return True
