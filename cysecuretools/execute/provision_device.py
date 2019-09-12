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
import os
from cysecuretools.execute.enums import ProtectionState, EntranceExamErrors
from cysecuretools.execute.entrance_exam import entrance_exam
from cysecuretools.execute.sys_call import get_prov_details, provision_keys_and_policies, transition_to_secure
from cysecuretools.execute.p6_memory_map import FLASH_ADDRESS, FLASH_SIZE, PROVISION_JWT_PACKET_ADDRESS, \
    PROVISION_JWT_PACKET_SIZE
from cysecuretools.execute.gen_data_from_json import ENTRANCE_EXAM_FW_STATUS_REG, ENTRANCE_EXAM_FW_STATUS_MASK, \
    ENTRANCE_EXAM_FW_STATUS_VAL
from cysecuretools.execute.p6_reg import CYREG_CPUSS_PROTECTION, NVSTORE_AREA_1_ADDRESS

BLOW_EFUSE = 1
DO_NOT_BLOW_EFUSE = 2


def provision_execution(tool, pub_key_json, prov_cmd_jwt, cy_bootloader_hex, protection_state=ProtectionState.secure):
    """
    Programs Cypress Bootloader and calls system calls for device provisioning.
    :param tool: Programming/debugging tool used for communication with device.
    :param pub_key_json: File where to save public key in JSON format.
    :param prov_cmd_jwt: Path to provisioning JWT file (packet which contains
           all data necessary for provisioning, including policy, authorization
           packets and keys).
    :param cy_bootloader_hex: Path to Cypress Bootloader program file.
    :param protection_state: Expected target protection state. The argument is for Cypress internal use only.
    :return: True if provisioning passed, otherwise False.
    """
    tool.set_frequency(200)
    tool.reset_and_halt()
    print("CPUSS.PROTECTION state: '0': UNKNOWN. '1': VIRGIN. '2': NORMAL. '3': SECURE. '4': DEAD.")
    print(hex(CYREG_CPUSS_PROTECTION), hex(tool.read32(CYREG_CPUSS_PROTECTION)))

    # Erase flash
    status = entrance_exam(tool) if protection_state == ProtectionState.secure else EntranceExamErrors.FLASH_NOT_EMPTY
    if status == EntranceExamErrors.FLASH_NOT_EMPTY:
        if protection_state != ProtectionState.secure:
            print(os.linesep + 'Erase JWT')
            print('erasing...')
            tool.erase(PROVISION_JWT_PACKET_ADDRESS, PROVISION_JWT_PACKET_SIZE)

        print(os.linesep + 'Erase main flash:')
        print('erasing...')
        tool.erase(FLASH_ADDRESS, FLASH_SIZE)
    elif status != EntranceExamErrors.OK:
        return False

    if protection_state != ProtectionState.secure:
        print(os.linesep + 'Run transition to secure:')
        tool.reset()
        is_exam_pass = transition_to_secure(tool, False)
        tool.reset()
        if not is_exam_pass:
            print('FAIL: Unexpected TransitionToSecure syscall response')
            return False

    print(os.linesep + 'Read FB Firmware status:')
    fb_firmware_status = tool.read32(ENTRANCE_EXAM_FW_STATUS_REG)
    print(f'FB Firmware status = {hex(fb_firmware_status)}')
    # Print Expected and received LIFECYCLE_STAGE values
    print(f'Received FB_FW_STATUS = {hex(fb_firmware_status & ENTRANCE_EXAM_FW_STATUS_MASK)}')
    print(f'Expected FB_FW_STATUS = {hex(ENTRANCE_EXAM_FW_STATUS_VAL)}')
    # Verify if received value is the same as expected
    is_exam_pass = (fb_firmware_status & ENTRANCE_EXAM_FW_STATUS_MASK) == ENTRANCE_EXAM_FW_STATUS_VAL
    print('PASS: FB Firmware status is as expected' if is_exam_pass else 'FAIL: FB Firmware status is not as expected')

    if is_exam_pass:
        print(os.linesep + 'PROGRAMMING APP HEX:')
        tool.program(cy_bootloader_hex)

    result, key = get_prov_details(tool, 1)
    print('Device public key has been read successfully.' if result else 'FAIL: Cannot read device public key.')
    print(key)

    with open(os.path.join(pub_key_json), 'w') as json_file:
        json_file.write(key)

    if is_exam_pass:
        print(os.linesep + 'Run provisioning syscall:')
        # Set a value indicating whether to convert device to SECURE CLAIMED mode
        blow_secure_fuse = BLOW_EFUSE if protection_state == ProtectionState.secure else DO_NOT_BLOW_EFUSE
        is_exam_pass = provision_keys_and_policies(tool, blow_secure_fuse, os.path.join(prov_cmd_jwt))
        print(hex(NVSTORE_AREA_1_ADDRESS) + ': ', sep=' ', end='', flush=True)
        if is_exam_pass:
            i = 0
            while i < 8 * 4:  # output 8 words
                print(hex(tool.read32(NVSTORE_AREA_1_ADDRESS + i)) + ' ', sep=' ', end='', flush=True)
                i += 4
            print(os.linesep)
        else:
            print('FAIL: Unexpected ProvisionKeysAndPolicies syscall response')

    if is_exam_pass:
        print('*****************************************')
        print("       PROVISIONING PASSED               ")
        print("*****************************************")

    tool.reset()
    return is_exam_pass
