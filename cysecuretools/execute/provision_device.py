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
import logging
from time import sleep
from cysecuretools.execute.enums import ProtectionState, EntranceExamStatus, ProvisioningStatus
from cysecuretools.execute.entrance_exam import entrance_exam
from cysecuretools.execute.sys_call import get_prov_details, provision_keys_and_policies, transition_to_secure, \
    read_lifecycle

BLOW_EFUSE = 1
DO_NOT_BLOW_EFUSE = 2
logger = logging.getLogger(__name__)


def provision_execution(tool, pub_key_json, prov_cmd_jwt, cy_bootloader_hex, memory_map, reg_map,
                        protection_state=ProtectionState.secure) -> ProvisioningStatus:
    """
    Programs Cypress Bootloader and calls system calls for device provisioning.
    :param tool: Programming/debugging tool used for communication with device.
    :param pub_key_json: File where to save public key in JSON format.
    :param prov_cmd_jwt: Path to provisioning JWT file (packet which contains
           all data necessary for provisioning, including policy, authorization
           packets and keys).
    :param cy_bootloader_hex: Path to Cypress Bootloader program file.
    :param memory_map: Device memory map.
    :param reg_map: Device register map.
    :param protection_state: Expected target protection state. The argument is for Cypress internal use only.
    :return: Provisioning status.
    """
    tool.set_frequency(200)
    tool.reset_and_halt()
    logger.info("CPUSS.PROTECTION state: '0': UNKNOWN. '1': VIRGIN. '2': NORMAL. '3': SECURE. '4': DEAD.")
    lifecycle = read_lifecycle(tool, reg_map)
    logger.info(f'{hex(lifecycle)}\n')

    # Erase flash
    status = entrance_exam(tool, reg_map) \
        if protection_state == ProtectionState.secure \
        else EntranceExamStatus.FLASH_NOT_EMPTY

    if status in [EntranceExamStatus.FLASH_NOT_EMPTY,
                  EntranceExamStatus.FIRMWARE_RUNNING_CM4,
                  EntranceExamStatus.FIRMWARE_RUNNING_CM0]:
        if protection_state == ProtectionState.secure:
            answer = input('Flash memory is not empty. Clear flash? (y/n): ')
            if answer.lower() == 'y':
                erase_flash(tool, memory_map, protection_state)
            else:
                return ProvisioningStatus.TERMINATED
        else:
            erase_flash(tool, memory_map, protection_state)
    elif status != EntranceExamStatus.OK:
        return ProvisioningStatus.FAIL

    if protection_state != ProtectionState.secure:
        is_exam_pass = to_secure(tool, reg_map)
        if not is_exam_pass:
            logger.error('Unexpected TransitionToSecure syscall response\n')
            return ProvisioningStatus.FAIL

    logger.info('Read FlashBoot firmware status:')
    fb_firmware_status = tool.read32(reg_map.ENTRANCE_EXAM_FW_STATUS_REG)
    logger.info(f'FlashBoot firmware status = {hex(fb_firmware_status)}')
    # Print Expected and received LIFECYCLE_STAGE values
    logger.info(f'Received FB_FW_STATUS = {hex(fb_firmware_status & reg_map.ENTRANCE_EXAM_FW_STATUS_MASK)}')
    logger.info(f'Expected FB_FW_STATUS = {hex(reg_map.ENTRANCE_EXAM_FW_STATUS_VAL)}')
    # Verify if received value is the same as expected
    is_exam_pass = (fb_firmware_status & reg_map.ENTRANCE_EXAM_FW_STATUS_MASK) == reg_map.ENTRANCE_EXAM_FW_STATUS_VAL
    if is_exam_pass:
        logger.info('FlashBoot firmware status is as expected\n')
    else:
        logger.error('FlashBoot firmware status is not as expected\n')

    if is_exam_pass:
        logger.info('PROGRAMMING APP HEX:')
        tool.program(cy_bootloader_hex)

    key = read_public_key(tool, reg_map)
    if key:
        with open(os.path.join(pub_key_json), 'w') as json_file:
            json_file.write(key)

    if is_exam_pass:
        logger.info('Run provisioning syscall:')
        # Set a value indicating whether to convert device to SECURE CLAIMED mode
        blow_secure_fuse = BLOW_EFUSE if protection_state == ProtectionState.secure else DO_NOT_BLOW_EFUSE
        is_exam_pass = provision_keys_and_policies(tool, blow_secure_fuse, prov_cmd_jwt, reg_map)
        if not is_exam_pass:
            logger.error('Unexpected ProvisionKeysAndPolicies syscall response')

        tool.reset()
        sleep(3)
        fb_firmware_status = tool.read32(reg_map.ENTRANCE_EXAM_FW_STATUS_REG)
        logger.info(f'FlashBoot firmware status = {hex(fb_firmware_status)}')

        is_exam_pass = fb_firmware_status == reg_map.FB_FW_STATUS_FIRMWARE_RUNNING_CM0
        if not is_exam_pass:
            logger.error('FlashBoot firmware status is not as expected')

    if is_exam_pass:
        logger.info('*****************************************')
        logger.info('       PROVISIONING PASSED               ')
        logger.info('*****************************************\n')

    tool.reset()
    return ProvisioningStatus.OK if is_exam_pass else ProvisioningStatus.FAIL


def read_silicon_data(tool, rot_cmd_jwt, reg_map, memory_map, protection_state=ProtectionState.secure):
    logger.info('Read response packet:')

    status = entrance_exam(tool, reg_map) if protection_state == ProtectionState.secure else EntranceExamStatus.FLASH_NOT_EMPTY
    if status == EntranceExamStatus.FLASH_NOT_EMPTY:
        erase_flash(tool, memory_map, protection_state)
    elif status != EntranceExamStatus.OK:
        return False

    if protection_state != ProtectionState.secure:
        is_exam_pass = to_secure(tool, reg_map)
        sleep(1)
        if not is_exam_pass:
            logger.error('Unexpected TransitionToSecure syscall response\n')
            return False

    logger.info('Run provisioning syscall')
    complete = 0
    response = None
    syscall_passed = provision_keys_and_policies(tool, complete, rot_cmd_jwt, reg_map)
    if syscall_passed:
        scratch_addr = tool.read32(reg_map.ENTRANCE_EXAM_SRAM_ADDR + 0x04)
        resp_size = tool.read32(scratch_addr)
        resp_addr = tool.read32(scratch_addr + 0x04)
        logger.info(f'resp_size = {hex(resp_size)}')
        logger.info(f'resp_addr = {hex(resp_addr)}')

        response = ''
        for i in range(resp_size):
            hash_byte_chr = chr(tool.read8(resp_addr + i))
            response += hash_byte_chr
        response = response.strip()
        logger.info(f'ProvisionKeysAndPolicies response = \'{response}\'')
    else:
        logger.error('Unexpected ProvisionKeysAndPolicies syscall response')

    return response


def erase_flash(tool, memory_map, protection_state):
    if protection_state != ProtectionState.secure:
        logger.info('Erase JWT:')
        erase_addr = memory_map.PROVISION_JWT_PACKET_ADDRESS
        erase_size = memory_map.PROVISION_JWT_PACKET_SIZE
        logger.info(f'erasing address {hex(erase_addr)}, size {hex(erase_size)} ...')
        tool.erase(erase_addr, erase_size)
        logger.info('Complete\n')

    logger.info('Erase main flash:')
    erase_addr = memory_map.FLASH_ADDRESS
    erase_size = memory_map.FLASH_SIZE
    logger.info(f'erasing address {hex(erase_addr)}, size {hex(erase_size)} ...')
    tool.erase(erase_addr, erase_size)
    logger.info('Complete\n')


def to_secure(tool, reg_map):
    logger.info('Run transition to secure:')
    tool.reset()
    is_exam_pass = transition_to_secure(tool, False, reg_map)
    tool.reset()
    return is_exam_pass


def read_public_key(tool, reg_map):
    syscall_passed, key = get_prov_details(tool, 1, reg_map)
    if syscall_passed:
        logger.info('Device public key has been read successfully')
        logger.info(f'{key}\n')
        return key
    else:
        logger.error('Cannot read device public key\n')
        return None
