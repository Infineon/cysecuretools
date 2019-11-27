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
from cysecuretools.execute.helper import check_mode
from cysecuretools.execute.enums import ProtectionState, EntranceExamStatus
from cysecuretools.execute.sys_call import region_hash

logger = logging.getLogger(__name__)


def entrance_exam(tool, reg_map):
    """
    Checks device life-cycle, Flashboot firmware and Flash state.
    :param tool: Programming/debugging tool used for communication with device.
    :param reg_map: Device register map.
    :return: Error code.
    """
    # Check the device life-cycle stage
    logger.info('Check device protection state:')
    if not check_mode(tool, reg_map, ProtectionState.secure):
        return EntranceExamStatus.INVALID_MODE

    # Check if any firmware is launched by FlashBoot and running on the device
    logger.info('Read Flashboot firmware status:')
    fb_firmware_status = tool.read32(reg_map.ENTRANCE_EXAM_FW_STATUS_REG)
    logger.info(f'FlashBoot firmware status = {hex(fb_firmware_status)}')
    logger.info(f'Received FB_FW_STATUS = {hex(fb_firmware_status & reg_map.ENTRANCE_EXAM_FW_STATUS_MASK)}')
    logger.info(f'Expected FB_FW_STATUS = {hex(reg_map.ENTRANCE_EXAM_FW_STATUS_VAL)}')
    is_exam_pass = (fb_firmware_status & reg_map.ENTRANCE_EXAM_FW_STATUS_MASK) == reg_map.ENTRANCE_EXAM_FW_STATUS_VAL
    if is_exam_pass:
        logger.info('PASS: FlashBoot firmware status is as expected\n')
    else:
        logger.error('FlashBoot firmware status is not as expected')
        if fb_firmware_status == reg_map.FB_FW_STATUS_FIRMWARE_RUNNING_CM4:
            logger.warning('Test firmware exists and running on CM4 core. Device is in SECURE UNCLAIMED mode\n')
            return EntranceExamStatus.FIRMWARE_RUNNING_CM4
        if fb_firmware_status == reg_map.FB_FW_STATUS_FIRMWARE_RUNNING_CM0:
            logger.warning('Secure firmware exists and running on CM0p core. Device is in SECURE CLAIMED mode\n')
            return EntranceExamStatus.FIRMWARE_RUNNING_CM0

    # Check flash for malicious firmware
    logger.info('Check if Main Flash of the device is empty:')
    if region_hash(tool, reg_map):
        logger.info('PASS: Flash value is as expected\n')
        logger.info('*****************************************')
        logger.info('       ENTRANCE EXAM TEST PASSED         ')
        logger.info('*****************************************\n')
        tool.reset()
        sleep(0.2)
    else:
        logger.warning('Flash value is not as expected\n')
        return EntranceExamStatus.FLASH_NOT_EMPTY
    return EntranceExamStatus.OK
