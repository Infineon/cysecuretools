"""
Copyright (c) 2019-2020 Cypress Semiconductor Corporation

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
from collections import namedtuple
from cysecuretools.core.enums import EntranceExamStatus, RegionHashStatus, ProtectionState
from cysecuretools.execute.sys_call import region_hash, read_lifecycle
from cysecuretools.execute.programmer.base import AP
from cysecuretools.execute.provisioning_lib.cyprov_crypto import Crypto
from cysecuretools.core.target_director import Target
from cysecuretools.core.entrance_exam_base import EntranceExam

logger = logging.getLogger(__name__)

ENTRANCE_EXAM_JWT = 'entrance_exam.jwt'
SFB_VER_ERROR = 'Engineering Sample version of PSoC64 detected, the current ' \
                'version of CySecureTools is incompatible. Please contact ' \
                'Cypress to receive production versions of PSoC64 Silicon\n'


class EntranceExamMXS40v1(EntranceExam):
    def __init__(self, target: Target, **kwargs):
        self.reg_map = target.register_map
        self.voltage_tool = target.voltage_tool(target)
        packet_dir = target.policy_parser.get_provisioning_packet_dir()
        self.entrance_exam_jwt = os.path.abspath(os.path.join(
            packet_dir, ENTRANCE_EXAM_JWT))
        self.target = target

    def execute(self, tool):
        """
        Checks device life-cycle, Flashboot firmware, Flash state and
        bunch of registers.
        """
        jwt_text = Crypto.read_jwt(self.entrance_exam_jwt)

        logger.info('*****************************************')
        logger.info('             ENTRANCE EXAM               ')
        logger.info('*****************************************')

        reader = self.target.silicon_data_reader(self.target)
        complete = reader.read_complete_status(tool)
        exam_pass = not complete
        if not exam_pass:
            logger.error('Device has been previously provisioned')

        if exam_pass:
            voltage = self.voltage_tool.get_voltage(tool=tool)
            v_min = self.voltage_tool.voltage_level * 0.9
            v_max = self.voltage_tool.voltage_level * 1.1
            if voltage < v_min or voltage > v_max:
                exam_pass = False
                logger.error(f'Silicon voltage is out of range. Expected voltage '
                             f'level is in range {v_min} V - {v_max} V\n')
            else:
                exam_pass = True
            tool.set_ap(AP.SYS)

        # Verify entrance exam JWT signature
        if exam_pass:
            logger.info('Verify entrance exam JWT signature:')
            cy_pub_key = self.target.key_reader.get_cypress_public_key()
            exam_pass = Crypto.validate_jwt(jwt_text, cy_pub_key)
            if exam_pass:
                logger.info('Signature verified')
            else:
                logger.error('Invalid signature')

        # Verify ahb_reads32
        if exam_pass:
            json_data = Crypto.readable_jwt(jwt_text)
            payload = json_data['payload']
            tool.reset()
            exam_pass = self.verify_ahb_reads(tool, payload['ahb_reads'], 32)

        # Verify ahb_reads8
        if exam_pass:
            exam_pass &= self.verify_ahb_reads(tool, payload['ahb_reads8'], 8)

        # Verify region_hashes
        if exam_pass:
            for item in payload['region_hashes']:
                logger.info('.' * 70)
                logger.info(f'Verify {item["description"]}')
                logger.info('.' * 70)
                logger.info(f'Address: {item["address"]}')
                logger.info(f'Size:    {item["size"]}')
                logger.info(f'Mode:    {item["hash_id"]}')
                logger.info(f'Value:   {item["value"]}')
                syscall_status = region_hash(tool, self.reg_map)
                if syscall_status == RegionHashStatus.OK:
                    logger.info('PASS\n')
                else:
                    logger.info('FAIL\n')

        result = EntranceExamStatus.OK
        if exam_pass:
            if syscall_status == RegionHashStatus.FLASH_NOT_EMPTY:
                result = EntranceExamStatus.FLASH_NOT_EMPTY
            elif syscall_status == RegionHashStatus.FAIL:
                result = EntranceExamStatus.FAIL
        else:
            result = EntranceExamStatus.FAIL

        logger.info('*****************************************')
        if result == EntranceExamStatus.OK:
            logger.info('       ENTRANCE EXAM PASSED')
        else:
            logger.info('       ENTRANCE EXAM FAILED')
        logger.info('*****************************************')

        return result

    def log_protection_state(self, tool):
        lifecycle = read_lifecycle(tool, self.reg_map)
        try:
            protection_state = ProtectionState(lifecycle).name
        except ValueError:
            protection_state = f'{ProtectionState.unknown.name} ({lifecycle})'
        logger.info(f'Chip protection state: {protection_state.capitalize()}')

    def read_sfb_version(self, tool):
        jwt_text = Crypto.read_jwt(self.entrance_exam_jwt)
        json_data = Crypto.readable_jwt(jwt_text)
        payload = json_data['payload']
        major_version = None
        minor_version = None
        for item in payload['ahb_reads']:
            if item['description'].startswith('SFB_VER_HI'):
                address = int(item['address'], 0)
                mask = int(item['mask'], 0)
                sfb_ver_hi = tool.read32(address)
                major_version = sfb_ver_hi & mask
            if item['description'].startswith('SFB_VER_LO'):
                address = int(item['address'], 0)
                mask = int(item['mask'], 0)
                sfb_ver_lo = tool.read32(address)
                minor_version = sfb_ver_lo & mask
            if major_version and minor_version:
                break

        # Parse SFB version values
        maj_version = (sfb_ver_hi >> 24) & 0x0F
        min_version = (sfb_ver_hi >> 16) & 0xFF
        patch = sfb_ver_lo >> 24
        build = sfb_ver_lo & 0x0000FFFF

        return f'{maj_version}.{min_version}.{patch}.{build}'

    def read_device_info(self, tool):
        jwt_text = Crypto.read_jwt(self.entrance_exam_jwt)
        json_data = Crypto.readable_jwt(jwt_text)
        payload = json_data['payload']
        silicon_id = None
        silicon_rev = None
        family_id = None
        for item in payload['ahb_reads']:
            if item['description'].startswith('SI_ID'):
                address = int(item['address'], 0)
                silicon_id = tool.read32(address) >> 16 & 0xFFFF
                silicon_rev = tool.read32(address) >> 8 & 0xFF
            if item['description'].startswith('FAMILY_ID'):
                address = int(item['address'], 0)
                mask = int(item['mask'], 0)
                family_id = tool.read32(address) & mask
            if silicon_id and silicon_rev and family_id:
                break

        DeviceInfo = namedtuple('DeviceInfo',
                                'silicon_id silicon_rev family_id')
        dev_info = DeviceInfo(silicon_id, silicon_rev, family_id)
        return dev_info

    @staticmethod
    def verify_ahb_reads(tool, items, bits):
        """
        Verifies ahb_reads sections from entrance exam JWT packet.
        :param tool: Programming/debugging tool used for communication
               with device.
        :param items: ahb_reads items.
        :param bits: Indicates whether it is 8-bit or 32.-bit value.
        :return: True if values of all registers are as expected,
                 otherwise, False.
        """
        exam_pass = True
        for item in items:
            logger.info('.' * 70)
            logger.info(f'Verify {item["description"]}')
            logger.info('.' * 70)

            address = int(item['address'], 0)
            mask = int(item['mask'], 0)
            value = int(item['value'], 0)

            if bits == 8:
                read_value = tool.read8(address) & mask
            elif bits == 32:
                read_value = tool.read32(address) & mask
            else:
                ValueError('Invalid number of bits.')

            expected_value = value & mask
            logger.info(f'Address: {item["address"]}')
            logger.info(f'Expected value:     {hex(expected_value)}')
            logger.info(f'Received value:     {hex(read_value)}')
            if read_value == expected_value:
                logger.info('PASS\n')
            else:
                logger.info('FAIL\n')
                exam_pass = False
                if item['description'].startswith('SFB_VER_HI') \
                        or item['description'].startswith('SFB_VER_LO'):
                    logger.error(SFB_VER_ERROR)
        return exam_pass
