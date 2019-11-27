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

READ_SILICON_ID_OPCODE = 0x00
READ_SILICON_ID_COMM = 0x01
PROVISION_KEYS_AND_POLICIES_OPCODE = 0x33  # ProvisionKeysAndPolicies API opcode
GET_PROV_DETAILS_OPCODE = 0x37  # GetProvDetails() API opcode
REGION_HASH_OPCODE = 0x31  # RegionHash() API opcode
TRANSISION_TO_SECURE_OPCODE = 0x32  # TransitionToSecure() API code
GET_OPCODE = 0x37

logger = logging.getLogger(__name__)


def region_hash(tool, reg_map):
    """
    Procedure calls RegionHash syscall over IPC and read response.
    :param tool: Programming/debugging tool used for communication with device.
    :param reg_map: Device register map.
    :return: True if syscall executed successfully, otherwise False.
    """
    sram_addr = reg_map.ENTRANCE_EXAM_SRAM_ADDR
    address = reg_map.ENTRANCE_EXAM_REGION_HASH_ADDR
    length = reg_map.ENTRANCE_EXAM_REGION_HASH_SIZE
    mode = reg_map.ENTRANCE_EXAM_REGION_HASH_MODE
    exp_value = reg_map.ENTRANCE_EXAM_REGION_HASH_EXPECTED_VAL

    # Acquire IPC structure
    tool.write32(reg_map.CYREG_IPC2_STRUCT_ACQUIRE, 0x80000000)
    ipc_acquire = 0
    while (ipc_acquire & 0x80000000) == 0:
        ipc_acquire = tool.read32(reg_map.CYREG_IPC2_STRUCT_ACQUIRE)

    # Set RAM address and Opcode
    op_code = (REGION_HASH_OPCODE << 24) + (exp_value << 16) + (mode << 8) + 0
    tool.write32(reg_map.CYREG_IPC2_STRUCT_DATA, sram_addr)
    tool.write32(sram_addr, op_code)

    scratch_addr = sram_addr + 0x08
    tool.write32(sram_addr + 0x04, scratch_addr)
    tool.write32(sram_addr + 0x08, length)
    tool.write32(sram_addr + 0x0C, address)

    # IPC_STRUCT[ipc_id].IPC_NOTIFY -
    tool.write32(reg_map.CYREG_IPC2_STRUCT_NOTIFY, 0x00000001)

    # Wait on response
    response = 0x80000000
    while (response & 0x80000000) != 0:
        response = tool.read32(reg_map.CYREG_IPC2_STRUCT_LOCK_STATUS)
    response = tool.read32(sram_addr)

    if (response & 0xFF000000) == 0xa0000000:
        logger.info('Region compare complete')
        return True
    else:
        logger.error('Region compare error response:')
        logger.info(f'{hex(reg_map.CYREG_IPC2_STRUCT_DATA)} {hex(tool.read32(reg_map.CYREG_IPC2_STRUCT_DATA))}')
        logger.info(f'{hex(sram_addr)} {hex(tool.read32(sram_addr))}')
        logger.info(f'{hex(sram_addr + 0x04)} {hex(tool.read32(sram_addr + 0x04))}')
        logger.info(f'{hex(sram_addr + 0x08)} {hex(tool.read32(sram_addr + 0x08))}')
        logger.info(f'{hex(sram_addr + 0x0C)} {hex(tool.read32(sram_addr + 0x0C))}')
        return False


def get_prov_details(tool, key_id, reg_map):
    """
    Calls GetProvDetails syscall over IPC.
    :param tool: Programming/debugging tool used for communication with device.
    :param key_id: Public key ID.
    :param reg_map: Device register map.
    :return: True if get provision details successfully, otherwise False.
    """
    sram_addr = reg_map.ENTRANCE_EXAM_SRAM_ADDR

    # Acquire IPC structure
    tool.write32(reg_map.CYREG_IPC2_STRUCT_ACQUIRE, 0x80000000)
    logger.info(f'{hex(reg_map.CYREG_IPC2_STRUCT_ACQUIRE)} {hex(tool.read32(reg_map.CYREG_IPC2_STRUCT_ACQUIRE))}')
    ipc_acquire = 0
    while (ipc_acquire & 0x80000000) == 0:
        ipc_acquire = tool.read32(reg_map.CYREG_IPC2_STRUCT_ACQUIRE)

    # Set RAM address and Opcode
    op_code = GET_PROV_DETAILS_OPCODE << 24
    tool.write32(reg_map.CYREG_IPC2_STRUCT_DATA, sram_addr)  # IPC_STRUCT.DATA
    tool.write32(sram_addr, op_code)  # SRAM_SCRATCH

    scratch_addr = sram_addr + 0x08
    tool.write32(sram_addr + 0x04, scratch_addr)
    tool.write32(sram_addr + 0x08, key_id)
    tool.write32(sram_addr + 0x0C, 0x0)

    # IPC_STRUCT[ipc_id].IPC_NOTIFY -
    tool.write32(reg_map.CYREG_IPC2_STRUCT_NOTIFY, 0x00000001)

    # Wait for response
    response = 0x80000000
    while (response & 0x80000000) != 0:
        response = tool.read32(reg_map.CYREG_IPC2_STRUCT_LOCK_STATUS)
    response = tool.read32(sram_addr)

    logger.info(f'{hex(reg_map.CYREG_IPC2_STRUCT_DATA)} {hex(tool.read32(reg_map.CYREG_IPC2_STRUCT_DATA))}')
    logger.info(f'{hex(sram_addr)} {hex(tool.read32(sram_addr))}')  # Expected MSB=0xA0
    logger.info(f'{hex(sram_addr + 0x04)} {hex(tool.read32(sram_addr + 0x04))}')
    logger.info(f'{hex(sram_addr + 0x08)} {hex(tool.read32(sram_addr + 0x08))}')

    is_exam_pass = (response & 0xFF000000) == 0xa0000000
    if is_exam_pass:
        scratch_addr = tool.read32(sram_addr + 0x04)
        read_hash_size = tool.read32(scratch_addr + 0x00)
        read_hash_addr = tool.read32(scratch_addr + 0x04)

        i = 0
        response = ''
        while i < read_hash_size:
            # Save data in string format
            hash_byte_chr = chr(tool.read8(read_hash_addr + i))
            response += hash_byte_chr
            i += 1
        response = response.strip()
    else:
        logger.info(f'{hex(reg_map.CYREG_IPC2_STRUCT_DATA)} {tool.read32(reg_map.CYREG_IPC2_STRUCT_DATA)}')
        logger.info(f'{hex(sram_addr)} {tool.read32(sram_addr)}')
        response = None

    return is_exam_pass, response


def provision_keys_and_policies(tool, blow_secure_efuse, filename, reg_map):
    """
    Calls ProvisionKeysAndPolicies syscall over IPC.
    :param tool: Programming/debugging tool used for communication with device.
    :param blow_secure_efuse: Indicates whether to convert device to SECURE CLAIMED mode.
    :param filename: Path to provisioning JWT file (packet which contains
           all data necessary for provisioning, including policy, authorization
           packets and keys).
    :param reg_map: Device register map.
    :return: True if sending provision keys and policies passed, otherwise False
    """
    file_size = os.path.getsize(filename)
    if file_size > reg_map.ENTRANCE_EXAM_SRAM_SIZE:
        logger.error('JWT packet too long')
        return False

    logger.info('UDS eFuses will be blown' if blow_secure_efuse == 1 else 'UDS eFuses will NOT be blown')
    logger.info(f'JWT packet size: {file_size}')
    with open(filename, 'r+') as jwt_file:
        jwt_file.seek(0)
        content = jwt_file.read()
    jwt_chars = list(content)

    # Acquires IPC structure.
    tool.write32(reg_map.CYREG_IPC2_STRUCT_ACQUIRE, 0x80000000)
    logger.info(f'{hex(reg_map.CYREG_IPC2_STRUCT_ACQUIRE)} {hex(tool.read32(reg_map.CYREG_IPC2_STRUCT_ACQUIRE))}')

    ipc_acquire = 0
    while (ipc_acquire & 0x80000000) == 0:
        ipc_acquire = tool.read32(reg_map.CYREG_IPC2_STRUCT_ACQUIRE)

    # Set RAM address and Opcode
    tool.write32(reg_map.CYREG_IPC2_STRUCT_DATA, reg_map.ENTRANCE_EXAM_SRAM_ADDR)
    tool.write32(reg_map.ENTRANCE_EXAM_SRAM_ADDR, (PROVISION_KEYS_AND_POLICIES_OPCODE << 24) + (blow_secure_efuse << 16))

    scratch_addr = reg_map.ENTRANCE_EXAM_SRAM_ADDR + 0x08
    tool.write32(reg_map.ENTRANCE_EXAM_SRAM_ADDR + 0x04, scratch_addr)
    tool.write32(reg_map.ENTRANCE_EXAM_SRAM_ADDR + 0x08, file_size + 0x04)
    scratch_addr = reg_map.ENTRANCE_EXAM_SRAM_ADDR + 0x0C

    for char in jwt_chars:
        tool.write8(scratch_addr, ord(char))
        scratch_addr += 1

    # IPC_STRUCT[ipc_id].IPC_NOTIFY -
    tool.write32(reg_map.CYREG_IPC2_STRUCT_NOTIFY, 0x00000001)
    logger.info(f'{hex(reg_map.CYREG_IPC2_STRUCT_NOTIFY)} {hex(tool.read32(reg_map.CYREG_IPC2_STRUCT_NOTIFY))}')
    # Wait for response
    response = 0x80000000
    while (response & 0x80000000) != 0:
        response = tool.read32(reg_map.CYREG_IPC2_STRUCT_LOCK_STATUS)

    # Read response for test
    logger.info(f'{hex(reg_map.CYREG_IPC2_STRUCT_DATA)} {hex(tool.read32(reg_map.CYREG_IPC2_STRUCT_DATA))}')
    i = 0
    addr_list = list()
    while i < 4 * 4:  # output 4 words
        addr_list.append(hex(tool.read32(reg_map.ENTRANCE_EXAM_SRAM_ADDR)))
        i += 4
    logger.info(f'{hex(reg_map.ENTRANCE_EXAM_SRAM_ADDR)}: {" ".join(addr_list)}\n')

    response = tool.read32(reg_map.ENTRANCE_EXAM_SRAM_ADDR)
    result = (response & 0xFF000000) == 0xa0000000

    if result:
        logger.info('ProvisionKeysAndPolicies complete')
    else:
        logger.error(f'ProvisionKeysAndPolicies error response: {hex(response)}')
    return result


def transition_to_secure(tool, blow_secure_efuse, reg_map):
    """
    Calls TransitionToSecure syscall over IPC.
    :param tool: Programming/debugging tool used for communication with device.
    :param blow_secure_efuse: Indicates whether to convert device to SECURE mode.
    :param reg_map: Device register map.
    :return: True if success, otherwise False.
    """
    if blow_secure_efuse:
        blowing_secure_value = 0
        logger.info('Chip will be converted to SECURE mode')
    else:
        blowing_secure_value = 1
        logger.info('Chip will NOT be converted to SECURE mode')

    # Acquires IPC structure.
    tool.write32(reg_map.CYREG_IPC2_STRUCT_ACQUIRE, 0x80000000)

    ipc_acquire = 0
    while (ipc_acquire & 0x80000000) == 0:
        ipc_acquire = tool.read32(reg_map.CYREG_IPC2_STRUCT_ACQUIRE)

    # Set RAM address and Opcode
    tool.write32(reg_map.CYREG_IPC2_STRUCT_DATA, reg_map.ENTRANCE_EXAM_SRAM_ADDR)
    logger.debug(f'blowing_secure_value = {blowing_secure_value}')
    tool.write32(reg_map.ENTRANCE_EXAM_SRAM_ADDR, (TRANSISION_TO_SECURE_OPCODE << 24) + (blowing_secure_value << 16))
    scratch_addr = reg_map.ENTRANCE_EXAM_SRAM_ADDR + 0x08
    tool.write32(reg_map.ENTRANCE_EXAM_SRAM_ADDR + 0x04, scratch_addr)
    tool.write32(reg_map.ENTRANCE_EXAM_SRAM_ADDR + 0x08, 0)
    tool.write32(reg_map.ENTRANCE_EXAM_SRAM_ADDR + 0x0C, 0)

    # IPC_STRUCT[ipc_id].IPC_NOTIFY -
    tool.write32(reg_map.CYREG_IPC2_STRUCT_NOTIFY, 0x00000001)
    # Wait for response
    response = 0x80000000
    while (response & 0x80000000) != 0:
        response = tool.read32(reg_map.CYREG_IPC2_STRUCT_LOCK_STATUS)

    response = tool.read32(reg_map.ENTRANCE_EXAM_SRAM_ADDR)
    if response & 0xFF000000 == 0xa0000000:
        # # Read region_hash values from application
        scratch_addr = tool.read32(reg_map.ENTRANCE_EXAM_SRAM_ADDR + 0x04)
        read_hash_size = tool.read32(scratch_addr + 0x00)
        read_hash_addr = tool.read32(scratch_addr + 0x04)
        response = ''

        i = 0
        while i < read_hash_size:
            # Save data in string format
            hash_byte_chr = chr(tool.read8(read_hash_addr + i))
            response += hash_byte_chr
            i += 1
        logger.info(f'Response = {response.strip()}')
        logger.info('Transition to Secure complete\n')
        return True
    else:
        logger.error('Transition to Secure Error response:')
        logger.info(f'{hex(reg_map.CYREG_IPC2_STRUCT_DATA)} {hex(tool.read32(reg_map.CYREG_IPC2_STRUCT_DATA))}')
        logger.info(f'{hex(reg_map.ENTRANCE_EXAM_SRAM_ADDR)} {hex(tool.read32(reg_map.ENTRANCE_EXAM_SRAM_ADDR))}\n')
        return False


def read_lifecycle(tool, reg_map):
    tool.write32(reg_map.CYREG_IPC2_STRUCT_ACQUIRE, 0x80000000)
    ipc_acquire = 0
    while (ipc_acquire & 0x80000000) == 0:
        ipc_acquire = tool.read32(reg_map.CYREG_IPC2_STRUCT_ACQUIRE)
    # Set RAM address and Opcode
    tool.write32(reg_map.CYREG_IPC2_STRUCT_DATA, (READ_SILICON_ID_OPCODE << 24) + (READ_SILICON_ID_COMM << 8) + 1)
    tool.write32(reg_map.CYREG_IPC2_STRUCT_NOTIFY, 0x00000001)
    # Wait for response
    response = 0x80000000
    while (response & 0x80000000) != 0:
        response = tool.read32(reg_map.CYREG_IPC2_STRUCT_LOCK_STATUS)
    response = tool.read32(reg_map.CYREG_IPC2_STRUCT_DATA)
    if response & 0xFF000000 == 0xa0000000:
        return (response >> 16) & 0x0f
