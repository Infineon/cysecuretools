"""
Copyright (c) 2018-2020 Cypress Semiconductor Corporation

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
from cysecuretools.core.enums import RegionHashStatus
import cysecuretools.data.mxs40v1.mxs40v1_sfb_status_codes as sfb_status

# SysCall operation codes
READ_SILICON_ID_OPCODE = 0x00
READ_SILICON_ID_COMM = 0x01
REGION_HASH_OPCODE = 0x31
PROVISIONING_OPCODE = 0x33
ENCRYPTED_PROGRAMMING_OPCODE = 0x34
GET_PROV_DETAILS_OPCODE = 0x37
SET_DAP_CONTROL_OPCODE = 0x3A

# GetProvDetails SysCall codes
FB_POLICY_JWT = 0x100
FB_POLICY_IMG_CERTIFICATE = 0x300

logger = logging.getLogger(__name__)


def region_hash(tool, reg_map):
    """
    Procedure calls RegionHash syscall over IPC and read response.
    :param tool: Programming/debugging tool.
    :param reg_map: Device register map.
    :return: Region hash status
    """
    result = RegionHashStatus.OK
    logger.debug('Start RegionHash syscall')
    sram_addr = reg_map.ENTRANCE_EXAM_SRAM_ADDR
    address = reg_map.ENTRANCE_EXAM_REGION_HASH_ADDR
    length = reg_map.ENTRANCE_EXAM_REGION_HASH_SIZE
    mode = reg_map.ENTRANCE_EXAM_REGION_HASH_MODE
    exp_value = reg_map.ENTRANCE_EXAM_REGION_HASH_EXPECTED_VAL

    # Acquire IPC structure
    if not wait_acquire_ipc_struct(tool, reg_map):
        raise TimeoutError('Acquire IPC struct timeout.')

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

    wait_release_ipc_struct(tool, reg_map)
    response = tool.read32(sram_addr)

    if (response & 0xFF000000) == 0xa0000000:
        logger.debug('RegionHash syscall passed')
    else:
        if response == sfb_status.get_code_by_name('CY_FB_INVALID_FLASH_OPERATION'):
            result = RegionHashStatus.FLASH_NOT_EMPTY
        else:
            logger.error(f'RegionHash syscall error: {hex(response)}')
            print_sfb_status(response)
            result = RegionHashStatus.FAIL

    return result


def get_prov_details(tool, reg_map, key_id):
    """
    Calls GetProvDetails syscall over IPC.
    :param tool: Programming/debugging tool.
    :param key_id: Public key ID.
    :param reg_map: Device register map.
    :return: True if syscall succeeds, otherwise False.
    """
    logger.debug('Start GetProvDetails syscall')
    sram_addr = reg_map.ENTRANCE_EXAM_SRAM_ADDR

    # Acquire IPC structure
    if not wait_acquire_ipc_struct(tool, reg_map):
        raise TimeoutError('Acquire IPC struct timeout.')

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
    wait_release_ipc_struct(tool, reg_map)
    response = tool.read32(sram_addr)

    log_reg_value(tool, reg_map.CYREG_IPC2_STRUCT_DATA)
    log_reg_value(tool, sram_addr)
    log_reg_value(tool, sram_addr + 0x04)
    log_reg_value(tool, sram_addr + 0x08)

    is_exam_pass = (response & 0xFF000000) == 0xa0000000
    if is_exam_pass:
        scratch_addr = tool.read32(sram_addr + 0x04)
        read_hash_size = tool.read32(scratch_addr + 0x00)
        read_hash_addr = tool.read32(scratch_addr + 0x04)

        i = 0
        prov_details = ''
        while i < read_hash_size:
            # Save data in string format
            hash_byte_chr = chr(tool.read8(read_hash_addr + i))
            prov_details += hash_byte_chr
            i += 1
        prov_details = prov_details.strip()
        logger.debug('GetProvDetails syscall passed')
    else:
        logger.debug(f'GetProvDetails syscall error: {hex(response)}')
        print_sfb_status(response, severity='debug')
        prov_details = None

    return is_exam_pass, prov_details


def provision_keys_and_policies(tool, filename, reg_map):
    """
    Calls ProvisionKeysAndPolicies syscall over IPC.
    :param tool: Programming/debugging tool.
    :param filename: Path to provisioning JWT file.
    :param reg_map: Device register map.
    :return: Tuple with the syscall result and device response
    """
    logger.debug('Start ProvisionKeysAndPolicies syscall')
    if filename:
        file_size = os.path.getsize(filename)
        if file_size > reg_map.ENTRANCE_EXAM_SRAM_SIZE:
            logger.error('JWT packet too long')
            return False

        logger.info(f'JWT packet size = {file_size}')
        with open(filename, 'r+') as jwt_file:
            jwt_file.seek(0)
            content = jwt_file.read()
        jwt_chars = list(content)
    else:
        file_size = 0
        jwt_chars = list()

    # Acquire IPC structure
    logger.debug('Acquire IPC structure')
    if not wait_acquire_ipc_struct(tool, reg_map):
        raise TimeoutError('Acquire IPC struct timeout.')
    else:
        log_reg_value(tool, reg_map.CYREG_IPC2_STRUCT_ACQUIRE)

    # Set RAM address and Opcode
    tool.write32(reg_map.CYREG_IPC2_STRUCT_DATA,
                 reg_map.ENTRANCE_EXAM_SRAM_ADDR)
    log_reg_value(tool, reg_map.CYREG_IPC2_STRUCT_DATA)
    tool.write32(reg_map.ENTRANCE_EXAM_SRAM_ADDR, (PROVISIONING_OPCODE << 24))
    log_reg_value(tool, reg_map.ENTRANCE_EXAM_SRAM_ADDR)

    scratch_addr = reg_map.ENTRANCE_EXAM_SRAM_ADDR + 0x08
    tool.write32(reg_map.ENTRANCE_EXAM_SRAM_ADDR + 0x04, scratch_addr)
    log_reg_value(tool, reg_map.ENTRANCE_EXAM_SRAM_ADDR + 0x04)
    tool.write32(reg_map.ENTRANCE_EXAM_SRAM_ADDR + 0x08, file_size + 0x04)
    log_reg_value(tool, reg_map.ENTRANCE_EXAM_SRAM_ADDR + 0x08)
    scratch_addr = reg_map.ENTRANCE_EXAM_SRAM_ADDR + 0x0C

    for char in jwt_chars:
        tool.write8(scratch_addr, ord(char))
        scratch_addr += 1

    if not jwt_chars:
        sleep(1)

    ipc_struct_notify(tool, reg_map)
    wait_release_ipc_struct(tool, reg_map)
    logger.debug('Reading response')

    # Read response for test
    log_reg_value(tool, reg_map.CYREG_IPC2_STRUCT_DATA)
    log_reg_value(tool, reg_map.ENTRANCE_EXAM_SRAM_ADDR)

    status = tool.read32(reg_map.ENTRANCE_EXAM_SRAM_ADDR)
    result = (status & 0xFF000000) == 0xa0000000
    response = None

    if result:
        logger.debug('ProvisionKeysAndPolicies syscall passed')
        response = read_device_response(tool, reg_map)
    else:
        if filename:
            logger.error(f'ProvisionKeysAndPolicies syscall error: '
                         f'{hex(status)}')
            print_sfb_status(status)
        else:
            syscall_invalid_arg = \
                sfb_status.get_code_by_name('CY_FB_SYSCALL_INVALID_ARGUMENT')
            if status == syscall_invalid_arg:
                response = read_device_response(tool, reg_map)
                result = True  # it is expected when no JWT packet specified
    return result, response


def encrypted_programming(tool, reg_map, mode, data, host_key_id=0,
                          dev_key_id=0, addr=None):
    """
    Calls EncryptedProgramming syscall over IPC.
    :param tool: Programming/debugging tool.
    :param reg_map: Device register map.
    :param mode: Syscall Mode: 0x00 - Init, 0x01 - Data, 0x02 - Finish.
    :param data: The data to program.
    :param host_key_id: Host private key ID (4 - HSM, 5 - OEM).
    :param dev_key_id: Device public key ID (1 - device, 12 - group).
    :param addr: Data address (used for Data mode only).
    :return: True if syscall succeeds, otherwise False.
    """
    logger.debug('Start EncryptedProgramming syscall')
    # Encrypted programming modes
    mode_init = 0x00
    mode_data = 0x01
    mode_finish = 0x02

    sram_addr_claimed = reg_map.ENTRANCE_EXAM_SRAM_ADDR + (
            reg_map.ENTRANCE_EXAM_SRAM_SIZE >> 1)

    data_size = 0 if mode == mode_finish else len(data)
    program_row_size = int(data_size / 2)

    # Acquire IPC structure
    wait_acquire_ipc_struct(tool, reg_map)

    # Set RAM address and Opcode
    op_code = (ENCRYPTED_PROGRAMMING_OPCODE << 24) + (host_key_id << 16) + \
              (dev_key_id << 8) + int(mode)

    logger.debug('Write registers:')
    logger.debug(f'{hex(reg_map.CYREG_IPC2_STRUCT_DATA)} <- '
                 f'{hex(sram_addr_claimed)}')
    tool.write32(reg_map.CYREG_IPC2_STRUCT_DATA, sram_addr_claimed)

    logger.debug(f'{hex(sram_addr_claimed)} <- {hex(op_code)}')
    tool.write32(sram_addr_claimed, op_code)

    scratch_addr = sram_addr_claimed + 0x08
    logger.debug(f'{hex(sram_addr_claimed + 0x04)} <- {hex(scratch_addr)}')
    tool.write32(sram_addr_claimed + 0x04, scratch_addr)

    logger.debug(f'{hex(sram_addr_claimed + 0x08)} <- {hex(data_size >> 1)}')
    tool.write32(sram_addr_claimed + 0x08, data_size >> 1)
    scratch_addr = sram_addr_claimed + 0x0C

    logger.debug('Clear RAM')
    for i in range(0, 512):
        tool.write8(scratch_addr, 0x00)
        scratch_addr += 1

    scratch_addr = sram_addr_claimed + 0x0C

    if mode_init == mode:
        logger.debug('Write AES header to RAM')
        for i in range(0, len(data), 2):
            b = int(data[i:i + 2], 16)
            tool.write8(scratch_addr, b)
            scratch_addr += 1

    elif mode_data == mode:
        tool.write32(sram_addr_claimed + 0x08, program_row_size)
        tool.write32(scratch_addr, addr)
        scratch_addr += 4
        logger.debug('Write data to RAM')
        for i in range(0, len(data), 2):
            b = int(data[i:i + 2], 16)
            tool.write8(scratch_addr, b)
            scratch_addr += 1

    # Read written data
    logger.debug('Read registers:')
    log_reg_value(tool, reg_map.CYREG_IPC2_STRUCT_DATA)
    log_reg_value(tool, sram_addr_claimed)
    log_reg_value(tool, sram_addr_claimed + 0x04)
    log_reg_value(tool, sram_addr_claimed + 0x08)
    log_reg_value(tool, sram_addr_claimed + 0x0C)

    ipc_struct_notify(tool, reg_map)

    wait_release_ipc_struct(tool, reg_map)

    response = tool.read32(sram_addr_claimed)

    # Read response for test
    log_reg_value(tool, reg_map.CYREG_IPC2_STRUCT_DATA)
    log_reg_value(tool, sram_addr_claimed)
    log_reg_value(tool, sram_addr_claimed + 0x04)
    log_reg_value(tool, sram_addr_claimed + 0x08)
    log_reg_value(tool, sram_addr_claimed + 0x0C)

    if response & 0xFF000000 == 0xa0000000:
        logger.debug('EncryptedProgramming syscall passed')
        return True
    else:
        logger.error(f'EncryptedProgramming syscall error: {hex(response)}')
        print_sfb_status(response)
        return False


def dap_control(tool, reg_map, cpu_id, desired_state, jwt_not_required,
                filename):
    """
    Calls DAPControl SysCall over IPC
    :param tool: Programming/debugging tool
    :param reg_map: Device register map
    :param cpu_id: CPU ID (0-CM0, 1-CM4, 2-SYS)
    :param desired_state: The state to be set for the AP
    :param jwt_not_required: Indicates whether SysCall can control the
           DAP with (control is set to 'certificate') or without
           (control is set to 'open') a signed certificate (JWT)
    :param filename: Path to the certificate (JWT)
    :return: True if SysCall succeeds, otherwise False
    """
    if cpu_id == 0:
        logger.debug(f'Config cm0 AP, desired state = {desired_state}')
    elif cpu_id == 1:
        logger.debug(f'Config cm4 AP, desired state = {desired_state}')
    elif cpu_id == 2:
        logger.debug(f'Config system AP, desired state = {desired_state}')
    else:
        raise ValueError(f'Invalid CPU ID {cpu_id}')

    wait_acquire_ipc_struct(tool, reg_map)

    disable_jwt_use = 1 if jwt_not_required else 0
    op_code = (SET_DAP_CONTROL_OPCODE << 24) + (desired_state << 16) + (cpu_id << 8) + disable_jwt_use

    if jwt_not_required:
        logger.debug('JWT is NOT required')
        tool.write32(reg_map.CYREG_IPC2_STRUCT_DATA, op_code)
        log_reg_value(tool, reg_map.CYREG_IPC2_STRUCT_DATA)
    else:
        logger.debug('JWT is required')
        if not filename:
            raise ValueError('JWT certificate is required but not specified')

        file_size = os.path.getsize(filename)
        if file_size > reg_map.ENTRANCE_EXAM_SRAM_SIZE:
            logger.error('JWT packet too long')
            return False

        logger.debug(f'JWT packet size: {file_size}')
        with open(filename, 'r+') as jwt_file:
            jwt_file.seek(0)
            content = jwt_file.read()
        jwt_chars = list(content)

        # Set RAM address and Opcode
        tool.write32(reg_map.CYREG_IPC2_STRUCT_DATA,
                     reg_map.ENTRANCE_EXAM_SRAM_ADDR)
        tool.write32(reg_map.ENTRANCE_EXAM_SRAM_ADDR, op_code)
        scratch_addr = reg_map.ENTRANCE_EXAM_SRAM_ADDR + 0x08
        tool.write32(reg_map.ENTRANCE_EXAM_SRAM_ADDR + 0x04, scratch_addr)
        tool.write32(reg_map.ENTRANCE_EXAM_SRAM_ADDR + 0x08, file_size)
        scratch_addr = reg_map.ENTRANCE_EXAM_SRAM_ADDR + 0x0C

        for char in jwt_chars:
            tool.write8(scratch_addr, ord(char))
            scratch_addr += 1

        log_reg_value(tool, reg_map.ENTRANCE_EXAM_SRAM_ADDR)
        log_reg_value(tool, reg_map.ENTRANCE_EXAM_SRAM_ADDR + 0x04)
        log_reg_value(tool, reg_map.ENTRANCE_EXAM_SRAM_ADDR + 0x08)
        log_reg_value(tool, reg_map.ENTRANCE_EXAM_SRAM_ADDR + 0x0C)

    ipc_struct_notify(tool, reg_map)
    wait_release_ipc_struct(tool, reg_map)

    if jwt_not_required:
        response = tool.read32(reg_map.CYREG_IPC2_STRUCT_DATA)
    else:
        response = tool.read32(reg_map.ENTRANCE_EXAM_SRAM_ADDR)

    if response & 0xFF000000 == 0xa0000000:
        logger.debug('DAP_Control SysCall passed')
        return True
    else:
        logger.error(f'DAP_Control SysCall error: {hex(response)}')
        print_sfb_status(response)
        log_reg_value(tool, reg_map.CYREG_IPC2_STRUCT_DATA)
        log_reg_value(tool, reg_map.ENTRANCE_EXAM_SRAM_ADDR)
        return False


def read_lifecycle(tool, reg_map):
    """
    Reads device lifecycle
    :param tool: Programming/debugging tool.
    :param reg_map: Device register map.
    :return: The value that indicates device current lifecycle
    """
    tool.write32(reg_map.CYREG_IPC2_STRUCT_ACQUIRE, 0x80000000)
    ipc_acquire = 0
    while (ipc_acquire & 0x80000000) == 0:
        ipc_acquire = tool.read32(reg_map.CYREG_IPC2_STRUCT_ACQUIRE)
    # Set RAM address and Opcode
    tool.write32(reg_map.CYREG_IPC2_STRUCT_DATA, (READ_SILICON_ID_OPCODE << 24)
                 + (READ_SILICON_ID_COMM << 8) + 1)
    tool.write32(reg_map.CYREG_IPC2_STRUCT_NOTIFY, 0x00000001)
    # Wait for response
    wait_release_ipc_struct(tool, reg_map)
    response = tool.read32(reg_map.CYREG_IPC2_STRUCT_DATA)
    if response & 0xFF000000 == 0xa0000000:
        return (response >> 16) & 0x0f


def read_device_response(tool, reg_map):
    """
    Reads device JWT response after provisioning syscall execution
    """
    scratch_addr = tool.read32(reg_map.ENTRANCE_EXAM_SRAM_ADDR + 0x04)
    resp_size = tool.read32(scratch_addr)
    resp_addr = tool.read32(scratch_addr + 0x04)
    logger.debug(f'Device response address = {hex(resp_addr)}')
    logger.debug(f'Device response size = {resp_size}')
    response = ''
    for i in range(resp_size):
        hash_byte_chr = chr(tool.read8(resp_addr + i))
        response += hash_byte_chr
    response = response.strip()
    logger.info(f'Device response = \'{response}\'')
    return response


def wait_acquire_ipc_struct(tool, reg_map, timeout=5000):
    """
    Wait for acquires IPC structure.
    :param tool: Programming/debugging tool.
    :param reg_map: Device register map.
    :param timeout: Timeout to acquire structure.
    :return: IPC acquire status (True or False)
    """
    logger.debug('Start wait_acquire_ipc_struct')
    tool.write32(reg_map.CYREG_IPC2_STRUCT_ACQUIRE, 0x80000000)

    count = 0
    ipc_acquire = 0
    while (ipc_acquire & 0x80000000) == 0 and count < timeout:
        ipc_acquire = tool.read32(reg_map.CYREG_IPC2_STRUCT_ACQUIRE)
        count += 1
        sleep(0.2)
    if count >= timeout:
        raise TimeoutError('IPC structure release timeout')

    result = (ipc_acquire & (1 << 31)) != 0
    logger.debug(f'wait_acquire_ipc_struct result \'{hex(result)}\'')
    return result


def wait_release_ipc_struct(tool, reg_map, timeout=1500):
    """
    Wait for release IPC structure.
    :param tool: Programming/debugging tool.
    :param reg_map: Device register map.
    :param timeout: Timeout to release structure.
    :return: IPC acquire status (True or False)
    """
    logger.debug('Start wait_release_ipc_struct')
    response = 0x80000000
    count = 0
    while (response & 0x80000000) != 0 and count < timeout:
        response = tool.read32(reg_map.CYREG_IPC2_STRUCT_LOCK_STATUS)
        count += 1
        sleep(0.2)
    if count >= timeout:
        raise TimeoutError('IPC structure release timeout')
    result = (response & (1 << 31)) != 0
    logger.debug(f'wait_release_ipc_struct result \'{hex(result)}\'')
    return result


def ipc_struct_notify(tool, reg_map):
    """
    IPC_STRUCT[ipc_id].IPC_NOTIFY
    :param tool: Programming/debugging tool.
    :param reg_map: Device register map.
    """
    logger.debug('ipc_struct_notify')
    tool.write32(reg_map.CYREG_IPC2_STRUCT_NOTIFY, 0x00000001)


def print_sfb_status(status_code, severity='error'):
    """
    Outputs SFB status description
    :param status_code: SFB status code
    :param severity: The severity of the status message
    """
    try:
        status = sfb_status.sfb_status_codes[status_code]
        msg = f'SFB status: {status["status"]}: {status["desc"]}'
        if severity == 'error':
            logger.error(msg)
        elif severity == 'warning':
            logger.warning(msg)
        elif severity == 'info':
            logger.info(msg)
        elif severity == 'debug':
            logger.debug(msg)
        else:
            raise ValueError(f'Invalid severity argument')
    except KeyError:
        logger.debug(f'Unexpected SFB status {hex(status_code)}')


def log_reg_value(tool, register):
    """
    Outputs register value for debugging
    """
    logger.debug(f'{hex(register)} {hex(tool.read32(register))}')
