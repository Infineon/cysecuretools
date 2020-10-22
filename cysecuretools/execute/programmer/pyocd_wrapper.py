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
import json
import logging
from cysecuretools.execute.programmer.base import ProgrammerBase, ResetType, AP
from pyocd.core.helpers import ConnectHelper
from pyocd.flash.file_programmer import FileProgrammer
from pyocd.flash.eraser import FlashEraser
from pyocd import coresight

TARGET_MAP = os.path.join(os.path.dirname(__file__), 'pyocd_target_map.json')
logger = logging.getLogger(__name__)


class Pyocd(ProgrammerBase):
    def __init__(self):
        super(Pyocd, self).__init__()
        self.session = None
        self.board = None
        self.target = None
        self.probe = None
        self.ap = None
        self._wait_for_target = None

    @property
    def wait_for_target(self):
        """
        Gets a value indicating whether to wait for the target
        if no available devices are connected
        """
        return self._wait_for_target

    @wait_for_target.setter
    def wait_for_target(self, value):
        """
        Sets a value indicating whether to wait for the target
        if no available devices are connected
        """
        self._wait_for_target = value

    def connect(self, target_name=None, interface=None, probe_id=None,
                ap='cm4', blocking=True):
        """
        Connects to target using default debug interface.
        :param target_name: The target name.
        :param interface: Debug interface.
        :param ap: The access port used for communication (cm0 or cm4).
        :param probe_id: Probe serial number.
        :param blocking: Specifies whether to wait for a probe to be
               connected if there are no available probes.
        :return: True if connected successfully, otherwise False.
        """
        if interface:
            raise NotImplementedError
        else:
            if target_name:
                logger.info(f'Target: {target_name}')
                # Search for device in target map
                with open(TARGET_MAP) as f:
                    file_content = f.read()
                    json_data = json.loads(file_content)
                for json_target in json_data:
                    if target_name.lower().strip() == json_target.lower().strip():
                        target_name = json_data[json_target][ap.lower()]
                        break
                options = {
                    'target_override': target_name
                }
            else:
                options = {}

            if self.wait_for_target is not None:
                blocking = self.wait_for_target

            self.session = \
                ConnectHelper.session_with_chosen_probe(blocking=blocking,
                                                        options=options,
                                                        board_id=probe_id,
                                                        unique_id=probe_id)
            if self.session is None:
                return False
            self.board = self.session.board
            self.session.open()

            self.target = self.board.target
            self.probe = self.session.probe
            self.ap = ap
            self.set_ap(AP.SYS)
            logger.info(f'Probe ID: {self.probe.unique_id}')
            return True

    def disconnect(self):
        """
        Closes active connection.
        """
        if self.session is None:
            raise ValueError('Debug session is not initialized.')
        self.session.close()

    def get_ap(self):
        """
        Gets access port.
        :return: Selected AP.
        """
        if self.target.selected_core == self.target.cores[0]:
            ap = AP.SYS
        elif self.target.selected_core == self.target.cores[1]:
            ap = AP.CMx
        logger.debug(f'AP: {ap}')
        return ap

    def set_ap(self, ap):
        """
        Sets access port.
        :param ap: The AP name.
        """
        if ap == AP.SYS:
            logger.info('Use system AP')
            if self.get_ap() != AP.SYS:
                self._start_core()
            self.target.selected_core = 0
        elif ap == AP.CM0:
            logger.info('Use cm0 AP')
            self.target.selected_core = 1
            self._start_core()
        elif ap == AP.CM4:
            logger.info('Use cm4 AP')
            self.target.selected_core = 1
            self._start_core()
        elif ap == AP.CMx:
            logger.info(f'Use {self.ap} AP')
            self.target.selected_core = 1
            self._start_core()
        else:
            raise ValueError('Invalid access port.')

    def _start_core(self):
        """
        Writes infinite loop into RAM and starts core execution.
        """
        logger.debug('Start core')
        self.halt()
        # B662 - CPSIE I - Enable IRQ by clearing PRIMASK
        # E7FE - B - Jump to address (argument is an offset)
        self.write32(0x08000000, 0xE7FEB662)
        self.write_reg('pc', 0x08000000)
        self.write_reg('sp', 0x08001000)
        self.write_reg('xpsr', 0x01000000)
        self.resume()

    def set_frequency(self, value_khz):
        """
        Sets probe frequency.
        :param value_khz: Frequency in kHz.
        """
        if self.probe is None:
            raise ValueError('Debug probe is not initialized.')
        self.probe.set_clock(value_khz * 1000)

    def halt(self):
        """
        Halts the target.
        """
        if self.session is None:
            raise ValueError('Debug session is not initialized.')
        logger.debug('halt')
        self.target.halt()

    def resume(self):
        """
        Resumes the execution
        """
        if self.target is None:
            raise ValueError('Target is not initialized.')
        logger.debug('resume')
        self.target.resume()

    def reset(self, reset_type=ResetType.SW):
        """
        Resets the target.
        :param reset_type: The reset type.
        """
        if self.target is None:
            raise ValueError('Target is not initialized.')
        logger.debug(f'reset ({reset_type})')
        self.target.reset(reset_type=reset_type)

    def reset_and_halt(self, reset_type=ResetType.SW):
        """
        Resets the target and halts the CPU immediately after reset.
        :param reset_type: The reset type.
        """
        if self.target is None:
            raise ValueError('Target is not initialized.')
        logger.debug(f'reset_and_halt ({reset_type})')
        self.target.reset_and_halt(reset_type=reset_type)

    def read8(self, address):
        """
        Reads 8-bit value from specified memory location.
        :param address: The memory address to read.
        :return: The read value.
        """
        if self.target is None:
            raise ValueError('Target is not initialized.')
        data = self.target.read_memory(address, transfer_size=8)
        logger.debug(f'read8 ({hex(address)}): {hex(data)}')
        return data

    def read16(self, address):
        """
        Reads 16-bit value from specified memory location.
        :param address: The memory address to read.
        :return: The read value.
        """
        if self.target is None:
            raise ValueError('Target is not initialized.')
        if (address & 0x01) == 0:
            data = self.target.read_memory(address, transfer_size=16)
            logger.debug(f'read16 ({hex(address)}): {hex(data)}')
            return data
        else:
            raise ValueError('Address not aligned.')

    def read32(self, address):
        """
        Reads 32-bit value from specified memory location.
        :param address: The memory address to read.
        :return: The read value.
        """
        if self.target is None:
            raise ValueError('Target is not initialized.')
        if (address & 0x03) == 0:
            data = self.target.read_memory(address, transfer_size=32)
            logger.debug(f'read32 ({hex(address)}): {hex(data)}')
            return data
        else:
            raise ValueError('Address not aligned.')

    def write8(self, address, value):
        """
        Writes 8-bit value by specified memory location.
        :param address: The memory address to write.
        :param value: The 8-bit value to write.
        """
        if self.target is None:
            raise ValueError('Target is not initialized.')
        logger.debug(f'write8 ({hex(address)}): {hex(value)}')
        data = self.target.write_memory(address, value, transfer_size=8)
        return data

    def write16(self, address, value):
        """
        Writes 16-bit value by specified memory location.
        :param address: The memory address to write.
        :param value: The 16-bit value to write.
        """
        if self.target is None:
            raise ValueError('Target is not initialized.')
        logger.debug(f'write16 ({hex(address)}): {hex(value)}')
        data = self.target.write_memory(address, value, transfer_size=16)
        return data

    def write32(self, address, value):
        """
        Writes 32-bit value by specified memory location.
        :param address: The memory address to write.
        :param value: The 32-bit value to write.
        """
        if self.target is None:
            raise ValueError('Target is not initialized.')
        logger.debug(f'write32 ({hex(address)}): {hex(value)}')
        data = self.target.write_memory(address, value, transfer_size=32)
        return data

    def read_reg(self, reg_name):
        """
        Gets value of a core register.
        :param reg_name: Core register name.
        :return: The register value.
        """
        reg = reg_name.lower()
        if reg in coresight.cortex_m.CORE_REGISTER:
            value = self.target.read_core_register(reg)
            logger.debug(f'read_reg ({reg_name}): {hex(value)}')
            return value
        else:
            raise ValueError(f'Unknown core register {reg}.')

    def write_reg(self, reg_name, value):
        """
        Sets value of a core register.
        :param reg_name: Core register name.
        :param value: The value to set.
        :return: The register value.
        """
        reg = reg_name.lower()
        if reg in coresight.cortex_m.CORE_REGISTER:
            logger.debug(f'write_reg ({reg_name}): {hex(value)}')
            self.target.write_core_register(reg, value)
        else:
            raise ValueError(f'Unknown core register {reg}.')

    def erase(self, address, size):
        """
        Erases entire device flash or specified sectors.
        :param address: The memory location.
        :param size: The memory size.
        """
        region = self.session.target.memory_map.get_region_for_address(address)
        if not region:
            raise ValueError('Address 0x%08x is not within a memory region.' % address)
        if not region.is_flash:
            raise ValueError('Address 0x%08x is not in flash.' % address)
        eraser = FlashEraser(self.session, FlashEraser.Mode.SECTOR)
        address_range = f"{hex(address)}-{hex(address + size)}"
        logger.debug(f'erase {address_range}')
        eraser.erase([address_range])

    def program(self, filename, file_format=None, address=None):
        """
        Programs a file into flash.
        :param filename: Path to a file.
        :param file_format: File format. Default is to use the file's
               extension.
        :param address: Base address used for the address where to
               flash a binary.
        :return: True if programmed successfully, otherwise False.
        """
        if self.session is None:
            raise ValueError('Debug session is not initialized.')
        programmer = FileProgrammer(self.session, chip_erase='sector')
        logger.debug(f'program {filename}')
        programmer.program(filename, base_address=address,
                           file_format=file_format)

    def read(self, address, length):
        """
        Reads specified number of bytes from memory
        :param address: The memory address where start reading
        :param length: Number of bytes to read
        :return: Values array
        """
        if self.target is None:
            raise ValueError('Target is not initialized.')
        data = self.target.read_memory_block8(address, length)
        logger.debug(f'Read block (address={hex(address)}, length={length}: '
                     f'{data}')
        return data

    @staticmethod
    def get_probe_list():
        """
        Gets list of all connected probes
        """
        return ConnectHelper.get_all_connected_probes(blocking=False)

    def set_skip_reset_and_halt(self, value):
        """
        Sets skip_reset_and_halt property value
        :param value: Indicates whether to skip or not
        """
        for i in range(len(self.target.cores)):
            logger.debug(f'core #{i}, skip_reset_and_halt = {value}')
            self.target.cores[i].skip_reset_and_halt = value

    def _set_acquire_timeout(self, timeout):
        """
        Sets acquire_timeout property value
        :param timeout: Timeout in seconds
        """
        for i in range(len(self.target.cores)):
            self.target.cores[i].acquire_timeout = timeout
