"""
Copyright (c) 2019 Cypress Semiconductor Corporation

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
from cysecuretools.execute.programmer.base import ProgrammerBase, ResetType
from pyocd.core.helpers import ConnectHelper
from pyocd.core import exceptions
from pyocd.flash import loader
from pyocd.flash.loader import FlashEraser
from pyocd import coresight
from cysecuretools.execute.programmer.exceptions import ExtendedTransferFaultError

TARGET_MAP = os.path.join(os.path.dirname(__file__), 'pyocd_target_map.json')


class Pyocd(ProgrammerBase):
    def __init__(self):
        super(Pyocd, self).__init__()
        self.session = None
        self.board = None
        self.target = None
        self.probe = None

    def connect(self, target_name=None, interface=None, probe_id=None):
        """
        Connects to target using default debug interface.
        :param target_name: The target name.
        :param interface: Debug interface.
        :param probe_id: Probe serial number.
        :return: True if connected successfully, otherwise False.
        """
        if interface:
            raise NotImplementedError
        else:
            if target_name:
                # Search for device in target map
                with open(TARGET_MAP) as f:
                    file_content = f.read()
                    json_data = json.loads(file_content)
                for json_target in json_data:
                    if target_name.lower().strip() == json_target.lower().strip():
                        target_name = json_data[json_target]
                        break
                options = {
                    'target_override': target_name
                }
            else:
                options = {}
            self.session = ConnectHelper.session_with_chosen_probe(blocking=True, options=options, board_id=probe_id,
                                                                   unique_id=probe_id)
            if self.session is None:
                return False
            self.board = self.session.board
            self.session.open()

            self.target = self.board.target
            self.probe = self.session.probe

            # Write infinite loop into RAM and start core execution
            self.halt()
            # B662 - CPSIE I - Enable IRQ by clearing PRIMASK
            # E7FE - B - Jump to address (argument is an offset)
            self.write32(0x08000000, 0xE7FEB662)
            self.write_reg('pc', 0x08000000)
            self.write_reg('sp', 0x08001000)
            self.write_reg('xpsr', 0x01000000)
            self.resume()

            return True

    def disconnect(self):
        """
        Closes active connection.
        """
        if self.session is None:
            raise ValueError('Debug session is not initialized.')
        self.session.close()

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
        self.target.halt()

    def resume(self):
        """
        Resumes the execution
        """
        if self.target is None:
            raise ValueError('Target is not initialized.')
        self.target.resume()

    def reset(self, reset_type=ResetType.SW):
        """
        Resets the target.
        :param reset_type: The reset type.
        """
        if self.target is None:
            raise ValueError('Target is not initialized.')
        self.target.reset(reset_type=reset_type)

    def reset_and_halt(self, reset_type=ResetType.SW):
        """
        Resets the target and halts the CPU immediately after reset.
        :param reset_type: The reset type.
        """
        if self.target is None:
            raise ValueError('Target is not initialized.')
        self.target.reset_and_halt(reset_type=reset_type)

    def read8(self, address):
        """
        Reads 8-bit value from specified memory location.
        :param address: The memory address to read.
        :return: The read value.
        """
        if self.target is None:
            raise ValueError('Target is not initialized.')
        try:
            data = self.target.read_memory(address, transfer_size=8)
        except exceptions.TransferFaultError as e:
            raise ExtendedTransferFaultError(e.fault_address, e.fault_length)
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
            try:
                data = self.target.read_memory(address, transfer_size=16)
            except exceptions.TransferFaultError as e:
                raise ExtendedTransferFaultError(e.fault_address, e.fault_length)
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
            try:
                data = self.target.read_memory(address, transfer_size=32)
            except exceptions.TransferFaultError as e:
                raise ExtendedTransferFaultError(e.fault_address, e.fault_length)
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
        try:
            data = self.target.write_memory(address, value, transfer_size=8)
        except exceptions.TransferFaultError as e:
            raise ExtendedTransferFaultError(e.fault_address, e.fault_length)
        return data

    def write16(self, address, value):
        """
        Writes 16-bit value by specified memory location.
        :param address: The memory address to write.
        :param value: The 16-bit value to write.
        """
        if self.target is None:
            raise ValueError('Target is not initialized.')
        try:
            data = self.target.write_memory(address, value, transfer_size=16)
        except exceptions.TransferFaultError as e:
            raise ExtendedTransferFaultError(e.fault_address, e.fault_length)
        return data

    def write32(self, address, value):
        """
        Writes 32-bit value by specified memory location.
        :param address: The memory address to write.
        :param value: The 32-bit value to write.
        """
        if self.target is None:
            raise ValueError('Target is not initialized.')
        try:
            data = self.target.write_memory(address, value, transfer_size=32)
        except exceptions.TransferFaultError as e:
            raise ExtendedTransferFaultError(e.fault_address, e.fault_length)
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
        eraser.erase([address_range])

    def program(self, filename, file_format=None, address=None):
        """
        Programs a file into flash.
        :param filename: Path to a file.
        :param file_format: File format. Default is to use the file's extension.
        :param address: Base address used for the address where to flash a binary.
        :return: True if programmed successfully, otherwise False.
        """
        if self.session is None:
            raise ValueError('Debug session is not initialized.')
        programmer = loader.FileProgrammer(self.session, chip_erase='sector')
        programmer.program(filename, base_address=address, file_format=file_format)
