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
from enum import Enum
from abc import ABCMeta, abstractmethod


class ResetType(Enum):
    SW = 1
    HW = 2


class Interface(Enum):
    SWD = 1
    JTAG = 2


class AP(Enum):
    SYS = 'sys'
    CM0 = 'cm0'
    CM4 = 'cm4'
    CMx = 'cmx'
    CM33 = 'cm33'


class ProgrammerBase(metaclass=ABCMeta):
    def __init__(self, name, path, require_path=True):
        self.name = name
        self.tool_path = path
        self.require_path = require_path

    def _start_core(self):
        """
        Writes infinite loop into RAM and starts core execution.
        CM0 will not be able to execute sys calls in case it is in
        undefined state.
        """
        start_core_program_address = 0x08000000
        program_counter_address = 0x08000000
        stack_pointer_address = 0x08001000
        thumb_bit_address = 0x01000000
        infinite_loop_code = 0xE7FEB662
        self.halt()
        # B662 - CPSIE I - Enable IRQ by clearing PRIMASK
        # E7FE - B - Jump to address (argument is an offset)
        self.write32(start_core_program_address, infinite_loop_code)
        self.write_reg('pc', program_counter_address)
        self.write_reg('sp', stack_pointer_address)
        self.write_reg('xpsr', thumb_bit_address)
        self.resume()

    @property
    def wait_for_target(self):
        """
        Gets a value indicating whether to wait for the target
        if no available devices are connected
        """
        raise NotImplementedError

    @wait_for_target.setter
    def wait_for_target(self, value):
        """
        Sets a value indicating whether to wait for the target
        if no available devices are connected
        """
        raise NotImplementedError

    @abstractmethod
    def connect(self, target_name=None, interface=None, probe_id=None,
                ap=None, acquire=True, blocking=True, reset_and_halt=False,
                power=None, voltage=None):
        """
        Connects to target.
        :param target_name: The target name.
        :param interface: Debug interface.
        :param probe_id: Probe serial number.
        :param ap: The access port used for communication.
        :param acquire: Indicates whether to acquire device on connect
        :param blocking: Specifies whether to wait for a probe to be
               connected if there are no available probes
        :param reset_and_halt: Indicates whether to do reset and halt
               after connect
        :param power: Target power
        :param voltage: Target power voltage
        :return: True if connected successfully, otherwise False.
        """
        raise NotImplementedError()

    @abstractmethod
    def disconnect(self):
        """
        Disconnects from target.
        """
        raise NotImplementedError()

    @abstractmethod
    def get_ap(self):
        """
        Gets access port.
        :return: Selected AP.
        """
        raise NotImplementedError()

    @abstractmethod
    def set_ap(self, ap):
        """
        Sets access port.
        """
        raise NotImplementedError()

    @abstractmethod
    def set_frequency(self, value_khz):
        """
        Sets probe frequency.
        :param value_khz: Frequency in kHz.
        """
        raise NotImplementedError()

    @abstractmethod
    def halt(self):
        """
        Halts the target.
        """
        raise NotImplementedError()

    @abstractmethod
    def resume(self):
        """
        Resumes the execution
        """
        raise NotImplementedError()

    @abstractmethod
    def reset(self, reset_type=ResetType.SW):
        """
        Resets the target.
        :param reset_type: The reset type.
        """
        raise NotImplementedError()

    @abstractmethod
    def reset_and_halt(self, reset_type=ResetType.SW):
        """
        Resets the target and halts the CPU immediately after reset.
        :param reset_type: The reset type.
        """
        raise NotImplementedError()

    @abstractmethod
    def read8(self, address):
        """
        Reads 8-bit value from specified memory location.
        :param address: The memory address to read.
        :return: The read value.
        """
        raise NotImplementedError()

    @abstractmethod
    def read16(self, address):
        """
        Reads 16-bit value from specified memory location.
        :param address: The memory address to read.
        :return: The read value.
        """
        raise NotImplementedError()

    @abstractmethod
    def read32(self, address):
        """
        Reads 32-bit value from specified memory location.
        :param address: The memory address to read.
        :return: The read value.
        """
        raise NotImplementedError()

    @abstractmethod
    def write8(self, address, value):
        """
        Writes 8-bit value by specified memory location.
        :param address: The memory address to write.
        :param value: The 8-bit value to write.
        """
        raise NotImplementedError()

    @abstractmethod
    def write16(self, address, value):
        """
        Writes 16-bit value by specified memory location.
        :param address: The memory address to write.
        :param value: The 16-bit value to write.
        """
        raise NotImplementedError()

    @abstractmethod
    def write32(self, address, value):
        """
        Writes 32-bit value by specified memory location.
        :param address: The memory address to write.
        :param value: The 32-bit value to write.
        """
        raise NotImplementedError()

    @abstractmethod
    def read_reg(self, reg_name):
        """
        Gets value of a core register.
        :param reg_name: Core register name.
        :return: The register value.
        """
        raise NotImplementedError()

    @abstractmethod
    def write_reg(self, reg_name, value):
        """
        Sets value of a core register.
        :param reg_name: Core register name.
        :param value: The value to set.
        """
        raise NotImplementedError()

    @abstractmethod
    def erase(self, address, size):
        """
        Erases entire device flash or specified sectors.
        :param address: The memory location.
        :param size: The memory size.
        """
        raise NotImplementedError()

    @abstractmethod
    def program(self, filename, file_format=None, address=None):
        """
        Programs a file into flash.
        :param filename: Path to a file.
        :param file_format: File format. Default is to use the file's extension.
        :param address: Base address used for the address where to flash a binary.
        :return: True if programmed successfully, otherwise False.
        """
        raise NotImplementedError()

    @abstractmethod
    def read(self, address, length):
        """
        Reads a block of unaligned bytes in memory
        :param address: The memory address where start reading
        :param length: Number of bytes to read
        :return: Values array
        """
        raise NotImplementedError()

    @abstractmethod
    def write(self, address, data):
        """
        Writes a block of unaligned bytes in memory
        :param address: The memory address where start writing
        :param data: Data block
        """
        raise NotImplementedError()

    @abstractmethod
    def get_probe_list(self):
        """
        Gets list of connected probes
        """
        raise NotImplementedError()

    def set_skip_reset_and_halt(self, value):
        """
        Sets skip_reset_and_halt property value. This is applicable
        for pyOCD and likely should not be implemented for other tools
        :param value: Indicates whether to skip or not
        """

    def examine_ap(self):
        """
        Examines CMx (depending on selected ap for connection) AP
        without reset. This is applicable for OpenOCD and likely should
        not be implemented for other tools
        """

    @abstractmethod
    def get_voltage(self):
        """Reads target voltage
        :@return Voltage value in Volts
        """
