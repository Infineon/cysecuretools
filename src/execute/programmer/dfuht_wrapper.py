"""
Copyright 2023 Cypress Semiconductor Corporation (an Infineon company)
or an affiliate of Cypress Semiconductor Corporation. All rights reserved.

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
import os
import tempfile
from collections import namedtuple

from .base import ProgrammerBase
from .dfuht_runner import DfuhtRunner
from ..dfuht_commands.dfuht_packet_creator import DfuhtCommandsCreator

logger = logging.getLogger(__name__)


class Dfuht(ProgrammerBase):
    """Wrapper around the DFU Host Tool which implements a single
    interface for OCDs
    """

    def __init__(self, name, settings):
        path = settings.ocd_path if settings else None
        super().__init__(name, path=path)
        self.runner = DfuhtRunner(settings) if settings else None
        self.probe_id = self.runner.serial_port if self.runner else None

    def connect(self, target_name=None, interface=None, probe_id=None, ap=None,
                acquire=True, power=None, voltage=None, ignore_errors=False):
        """Checks whether the specified target is connected"""
        if not probe_id:
            probe_id = self.runner.serial_port
        for probe in self.get_probe_list():
            if probe_id in probe:
                logger.info("Target connected %s", probe)
                return True

        raise ValueError(f"Unknown probe ID '{probe_id}'")

    def disconnect(self):
        """N/A for DFU Host Tool"""

    def get_ap(self):
        """N/A for DFU Host Tool"""
        raise NotImplementedError

    def set_ap(self, _):
        """N/A for DFU Host Tool"""
        raise NotImplementedError

    def set_frequency(self, _):
        """N/A for DFU Host Tool"""
        raise NotImplementedError

    def halt(self):
        """N/A for DFU Host Tool"""
        raise NotImplementedError

    def resume(self):
        """N/A for DFU Host Tool"""
        raise NotImplementedError

    def reset(self, *_):
        """N/A for DFU Host Tool"""
        raise NotImplementedError

    def reset_and_halt(self, *_):
        """N/A for DFU Host Tool"""
        raise NotImplementedError

    def read8(self, address):
        """Reads 8-bit value from specified memory location
        @param address: The memory address to read
        @return: The read value or error message
        """
        return self._read_cmd(address, 1)

    def read16(self, address):
        """Reads 16-bit value from specified memory location
        @param address: The memory address to read
        @return: The read value or error message
        """
        return self._read_cmd(address, 2)

    def read32(self, address):
        """Reads 32-bit value from specified memory location
        @param address: The memory address to read
        @return: The read value or error message
        """
        return self._read_cmd(address, 4)

    def write8(self, *_):
        """N/A for DFU Host Tool"""
        raise NotImplementedError

    def write16(self, *_):
        """N/A for DFU Host Tool"""
        raise NotImplementedError

    def write32(self, *_):
        """N/A for DFU Host Tool"""
        raise NotImplementedError

    def write(self, address, data):
        raise NotImplementedError

    def read_reg(self, _):
        """N/A for DFU Host Tool"""
        raise NotImplementedError

    def write_reg(self, *_):
        """N/A for DFU Host Tool"""
        raise NotImplementedError

    def erase(self, address, size):
        raise NotImplementedError

    def program(self, filename, file_format=None, address=None, **kwargs):
        """Programs a file into flash
        @param filename: Path to image '.hex' file or custom command '.mtbdfu'
        @param file_format: File format.
        @param address: A tuple (start_addr, end_addr)
        @return: Returns response data: stdout, stderr
        """
        cmd = ['--custom-command', filename]
        if address:
            cmd = ['--program-device', filename]
            cmd.extend(self._image_info(address, kwargs.get('image_id')))
        stdout, _ = self.runner.run(cmd)
        return self._result_check(stdout)

    def read(self, address, length):
        """Reads a block of unaligned bytes in memory
        @param address: The memory address where start reading
        @param length: Number of bytes to read
        @return: An array of byte values
        """
        return self._read_cmd(address, length, array=True)

    def get_probe_list(self):
        """Gets compatible connected hardware"""
        stdout, stderr = self.runner.run(
            ['--display-hw'], add_protocol_args=False, print_output=False)
        if not stdout:
            for line in stderr:
                logger.error(line)
        return stdout

    def get_voltage(self):
        """N/A for DFU Host Tool"""
        raise NotImplementedError

    def dump_image(self, filename, addr, size):
        """Dumps memory region to the file
        @param filename: Filename where to save the dump
        @param addr: Region address
        @param size: Region size
        @return: True if programmed successfully, otherwise False
        """
        dump_value = self._read_cmd(addr, size, array=True)
        dir_name = os.path.dirname(filename)
        if dir_name:
            os.makedirs(dir_name, exist_ok=True)
        with open(filename, 'wb') as f:
            f.write(dump_value)
        logger.debug("Load data to file '%s'", os.path.abspath(filename))
        return dump_value

    def verify(self, filename, address, **kwargs):
        """Image verification in the device memory
        @param filename: Path to image '.hex' file or custom command '.mtbdfu'
        @param address: A tuple (start_addr, end_addr)
        @return: Returns response data: stdout, stderr
        """
        cmd = ['--verify-device', filename]
        cmd.extend(self._image_info(address, kwargs.get('image_id')))
        stdout, _ = self.runner.run(cmd)
        return self._result_check(stdout)

    def _read_cmd(self, addr, length, array=False):
        """Creates custom command and reads data via DFU Host Tool
        @addr: Start address to read data
        @length: Number of bytes to read
        @array: Method returns bytes array if True, otherwise integer value
        @return: Returns integer value or bytes based on array parameter value
        """
        value = b''
        with tempfile.TemporaryDirectory() as dfu_command_dir:
            for read in self._read_cmd_series(addr, length):
                cmd_name = os.path.join(
                    dfu_command_dir, hex(read.addr) + '.mtbdfu')
                dfu_command = DfuhtCommandsCreator(None, None, cmd_name)
                cmd = dfu_command.read_cmd_packet(
                    read.addr, read.size, cmd_name)
                stdout, _ = self.runner.run(['--custom-command', cmd.filename])
                if self._result_check(stdout):
                    value += bytes.fromhex(stdout[1])
                else:
                    raise RuntimeError(
                        f'Failed to read data (address {hex(read.addr)},'
                        f'length {read.size})')
        if not array:
            int_value = int.from_bytes(value, byteorder="little")
            return int_value
        return value

    @staticmethod
    def _image_info(address, image_id):
        """Image info data to program-device command"""
        cmd = ['--application-start', hex(address[0]),
               '--application-length', hex(address[1])]
        if image_id:
            cmd.extend(['--application-id', hex(image_id)])
        return cmd

    @staticmethod
    def _result_check(stdout):
        """Check for operation success status message"""
        return bool('Operation succeeded.' in stdout)

    @staticmethod
    def _read_cmd_series(addr, length):
        """Creates a collection of DFU custom commands if
        the amount of data exceeds 256 bytes
        """
        CmdInfo = namedtuple('CmdInfo', 'addr size')
        commands = []
        max_size = 256
        read_address = addr
        while length > max_size:
            commands.append(CmdInfo(read_address, max_size))
            read_address += max_size
            length -= max_size
        commands.append(CmdInfo(read_address, length))
        return commands
