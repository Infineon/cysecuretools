"""
Copyright 2019-2022 Cypress Semiconductor Corporation (an Infineon company)
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
import os
import json
import logging
from time import sleep
from cysecuretools.execute.programmer.base import ProgrammerBase, ResetType, AP
from pyocd.core.target import Target
from pyocd.core.helpers import ConnectHelper
from pyocd.flash.file_programmer import FileProgrammer
from pyocd.flash.eraser import FlashEraser
from pyocd.core.exceptions import TransferError

TARGET_MAP = os.path.join(os.path.dirname(__file__), 'pyocd_target_map.json')
logger = logging.getLogger(__name__)


class Pyocd(ProgrammerBase):
    def __init__(self, name, path=None):
        super(Pyocd, self).__init__(name, path, require_path=False)
        self.session = None
        self.board = None
        self.target = None
        self.probe = None
        self.ap = None
        self._wait_for_target = None
        self.probe_id = None

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
                ap='cm4', acquire=None, blocking=True, reset_and_halt=False,
                power=None, voltage=None):
        """
        Connects to target using default debug interface.
        :param target_name: The target name.
        :param interface: Debug interface.
        :param ap: The access port used for communication (cm0 or cm4).
        :param probe_id: Probe serial number.
        :param acquire: Indicates whether to acquire device on connect
        :param blocking: Specifies whether to wait for a probe to be
               connected if there are no available probes.
        :param reset_and_halt: Indicates whether to do reset and halt
               after connect
        :param power: N/A for PyOCD
        :param voltage: N/A for PyOCD
        :return: True if connected successfully, otherwise False.
        """
        if interface:
            raise NotImplementedError
        else:
            if target_name:
                logger.info('Target: %s', target_name)
                # Search for device in target map
                with open(TARGET_MAP, encoding='utf-8') as f:
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
            self.probe_id = self.probe.unique_id

            if reset_and_halt:
                self.reset_and_halt(reset_type=ResetType.HW)

            self.ap = ap
            self.set_ap(AP.SYS)
            logger.info('Probe ID: %s', self.probe.unique_id)
            return True

    def disconnect(self):
        """ Closes the active connection. """
        
        def close_session():
            """
            Close the session.
            Uninits the board and disconnects then closes the probe.
            """
            # pylint: disable=protected-access
            if self.session._closed:
                return

            logger.debug('uninit session %s', self)
            if self.session._inited:
                uninit_board()
                self.session._inited = False

            if self.probe.is_open:
                self.probe.disconnect()
                self.probe.close()

            self.session._closed = True

        def uninit_board():
            """ Uninitialize the board."""
            # pylint: disable=protected-access
            if self.board._inited:
                logger.debug('uninit board %s', self)
                self.board.target.disconnect(False)
                self.board._inited = False

        logger.debug('disconnect::enter')
        if self.session is None:
            raise ValueError('Debug session is not initialized.')

        self.resume()
        # Avoid race condition when the bootloader does flash
        # operations at the moment the tool tries to disconnect
        counter = 0
        timeout = 10
        while True:
            try:
                logger.debug('disconnect attempt #%d', counter)
                close_session()
                break
            except TransferError as e:
                if counter < timeout:
                    sleep(1)
                    counter += 1
                else:
                    raise e
        logger.debug('disconnect::exit')

    def get_ap(self):
        """
        Gets access port.
        :return: Selected AP.
        """
        if self.target.selected_core == self.target.cores[0]:
            ap = AP.SYS
        elif self.target.selected_core == self.target.cores[1]:
            ap = AP.CMx
        logger.debug('AP: %s', ap)
        return ap

    def set_ap(self, ap):
        """
        Sets access port.
        :param ap: The AP name.
        """
        if ap == AP.SYS:
            logger.debug('Use system AP')
            if self.get_ap() != AP.SYS:
                self._start_core()
            self.target.selected_core = 0
        elif ap == AP.CM0:
            logger.debug('Use cm0 AP')
            self.target.selected_core = 1
            self._start_core()
        elif ap == AP.CM4:
            logger.debug('Use cm4 AP')
            self.target.selected_core = 1
            self._start_core()
        elif ap == AP.CMx:
            logger.debug('Use %s AP', self.ap)
            self.target.selected_core = 1
            self._start_core()
        else:
            raise ValueError('Invalid access port.')

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
        logger.debug('reset (%s)', reset_type)
        self.target.reset(reset_type=self._pyocd_reset_type(reset_type))

    def reset_and_halt(self, reset_type=ResetType.SW):
        """
        Resets the target and halts the CPU immediately after reset.
        :param reset_type: The reset type.
        """
        if self.target is None:
            raise ValueError('Target is not initialized.')
        logger.debug('reset_and_halt (%s)', reset_type)
        self.target.reset_and_halt(reset_type=self._pyocd_reset_type(
            reset_type))

    def read8(self, address):
        """
        Reads 8-bit value from specified memory location.
        :param address: The memory address to read.
        :return: The read value.
        """
        if self.target is None:
            raise ValueError('Target is not initialized.')
        data = self.target.read_memory(address, transfer_size=8)
        logger.debug('read8 (0x%x): 0x%x', address, data)
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
            logger.debug('read16 (0x%x): 0x%x', address, data)
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
            logger.debug('read32 (0x%x): 0x%x', address, data)
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
        logger.debug('write8 (0x%x): 0x%x', address, value)
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
        logger.debug('write16 (0x%x): 0x%x', address, value)
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
        logger.debug('write32 (0x%x): 0x%x', address, value)
        data = self.target.write_memory(address, value, transfer_size=32)
        return data

    def read_reg(self, reg_name):
        """
        Gets value of a core register.
        :param reg_name: Core register name.
        :return: The register value.
        """
        reg = reg_name.lower()
        value = self.target.read_core_register(reg)
        logger.debug('read_reg (%s): 0x%x', reg_name, value)
        return value

    def write_reg(self, reg_name, value):
        """
        Sets value of a core register.
        :param reg_name: Core register name.
        :param value: The value to set.
        :return: The register value.
        """
        reg = reg_name.lower()
        logger.debug('write_reg (%s): 0x%x', reg_name, value)
        self.target.write_core_register(reg, value)

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
        logger.debug('erase %s', address_range)
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
        logger.debug('program %s', filename)
        programmer.program(filename, base_address=address,
                           file_format=file_format)

    def read(self, address, length):
        """
        Reads a block of unaligned bytes in memory
        :param address: The memory address where start reading
        :param length: Number of bytes to read
        :return: An array of byte values
        """
        if self.target is None:
            raise ValueError('Target is not initialized.')
        data = self.target.read_memory_block8(address, length)
        logger.debug('Read block (address=0x%x, length=%s): %s',
                     address, length, data)
        return data

    def write(self, address, data):
        """
        Writes a block of unaligned bytes in memory
        :param address: The memory address where start writing
        :param data: An array of byte values
        """
        if self.target is None:
            raise ValueError('Target is not initialized.')
        self.target.write_memory_block8(address, data)
        logger.debug('Write block (address=0x%x): %s', address, data)

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
            logger.debug('core #%d, skip_reset_and_halt = %s', i, value)
            self.target.cores[i].skip_reset_and_halt = value

    def examine_ap(self):
        """
        N/A for pyOCD
        """

    def _set_acquire_timeout(self, timeout):
        """
        Sets acquire_timeout property value
        :param timeout: Timeout in seconds
        """
        for i in range(len(self.target.cores)):
            self.target.cores[i].acquire_timeout = timeout

    @staticmethod
    def _pyocd_reset_type(reset_type: ResetType):
        """ Maps internal ResetType value to the pyocd ResetType value """
        if reset_type == ResetType.HW:
            pyocd_reset_type = Target.ResetType.HW
        elif reset_type == ResetType.SW:
            pyocd_reset_type = Target.ResetType.SW
        else:
            raise ValueError(f'Unknown reset type {reset_type}')
        return pyocd_reset_type

    def get_voltage(self):
        """ Reads target voltage """
        raise NotImplementedError
