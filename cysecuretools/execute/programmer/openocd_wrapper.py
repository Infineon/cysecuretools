"""
Copyright 2022 Cypress Semiconductor Corporation (an Infineon company)
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
import re
import sys
import json
import socket
import signal
import logging
from cysecuretools.execute.programmer.base import ProgrammerBase, ResetType, AP
from cysecuretools.core.target_director import TargetDirector
from cysecuretools.execute.programmer.openocd_server import OpenocdServer

TARGET_MAP = os.path.join(os.path.dirname(__file__), 'openocd_target_map.json')
logger = logging.getLogger(__name__)


class Openocd(ProgrammerBase):
    """
    OpenOCD wrapper for client side
    """

    _CMD_SUCCESS = 0
    _CMD_FAIL = -1

    def __init__(self, name, path=None):
        super(Openocd, self).__init__(name, path)
        self.sock = None
        self.target = None
        self.ocd_server = None
        self.verbose = False
        self.tcp_host_address = '127.0.0.1'
        self.tcp_host_port = 6666
        self.sock_buffer_size = 4096
        self._command_token = '\x1a'
        self.probe_id = None

        # Older versions of OpenOCD when connected to server via TCL port
        # require 'ocd_' prefix to get command output
        self.ocd_cmd_prefix = ''

        # Patterns to check an error message
        self._error_msg_patterns = [
            'Failed to',
            'Error',
            'error writing',
            'invalid command name',
        ]
        self.current_ap = AP.SYS  # currently selected by user access port
        self.connect_ap = AP.SYS  # access port selected before init
        self.mcu = None

    @property
    def wait_for_target(self):
        """
        N/A for OpenOCD
        """

    @wait_for_target.setter
    def wait_for_target(self, value):
        """
        N/A for OpenOCD
        """

    def connect(self, target_name=None,
                interface=None, probe_id=None, ap='cm4', acquire=None,
                blocking=None, reset_and_halt=False,
                power=None, voltage=None):
        """
        Connects to target using default debug interface.
        :param power: Indicates whether to on/off the KitProg3 power
        :param voltage: The KitProg3 voltage level
        :param target_name: The target name.
        :param interface: Debug interface.
        :param probe_id: Probe serial number.
        :param ap: The access port to be used for flash operations
        :param acquire: Indicates whether to acquire device on connect
        :param blocking: Specifies whether to wait for a probe to be
               connected if there are no available probes.
        :param reset_and_halt: Indicates whether to do reset and halt
               after connect
        :return: True if connected successfully, otherwise False.
        """
        if interface:
            raise NotImplementedError

        if target_name:
            ocd_target_name = ''
            # Search for device in target map
            with open(TARGET_MAP, encoding='utf-8') as f:
                file_content = f.read()
                json_data = json.loads(file_content)
            for json_target in json_data:
                if target_name.lower().strip() == json_target.lower().strip():
                    # Get target info
                    director = TargetDirector()
                    try:
                        from cysecuretools.targets import target_map
                        director.builder = target_map[target_name]['class']()
                    except KeyError as e:
                        raise ValueError(
                            f'Unknown target "{target_name}"') from e
                    self.target = director.get_target(None, target_name, None)
                    # Get target name which is relevant to OpenOCD
                    ocd_target_name = json_data[json_target]['target']
                    self.mcu = json_data[json_target]['mcu']
                    break
        else:
            raise ValueError("Parameter 'target_name' is None")

        if ap == 'cm4':
            self.connect_ap = AP.CM4
        elif ap == 'cm0':
            self.connect_ap = AP.CM0
        elif ap == 'sysap':
            self.connect_ap = AP.SYS
        elif ap == 'cm33':
            self.connect_ap = AP.CM33
        else:
            if not power:
                raise ValueError(f'Invalid access port value \'{ap}\'')

        # Register the signal handlers
        # When TERMINATE or INT signal from the system will be received,
        # the OCD server will be stopped
        signal.signal(signal.SIGTERM, self._terminate_signal_received)
        signal.signal(signal.SIGINT, self._terminate_signal_received)

        # Configure OpenOCD server
        self.ocd_server = OpenocdServer(self.target, ocd_target_name,
                                        interface, probe_id,
                                        tool_path=self.tool_path,
                                        power=power, voltage=voltage)
        self.probe_id = self.ocd_server.probe_id
        # Start GDB server and check if it is started
        server_started = self.ocd_server.start(ap, acquire)
        # No need of further connection if the power command is sent
        if power:
            return server_started
        if server_started:
            # Connect to OpenOCD server
            if self.sock is None:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.connect((self.tcp_host_address, self.tcp_host_port))
            else:
                raise ValueError('Debug session has already initialized')
        else:
            return False
        self.set_ap(self.connect_ap)
        self.examine_ap()
        if reset_and_halt:
            self.reset_and_halt(reset_type=ResetType.HW)
        if self.current_ap in [AP.CM0, AP.CM4]:
            self._start_core()
            self.set_ap(AP.SYS)

        return True

    def disconnect(self):
        """
        Closes active connection.
        """
        self.halt()  # halted core before disconnecting from it
        if self.sock is None:
            raise ValueError('Debug session is not initialized')
        self.sock.close()
        self.sock = None
        self.ocd_server.stop()

    def set_frequency(self, value_khz):
        """
        Sets probe frequency.
        :param value_khz: Frequency in kHz.
        """
        if self.sock is None:
            raise ValueError('Debug probe is not initialized')
        self._send('adapter_khz {0}'.format(value_khz))

    def halt(self):
        """
        Halts the target.
        """
        if self.sock is None:
            raise ValueError('Debug session is not initialized')
        logger.debug('halt')
        self._send('halt')

    def resume(self):
        """
        Resumes the execution
        """
        if self.sock is None:
            raise ValueError('Target is not initialized')
        logger.debug('resume')
        self._send('resume')

    def reset(self, reset_type=ResetType.SW):
        """
        Resets the target.
        :param reset_type: The reset type.
        """
        if self.sock is None:
            raise ValueError('Target is not initialized')
        logger.debug('reset')
        self._send('reset run')

    def reset_and_halt(self, reset_type=ResetType.SW):
        """
        Resets the target and halts the CPU immediately after reset.
        :param reset_type: The reset type.
        """
        if self.sock is None:
            raise ValueError('Target is not initialized')
        logger.debug('reset_and_halt')
        self._send('reset init')

    def read8(self, address):
        """
        Reads 8-bit value from specified memory location.
        :param address: The memory address to read.
        :return: The read value.
        """
        if self.sock is None:
            raise ValueError('Target is not initialized')
        cmd_rsp = self._send('mdb 0x{0:x}'.format(address))
        value = self._parse_and_convert_read(cmd_rsp)
        logger.debug('read8 (0x%x): 0x%x', address, value)
        return value

    def read16(self, address):
        """
        Reads 16-bit value from specified memory location.
        :param address: The memory address to read.
        :return: The read value.
        """
        if self.sock is None:
            raise ValueError('Target is not initialized')
        if (address & 0x01) == 0:
            cmd_rsp = self._send('mdh 0x{0:x}'.format(address))
            value = self._parse_and_convert_read(cmd_rsp)
            logger.debug('read16 (0x%x): 0x%x', address, value)
            return value
        else:
            raise ValueError('Address not aligned')

    def read32(self, address):
        """
        Reads 32-bit value from specified memory location.
        :param address: The memory address to read.
        :return: The read value.
        """
        if self.sock is None:
            raise ValueError('Target is not initialized')
        if (address & 0x03) == 0:
            cmd_rsp = self._send('mdw 0x{0:x}'.format(address))
            value = self._parse_and_convert_read(cmd_rsp)
            logger.debug('read32 (0x%x): 0x%x', address, value)
            return value
        else:
            raise ValueError('Address not aligned')

    def write8(self, address, value):
        """
        Writes 8-bit value by specified memory location.
        :param address: The memory address to write.
        :param value: The 8-bit value to write.
        """
        if self.sock is None:
            raise ValueError('Target is not initialized.')
        logger.debug('write8 (0x%x): 0x%x', address, value)
        data = self._send('mwb 0x{0:x} 0x{1:x}'.format(address, value))
        return data

    def write16(self, address, value):
        """
        Writes 16-bit value by specified memory location.
        :param address: The memory address to write.
        :param value: The 16-bit value to write.
        """
        if self.sock is None:
            raise ValueError('Target is not initialized')
        logger.debug('write16 (0x%x): 0x%x', address, value)
        data = self._send('mwh 0x{0:x} 0x{1:x}'.format(address, value))
        return data

    def write32(self, address, value):
        """
        Writes 32-bit value by specified memory location.
        :param address: The memory address to write.
        :param value: The 32-bit value to write.
        """
        self._send('targets')
        if self.sock is None:
            raise ValueError('Target is not initialized')
        logger.debug('write32 (0x%x): 0x%x', address, value)
        data = self._send('mww 0x{0:x} 0x{1:x}'.format(address, value))
        return data

    def read_reg(self, reg_name):
        """
        Gets value of a core register.
        :param reg_name: Core register name.
        :return: The register value.
        """
        reg = reg_name.lower()
        value = self._send('reg {0}'.format(reg))
        logger.debug('read_reg (%s): 0x%x', reg, value)
        return value

    def write_reg(self, reg_name, value):
        """
        Sets value of a core register.
        :param reg_name: Core register name.
        :param value: The value to set.
        :return: The register value.
        """
        reg = reg_name.lower()
        logger.debug('write_reg (%s): 0x%x', reg, value)
        self._send('reg {0} {1:#x}'.format(reg, value))

    def erase(self, address, size):
        """
        Erases entire device flash or specified sectors.
        :param address: The memory location.
        :param size: The memory size.
        """
        if self.sock is None:
            raise ValueError('Debug session is not initialized')
        self.halt()
        logger.debug('erase 0x%x-0x%x', address, address + size)
        self._send('flash erase_address {0} {1}'.format(address, size))

    def program(self, filename, file_format=None, address=None):
        """
        Programs a file into flash.
        :param filename: Path to a file.
        :param file_format: N/A for OpenOCD.
        :param address: Base address used for the address where to
               flash a binary.
        :return: True if programmed successfully, otherwise False.
        """
        if self.sock is None:
            raise ValueError('Debug session is not initialized')
        # Remove Windows-style path separator
        filename = filename.replace(os.sep, '/')
        self.halt()
        if address:
            logger.debug("Programming '%s' to %s", filename, address)
            self._send(f'flash write_image erase "{filename}" {address}')
        else:
            logger.debug("Programming '%s'", filename)
            self._send(f'flash write_image erase "{filename}"')

    def program_ram(self, filename, file_format=None, address=None):
        """
        Programs a file into flash.
        :param filename: Path to a file.
        :param file_format: N/A for OpenOCD.
        :param address: Base address used for the address where to
               flash a binary.
        :return: True if programmed successfully, otherwise False.
        """
        if self.sock is None:
            raise ValueError('Debug session is not initialized')
        # Remove Windows-style path separator
        filename = filename.replace(os.sep, '/')
        self.halt()
        if address:
            logger.debug("Programming '%s' to %s", filename, address)
            self._send(f'load_image "{filename}" {address}')
        else:
            logger.debug("Programming '%s'", filename)
            self._send(f'load_image "{filename}"')

    def _parse_read(self, cmd_response):
        """
        Parse OpenOCD output from read memory commands
        :param cmd_response: String with response from server to the
               read command
        :return: The register as integer value
        """
        for err_msg in self._error_msg_patterns:
            if err_msg in cmd_response:
                logger.error("Unable to get data from the memory")
                return self._CMD_FAIL
        cmd_result = cmd_response.split(':')
        value = cmd_result[1].strip()
        return value

    def _parse_and_convert_read(self, cmd_response):
        """
        Parse OpenOCD output from read memory commands
        :param cmd_response: String with response from server to the
               read command
        :return: The register as integer value
        """
        value = self._parse_read(cmd_response)
        value = int(value, 16)
        return value

    def _send(self, cmd):
        """
        Send a command to TCL RPC.
        Note: This command also check command status and if it is not SUCCESS raise ValueError exception
        :param cmd: String with command for OpenOCD server.
        :return: String with response on sent command to the server.
        """
        if self.sock is None:
            raise ValueError('Debug session is not initialized')
            # Stop OpenOCD server if termination signal was received

        if self.verbose:
            logger.info('send -> %s', cmd)

        # Append ocd_ prefix to each command
        cmd = ''.join([self.ocd_cmd_prefix, cmd])
        logger.debug("Sending command '%s'", cmd)
        # 1. Send command and save status code and message
        send_cmd = 'set cmd_status [catch {{ {0} }} cmd_msg]'.format(cmd)
        cmd_status = self._send_cmd(send_cmd)
        # 2. Send set command to get message
        send_cmd = 'set cmd_response "$cmd_msg"'
        cmd_message = self._send_cmd(send_cmd)

        # Check if command status is OK (_CMD_SUCCESS)
        err_code = int(cmd_status, 16)
        if self._CMD_SUCCESS != err_code:
            raise RuntimeError("Command FAILED: {1}{0}{1}".format(cmd_message,
                                                                  os.linesep))
        cmd_message = cmd_message.rstrip()
        if cmd_message:
            logger.debug(cmd_message)
        return cmd_message

    def _send_cmd(self, cmd):
        """
        Send a command string to TCL RPC.
        :param cmd: String with command for OpenOCD server.
        :return: String with response on sent command.
        """
        data = (cmd + self._command_token).encode("utf-8")
        self.sock.send(data)
        return self._receive()

    def _receive(self):
        """
        Read from the stream until the token (\x1a) was received.
        :return: String with response on sent command to the server.
        """
        data = bytes()
        while True:
            chunk = self.sock.recv(self.sock_buffer_size)
            data += chunk
            if bytes(self._command_token, encoding="utf-8") in chunk:
                break
        data = data.decode("utf-8").strip()
        data = data[:-1]  # strip trailing command token \x1a
        if self.verbose:
            logger.info('receive -> %s', data)
        return data

    def _terminate_signal_received(self, **_):
        """
        The termination signal from the system was received
        """
        if logger is not None:
            logger.info('The termination signal from the system was received')
        if self.sock is not None:
            self.sock.close()
        self.ocd_server.stop()
        sys.exit(0)

    def get_ap(self):
        """
        Gets access port.
        :return: Selected AP.
        """
        logger.debug('AP: %s', self.current_ap)
        return self.current_ap

    def set_ap(self, ap):
        """
        Sets access port.
        :param ap: The AP name.
        """
        if ap == AP.CM0:
            logger.debug('Use cm0 AP')
            self._send(f'targets {self.mcu}.cm0')
        elif ap == AP.CM4:
            logger.debug('Use cm4 AP')
            self._send(f'targets {self.mcu}.cm4')
        elif ap == AP.CMx:
            if self.connect_ap == AP.CM0:
                logger.debug('Use cm0 AP')
                self._send(f'targets {self.mcu}.cm0')
            elif self.connect_ap == AP.CM4:
                logger.debug('Use cm4 AP')
                self._send(f'targets {self.mcu}.cm4')
            elif self.connect_ap == AP.CM33:
                logger.debug('Use system CM33 AP')
                self._send(f'targets {self.mcu}.cm33ap')
        elif ap == AP.CM33:
            logger.debug('Use system CM33 AP')
            self._send(f'targets {self.mcu}.cm33ap')
        elif ap == AP.SYS:
            logger.debug('Use system AP')
            self._send(f'targets {self.mcu}.sysap')
        self._send('targets')
        self.current_ap = ap

    def read(self, address, length):
        """
        Reads a block of unaligned bytes in memory
        :param address: The memory address where start reading
        :param length: Number of bytes to read
        :return: An array of byte values
        """
        cmd = 'read_memory 0x{0:x} 8 {1}'.format(address, length)
        logger.debug(cmd)
        response = self._send(cmd)
        value = [int(i, 16) for i in response.split()]
        return value

    def write(self, address, data):
        """
        Write a block of unaligned bytes in memory
        :param address: The memory address where start writing
        :param data: An array of byte values
        """
        if self.sock is None:
            raise ValueError('Target is not initialized.')

        if isinstance(data, list) and all(isinstance(i, int) for i in data):
            value = ' '.join([hex(i) for i in data])
        elif isinstance(data, (bytes, bytearray)):
            s = data.hex()
            value = '0x' + ' 0x'.join([s[i:i + 2] for i in range(0, len(s), 2)])
        else:
            raise ValueError('Either int array or bytes is supported')

        cmd = 'write_memory 0x{0:x} 8 {{{1}}}'.format(address, value)
        logger.debug(cmd)
        self._send(cmd)

    @staticmethod
    def get_probe_list():
        """
        Not implemented in OpenOCD.
        """
        raise NotImplementedError

    def set_skip_reset_and_halt(self, value):
        """
        N/A for OpenOCD
        """

    def examine_ap(self):
        """
        Examines CMx (depending on selected ap for connection) AP
        without reset
        """
        if self.connect_ap == AP.CM0:
            ap = 'cm0'
        elif self.connect_ap == AP.CM4:
            ap = 'cm4'
        elif self.connect_ap == AP.SYS:
            ap = 'sysap'

        self._send(f'{self.mcu}.{ap} arp_examine')

    def get_voltage(self):
        """Reads target voltage
        :@return Voltage value in Volts
        """
        if self.sock is None:
            raise ValueError('Target is not initialized')

        if self.ocd_server.probe_interface == 'kitprog3':
            logger.debug('kitprog3 get_power')
            response = self._send('kitprog3 get_power')
            match = re.search('VTarget = ([0-9.,]+) V', response)
            if match is not None:
                voltage = float(match.group(1))
                logger.debug('VTarget = %s', voltage)
            else:
                voltage = None
                logger.warning('VTarget is unknown')
        else:
            raise NotImplementedError
        return voltage
