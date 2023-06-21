"""
Copyright 2022-2023 Cypress Semiconductor Corporation (an Infineon company)
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
import sys
import time
import logging
import platform
from subprocess import Popen, PIPE

from ...core.progress_bar import update_progress

logger = logging.getLogger(__name__)


class DfuhtRunner:
    """The class is responsible for running the dfuht-cli application.
    Based on the user configuration it provides input parameters for
    the serial interface protocols. Also parses the application output
    and provides the output consistent with the package
    """

    def __init__(self, settings):
        self.dfuht_path = settings.ocd_path
        self.proc = None
        self.serial_config = settings.serial_config()
        self.serial_port = self.serial_config.get('hwid')
        self.protocol = self.serial_config.get('protocol')

        if self.serial_port is None:
            raise ValueError('Serial port not specified')
        if self.protocol is None:
            raise ValueError('Serial interface protocol not specified')

        if platform.system() not in ['Windows', 'Linux', 'Darwin']:
            raise ValueError(f'Unsupported OS platform: {platform.system()}')

    def run(self, args, add_protocol_args=True, print_output=True):
        """Executes the dfuht-cli application
        @param args: List of arguments
        @param add_protocol_args: Indicates whether to add the
            arguments for the currently selected protocol
        @param print_output: Indicates whether to print the
            tool output to the log
        @return: stdout, stderr
        """
        command = [self.dfuht_path] + args
        if add_protocol_args:
            protocol_args = self.protocol_args()
            self.log_protocol_args(protocol_args)
            command.extend(protocol_args)
            command.extend(['--hwid', self.serial_port])

        logger.debug('Execute command: %s', command)
        with Popen(command, stdout=PIPE, stderr=PIPE) as self.proc:
            stdout = self.read_stdout()
            stderr = self.read_stderr()

        self.stop()

        if print_output:
            if 'Operation succeeded.' in stdout:
                self.log_success(stderr, stdout)
            else:
                self.log_failure(stderr, stdout)

        return stdout, stderr

    def log_protocol_args(self, args):
        """Logs dfuht-cli protocol arguments"""
        logger.info('port = %s', self.serial_port)
        logger.info('protocol = %s', self.protocol)
        for idx, arg in enumerate(args):
            if '--' in arg:
                value = None
                parameter = arg.lstrip('-')
                if len(args) - 1 > idx:
                    if '--' not in args[idx + 1]:
                        value = args[idx + 1]
                if value:
                    logger.info('%s = %s', parameter, value)
                else:
                    logger.info('%s', parameter)
            continue

    @staticmethod
    def log_success(stderr, stdout):
        """Logs the messages from the stderr and stdout
        in case of success
        """
        warning_template = '"Log: " Warning: '
        for line in stderr:
            if line.startswith(warning_template):
                logger.warning(line.replace(warning_template, ''))
            else:
                logger.debug(line)
        for line in stdout:
            logger.info(line)

    @staticmethod
    def log_failure(stderr, stdout):
        """Logs the messages from the stderr and stdout
        in case of failure
        """
        warning_template = '"Log: " Warning: '
        for line in stderr:
            if line.startswith(warning_template):
                logger.warning(line.replace(warning_template, ''))
            else:
                logger.debug(line)
        for line in stdout:
            logger.error(line)

    def read_stderr(self):
        """Parses stderr output
        @return: List of stderr lines
        """
        if self.proc.stderr is not None:
            out = b''
            for char in iter(lambda: self.proc.stderr.read(1), b''):
                out += char
            return list(filter(None, out.decode('utf-8').split('\n')))
        return None

    def read_stdout(self):
        """Parses stdout output
        @return: List of stdout lines
        """
        if self.proc.stdout is not None:
            out = b''
            progress = None
            for char in iter(lambda: self.proc.stdout.read(1), b''):
                if char == b'\r':
                    out += b''
                else:
                    out += char
                    if len(out) == 3:
                        if progress != out[:3] and out[:3].strip().isdigit():
                            progress = out[:3]
                            update_progress(int(progress))
                            if int(progress) == 100:
                                sys.stdout.write('\n')
            lines = out.decode('utf-8').split('\n')
            return [ln for ln in lines if ln and not ln.startswith('100%')]
        return None

    def protocol_args(self):
        """Gets selected protocol arguments for dfuht-cli specified in
        the settings or project file
        @return: List of protocol configuration arguments
        """
        if self.protocol == 'uart':
            return self.uart_args()
        if self.protocol == 'i2c':
            return self.i2c_args()
        if self.protocol == 'spi':
            return self.spi_args()
        if self.protocol == 'usb_cdc':
            return self.uart_args()
        raise ValueError(f"Invalid serial interface protocol '{self.protocol}'")

    def uart_args(self):
        """Gets dfuht-cli arguments for UART protocol"""
        uart = self.serial_config.get('uart')
        if not uart:
            raise ValueError('UART configuration not defined')
        try:
            return [
                '--uart-baudrate', str(uart['baudrate']),
                '--uart-databits', str(uart['databits']),
                '--uart-stopbits', str(uart['stopbits']),
                '--uart-paritytype', uart['paritytype']
            ]
        except KeyError as e:
            raise KeyError(f'UART parameter {e} not specified') from e

    def i2c_args(self):
        """Gets dfuht-cli arguments for I2C protocol"""
        i2c = self.serial_config.get('i2c')
        if not i2c:
            raise ValueError('I2C configuration not defined')
        try:
            return [
                '--i2c-address', str(i2c['address']),
                '--i2c-speed', str(i2c['speed'])
            ]
        except KeyError as e:
            raise KeyError(f'I2C parameter {e} not specified') from e

    def spi_args(self):
        """Gets dfuht-cli arguments for SPI protocol"""
        spi = self.serial_config.get('spi')
        if not spi:
            raise ValueError('I2C configuration not defined')
        try:
            args = [
                '--spi-clockspeed', str(spi['clockspeed']),
                '--spi-mode', str(spi['mode']),
            ]
        except KeyError as e:
            raise KeyError(f'SPI parameter {e} not specified') from e
        if spi.get('lsb_first'):
            args.append('--spi-lsb-first')
        return args

    def stop(self):
        """Stops the process"""
        if self.proc is not None:
            timeout_sec = 1
            self.proc.kill()
            start_time = time.time()
            while self.proc.poll() is None:
                if time.time() - start_time > timeout_sec:
                    break
            self.proc = None

    def __del__(self):
        self.stop()
