"""
Copyright (c) 2020 Cypress Semiconductor Corporation

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
import enum
import platform
import time
import psutil
import atexit
import subprocess
from pathlib import Path
from cysecuretools.core.logging_configurator import LoggingConfigurator
from cysecuretools.core.ocd_settings import OcdSettings


OPENOCD_DEFAULT_PATH = os.path.join(os.path.dirname(__file__), os.pardir,
                                    os.pardir, os.pardir, 'openocd')

logger = logging.getLogger(__name__)


class OcdTransport(enum.Enum):
    """ Enum with supported transport protocols in OpenOCD """
    SWD = 'swd'
    JTAG = 'jtag'


class OcdProbeInterface(enum.Enum):
    """ Enum with supported debug probes in OpenOCD """
    KITPROG3 = 'kitprog3'
    CMSIS_DAP = 'cmsis-dap'


class OcdAcquire(enum.IntEnum):
    """ Enum with possible Aquire options in OpenOCD """
    ENABLE = 1
    DISABLE = 0


class OcdConfig(object):
    """
        This is a class which contains configuration settings for OpenOCD.

        See OpenOCD documentation for details:
        http://openocd.org/doc/pdf/openocd.pdf
    """

    def __init__(self):
        """ Set initial basic configuration params for OpenOCD """
        # Root path to the OCD tool
        self.ocd_root_path = None

        # debug_level [n]
        # Display debug level.
        # If n (from 0..4) is provided, then set it to that level.
        # This affects the kind of messages sent to the server log.
        #   Level 0 is error messages only;
        #   level 1 adds warnings;
        #   level 2 adds informational messages;
        #   level 3 adds debugging messages;
        #   level 4 adds verbose low-level debug messages.
        # The default is level 2.
        # This is an OPTIONAL parameter
        self.debug_level = 2

        # Indicates whether enable the power supply on the debug probe to
        # power the target device.
        # The possible values:
        #    0 – Power supply disabled.
        #    Any other value defines target voltage in millivolts.
        # This is an OPTIONAL parameter
        self.enable_power_supply = 0

        # Enables or disables acquisition of the target device in Test mode.
        # This is OPTIONAL parameter
        self.enable_acquire = OcdAcquire.ENABLE.value

        # Set the serial number of the specific probe to which want to connect
        # This is OPTIONAL parameter
        self.probe_id = None

        # Set the specific debug adapter. Examples: kitprog3, jlink, cmsis-dap
        # This is MANDATORY parameter
        self.probe_interface = OcdProbeInterface.KITPROG3.value

        # Set the speed in kHz for the selected debug adapter.
        # This is OPTIONAL parameter
        self.adapter_speed_khz = 100

        # Set the transport level. Examples: swd, jtag
        # This is MANDATORY parameter
        self.transport_select = OcdTransport.SWD.value

        # Set the name of the target device. Examples: psoc6, player
        # This is MANDATORY parameter
        self.target_device_name = None
        
        # Set the limit the size of accessible Flash
        # This is OPTIONAL parameter
        self.flash_restriction_size = None


class OpenocdServer(OcdConfig):
    """
        This is a class which implements OpenOCD server configuration.

        See OpenOCD documentation for details:
        http://openocd.org/doc/pdf/openocd.pdf
    """

    _supported_os_short_names = {
        'Windows': 'win',
        'Linux':   'linux',
        'Darwin':  'osx',
    }

    log_counter = 1

    def __init__(self, target, target_name=None, interface=None,
                 probe_id=None, tool_path=None):
        """ Set initial basic configuration params for OpenOCD """
        if interface:
            raise NotImplementedError

        super().__init__()
        self.inited = True
        self.server_proc = None  # TCL RPC server process
        self.openocd_cmd = ''    # command for OpenOCD configuration

        os_name = platform.system()  # current OS type
        # Set OpenOCD execution filename
        if os_name in self._supported_os_short_names.keys():
            self._os_short_name = self._supported_os_short_names[os_name]
        else:
            self.inited = False
            raise ValueError('Unsupported OS platform: {0}'.format(os_name))

        # Set OpenOCD executabe filename
        if self._os_short_name == 'win':
            self.openocd_exec_file = 'openocd.exe'
        else:
            self.openocd_exec_file = 'openocd'

        # Get OpenOCD directory path
        if tool_path is None:
            settings = OcdSettings()
            self.ocd_root_path = settings.ocd_path
        else:
            self.ocd_root_path = tool_path
        if not os.path.exists(self.ocd_root_path):
            raise FileNotFoundError(
                f"Unable to find OpenOCD in '{self.ocd_root_path}'")

        self.target_device_name = target_name
        self.probe_id = probe_id

        # Update Flash restriction size to be able to program Secure Bootloader
        self.flash_restriction_size = target.memory_map.FLASH_SIZE

        # Only SWD interface supported by now
        self.transport_select = OcdTransport.SWD.value

    def _prepare_command(self, ap='sysap', acquire=None):
        """
        This command configure the local OpeOCD server.
        :return: None
        """
        openocd_exec_file = os.path.abspath(os.path.join(
            self.ocd_root_path, 'bin', self.openocd_exec_file))
        openocd_scripts_dir = os.path.join(self.ocd_root_path, 'scripts')

        if self.probe_id is None:
            set_probe_id_command = ''
        else:
            set_probe_id_command = f'cmsis_dap_serial {self.probe_id}'

        self.openocd_cmd = [
            openocd_exec_file,
            '--search',
            openocd_scripts_dir,
        ]

        ap_config = ''
        if ap == 'cm0':
            ap_config = 'set TARGET_AP cm0_ap'
        if ap == 'cm4':
            ap_config = 'set TARGET_AP cm4_ap'

        enable_acquire = self.enable_acquire if acquire is None else int(acquire)

        openocd_config_cmd = []
        if self.flash_restriction_size is not None:
            openocd_config_cmd += [f'set FLASH_RESTRICTION_SIZE {self.flash_restriction_size}']

        openocd_config_cmd += [
            f'debug_level {self.debug_level}',
            f'set ENABLE_ACQUIRE {enable_acquire}',
            f'set ENABLE_POWER_SUPPLY {self.enable_power_supply}',
            'set ACQUIRE_TIMEOUT 10',
            ap_config,
            'gdb_memory_map enable',
            'gdb_flash_program enable',
            f'source [find interface/{self.probe_interface}.cfg]',
            f'{set_probe_id_command}',
            f'transport select {self.transport_select}',
            f'source [find target/{self.target_device_name}.cfg]',
            f'adapter speed {self.adapter_speed_khz}',
            f'{self.target_device_name}.cm33 configure -defer-examine',
            'init',
            f'targets {self.target_device_name}.{ap}'
        ]

        # Remove empty elements from list
        openocd_config_cmd = list(filter(None, openocd_config_cmd))
        # Insert a command '-c' before each element in list
        openocd_config_cmd = \
            [cmd for elem in openocd_config_cmd for cmd in ('-c', elem)]
        # Format command for Popen
        self.openocd_cmd.extend(openocd_config_cmd)

    def start(self, ap='sysap', acquire=None):
        """
        This command starts the local OpeOCD server.
        :return: True if server successfully started, otherwise False.
        """
        # Maximum time in seconds server should start after OpenOCD start
        server_startup_time = 5
        log_dir = LoggingConfigurator.get_log_dir()
        log_file = f'{log_dir}/openocd_{OpenocdServer.log_counter}.log'
        OpenocdServer.log_counter += 1
        server_started = False

        # Check if OpenOCD server is running now
        if (self.server_proc is not None and self.server_proc.poll() is not None) or self.server_proc is None:
            # Prepare command for Popen function
            self._prepare_command(ap, acquire)
            logger.debug('Execute command: %s', self.openocd_cmd)

            # Register function which will be executed at the end
            # of __main__ execution
            atexit.register(self.stop)

            # Start OpenOCD server and redirect stdout to the file
            Path('logs').mkdir(parents=True, exist_ok=True)
            with open(log_file, 'w', encoding='utf-8') as f:
                self.server_proc = subprocess.Popen(self.openocd_cmd, stdout=f,
                                                    stderr=subprocess.STDOUT)

            # Check if server was started correctly
            start_time = time.time()
            while time.time() - start_time < server_startup_time:
                try:
                    with open(log_file, 'r', encoding='utf-8') as log:
                        lines = log.readlines()
                        for line in lines:
                            if 'Error' in line:
                                server_started = False
                                logger.error('Server ERROR: %s', line.rstrip())
                            else:
                                logger.info(line.rstrip())
                            if 'Listening on port' in line:
                                server_started = True
                                break
                    # Wait 1 second and check if server is running.
                    time.sleep(1)
                    if (self.server_proc.poll() is not None and
                            not server_started) or server_started:
                        break
                except FileNotFoundError:
                    logger.error('Server log file not found: %s', log_file)
                    server_started = False
                    break
        else:
            logger.error('OpenOCD server is running now')
        return server_started

    def stop(self):
        """
        This command stops the local OpeOCD server.
        :return: None
        """
        if self.server_proc is not None:
            timeout = 1  # seconds
            self.server_proc.kill()
            start_time = time.time()
            while self.server_proc.poll() is None:
                if time.time() - start_time > timeout:
                    break
            self.server_proc = None

    def _kill_all(self):
        """ This command kill all OpeOCD processes """
        openocd_proc_name = self.openocd_exec_file
        for proc in psutil.process_iter():
            if proc.name() == openocd_proc_name:
                proc.kill()

    def __del__(self):
        self.stop()