"""
Copyright 2021-2023 Cypress Semiconductor Corporation (an Infineon company)
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
import sys
import logging

from .mtb_tools_discovery import mtb_openocd_dir
from .target_director import Target
from ..execute.programmer.base import ProgrammerBase

logger = logging.getLogger(__name__)


class ConnectHelper:
    """ Helper class for connection creation process """

    connected = False
    do_not_disconnect = False

    @staticmethod
    def connect(tool: ProgrammerBase, target: Target,
                probe_id=None, ap='sysap', acquire=True, ignore_errors=False,
                power=None, voltage=None) -> bool:
        """ Checks for target/OCD compatibility and creates a connection """

        if tool.name not in target.ocds:
            logger.error("Target '%s' is not supported by the selected "
                         "on-chip debugger '%s'", target.name, tool.name)
            ConnectHelper._print_ocd_info(tool, target)
            ConnectHelper._print_example()
            raise ValueError('Incompatible target and on-chip debugger')

        if tool.require_path:
            if not tool.tool_path:
                tool.tool_path = ConnectHelper.discover_tool(tool.name)
                if not tool.tool_path:
                    logger.error("Path to '%s' not specified", tool.name)
                    ConnectHelper._print_example()
                    raise ValueError('Invalid on-chip debugger path')
            if not os.path.exists(tool.tool_path):
                logger.error(
                    "Path to '%s' not found (%s)", tool.name, tool.tool_path)
                ConnectHelper._print_example()
                raise ValueError('Invalid on-chip debugger path')

        if not ConnectHelper.connected:
            if tool.require_path and tool.tool_path:
                logger.info("On-Chip debugger path is '%s'", tool.tool_path)
            ConnectHelper.connected = tool.connect(
                target.name, probe_id=probe_id, ap=ap, acquire=acquire,
                power=power, voltage=voltage, ignore_errors=ignore_errors)

        if not ConnectHelper.connected:
            if tool.name == 'openocd' and not ignore_errors:
                logger.error('OpenOCD server has not started')
        return ConnectHelper.connected

    @staticmethod
    def power_on(tool: ProgrammerBase, target: Target, voltage):
        if tool.name != 'openocd':
            logger.error("Incompatible command and on-chip debugger")
            return False
        logger.warning('ATTENTION! To avoid device destruction, make sure the '
                       'external power is not connected. Continue? (y/n): ')
        confirm = input()
        if confirm.lower() == 'y':
            if voltage is None:
                voltage = 2500
                logger.warning('Voltage is not specified. Default voltage '
                               'level will be used (%d mV).', voltage)
            if ConnectHelper.connect(tool, target, power='on', voltage=voltage):
                logger.info('Power on command sent')
                return True
        else:
            return True
        return False

    @staticmethod
    def power_off(tool: ProgrammerBase, target: Target):
        if tool.name != 'openocd':
            logger.error("Incompatible command and on-chip debugger")
            return False
        if ConnectHelper.connect(tool, target, power='off'):
            logger.info('Power off command sent')
            return True
        return False

    @staticmethod
    def disconnect(tool: ProgrammerBase):
        if ConnectHelper.connected and not ConnectHelper.do_not_disconnect:
            tool.disconnect()
            ConnectHelper.connected = False

    @staticmethod
    def discover_tool(tool_name):
        """Autodiscovery of the OCD path"""
        if tool_name == 'openocd':
            return mtb_openocd_dir()
        return None

    @staticmethod
    def _print_ocd_info(tool, target):
        print(f'The currently selected on-chip debugger: {tool.name}.')
        print(f"The supported on-chip debugger(s) for the '{target.name}' "
              f'target: {",".join(target.ocds)}.')

    @staticmethod
    def _print_example():
        app_name = os.path.basename(sys.argv[0])
        print("Use the 'set-ocd' command to configure the On-Chip debugger.")
        print('Example:')
        print(f'{app_name} set-ocd --name openocd --path /Users/username/'
              f'tools/openocd')
