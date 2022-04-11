"""
Copyright (c) 2021 Cypress Semiconductor Corporation

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

from .target_director import Target
from ..execute.programmer.base import ProgrammerBase

logger = logging.getLogger(__name__)


class ConnectHelper:
    """ Helper class for connection creation process """

    connected = False
    do_not_disconnect = False

    @staticmethod
    def connect(tool: ProgrammerBase, target: Target,
                probe_id=None, ap=None, acquire=True, blocking=True,
                suppress_errors=False) -> bool:
        """ Checks for target/OCD compatibility and creates a connection """

        if tool.name not in target.ocds:
            logger.error("Target '%s' is not supported by the selected "
                         "on-chip debugger '%s'", target.name, tool.name)
            ConnectHelper._print_ocd_info(tool, target)
            ConnectHelper._print_example()
            raise ValueError('Incompatible target and on-chip debugger')

        if tool.require_path:
            if not tool.tool_path:
                logger.error("Path to '%s' not specified", tool.name)
                ConnectHelper._print_example()
                raise ValueError('Invalid on-chip debugger path')
            elif not os.path.exists(tool.tool_path):
                logger.error(
                    "Path to '%s' not found (%s)", tool.name, tool.tool_path)
                ConnectHelper._print_example()
                raise ValueError('Invalid on-chip debugger path')

        if not ConnectHelper.connected:
            ConnectHelper.connected = tool.connect(
                target.name, probe_id=probe_id, ap=ap, acquire=acquire,
                blocking=blocking)

        if not ConnectHelper.connected:
            if tool.name == 'openocd' and not suppress_errors:
                logger.error('OpenOCD server has not started')
        return ConnectHelper.connected

    @staticmethod
    def disconnect(tool: ProgrammerBase):
        if ConnectHelper.connected and not ConnectHelper.do_not_disconnect:
            tool.disconnect()
            ConnectHelper.connected = False

    @staticmethod
    def _print_ocd_info(tool, target):
        print(f'The currently selected on-chip debugger: {tool.name}.')
        print(f"The supported on-chip debugger(s) for the '{target.name}' "
              f'target: {",".join(target.ocds)}.')

    @staticmethod
    def _print_example():
        app_name = os.path.basename(sys.argv[0])
        print("Use the 'set-ocd' command to set the active debugger.")
        print('Examples:')
        print(f'{app_name} set-ocd --name pyocd')
        print(f'{app_name} set-ocd --name openocd --path /Users/username/'
              f'tools/openocd')
