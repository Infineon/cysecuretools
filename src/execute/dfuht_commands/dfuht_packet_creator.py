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
import os
import logging

from intelhex import IntelHex

from .dfuht_packet import (
    DfuhtPacket, DfuhtMeta, DfuhtProvisionCommand, DfuhtReadCommand)

logger = logging.getLogger(__name__)


class DfuhtCommandsCreator:
    """Implements JSON commands creator for DFU Host Tool"""

    def __init__(self, target, app, cmd_path=None):
        self.target = target
        self.cmd_path = cmd_path
        self.applications = []
        if isinstance(app, list):
            self.applications.extend(app)
        else:
            self.applications.append(app)

    def create_packets(self):
        """Creates JSON commands for each application
        @return: A list where each element is a list of custom commands which
                 has to be executed for a single application
        """
        packets = []
        meta = DfuhtMeta()
        for app in self.applications:
            app_packets = []
            dfu_cmd = self.cmd_path
            if app.dfu_commands_path:
                dfu_cmd = app.dfu_commands_path
            image, hex_info = self._bin2hex(app)
            cmd = DfuhtProvisionCommand(hex_info[0])
            app_packets.append(self.create_packet(
                meta, cmd, dfu_cmd, image=image, start_addr=hex_info[0],
                end_addr=hex_info[1]))
            packets.append(app_packets)
        return packets

    def read_cmd_packet(self, address, size, path):
        """Creates command packet to read data from device"""
        meta = DfuhtMeta()
        cmd = DfuhtReadCommand(address, size)
        cmd_packet = self.create_packet(meta, cmd, path)
        return cmd_packet

    @staticmethod
    def create_packet(meta, cmd, filename, **kwargs):
        """Creates single DFU Host Tool command
        @param meta: DFU Host Tool command metadata
        @param cmd: DFU Host Tool command
        @param filename: A file where to save the command
        """
        file_without_ext, ext = os.path.splitext(filename)
        filename = file_without_ext + '_' + hex(cmd.cmd_id) + ext
        packet = DfuhtPacket(meta, [cmd], filename, **kwargs)
        packet.dump()
        return packet

    def _bin2hex(self, app_data):
        dlm_path = app_data.dlm_path
        dlm_path_name, dlm_file_ext = os.path.splitext(dlm_path)
        if dlm_file_ext == '.bin':
            dlm_path = dlm_path_name + '.hex'
            if not self.target.sign_tool.bin2hex(
                    app_data.dlm_path, dlm_path, app_data.image_address):
                raise RuntimeError(f"Could not create file '{dlm_path}'")
            logger.debug('Convert %s to %s', app_data.dlm_path,
                         dlm_path)
        ihex = IntelHex(dlm_path)
        hex_start_end_addr = (ihex.minaddr(), ihex.maxaddr())
        return dlm_path, hex_start_end_addr
