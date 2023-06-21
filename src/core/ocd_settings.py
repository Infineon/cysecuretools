"""
Copyright (c) 2021-2022 Cypress Semiconductor Corporation

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
import json

from ..pkg_globals import SETTINGS_FILE
from ..core.project_base import ProjectInitializerBase


class OcdSettings:
    """A class for accessing On-Chip debugger configuration"""

    def __init__(self):
        with open(SETTINGS_FILE, encoding='utf-8') as f:
            file_content = f.read()
        try:
            self.json_data = json.loads(file_content)
        except json.decoder.JSONDecodeError as e:
            msg = (f"Failed to parse settings file '{SETTINGS_FILE}': "
                   f'{e.args[0]}')
            raise json.decoder.JSONDecodeError(msg, e.doc, e.pos)

    @property
    def ocd_name(self):
        """Gets a name of the On-Chip debugger"""
        ocd_name = None
        if ProjectInitializerBase.is_project():
            ocd_name, _ = ProjectInitializerBase.get_ocd_data()
        if ocd_name is None:
            try:
                ocd_name = self.json_data['programming_tool']['name']
            except KeyError as e:
                raise KeyError(f'Invalid settings file structure '
                               f'({SETTINGS_FILE})') from e
        return ocd_name

    @property
    def ocd_path(self):
        """Gets a path to the On-Chip debugger"""
        ocd_path = None
        if ProjectInitializerBase.is_project():
            _, ocd_path = ProjectInitializerBase.get_ocd_data()
        if ocd_path is None:
            try:
                ocd_path = self.json_data['programming_tool']['path']
            except KeyError as e:
                raise KeyError(f'Invalid settings file structure '
                               f'({SETTINGS_FILE})') from e
        return ocd_path

    @staticmethod
    def serial_config():
        """Gets serial interface configuration"""
        if ProjectInitializerBase.is_project():
            config = ProjectInitializerBase.get_serial_config()
        else:
            config = ProjectInitializerBase.get_serial_config(SETTINGS_FILE)
        return config
