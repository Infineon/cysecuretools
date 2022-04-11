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
import json

from ..core.project import ProjectInitializer


class OcdSettings:
    TOOLS_PATH = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(
        __file__)), '..'))
    SETTINGS_FILE = os.path.join(TOOLS_PATH, 'settings.json')

    def __init__(self):
        with open(self.SETTINGS_FILE, encoding='utf-8') as f:
            file_content = f.read()
        try:
            self.json_data = json.loads(file_content)
        except json.decoder.JSONDecodeError as e:
            msg = (f"Failed to parse settings file '{self.SETTINGS_FILE}': "
                   f'{e.args[0]}')
            raise json.decoder.JSONDecodeError(msg, e.doc, e.pos)

    @property
    def ocd_name(self):
        ocd_name = None
        if ProjectInitializer.is_project():
            ocd_name, _ = ProjectInitializer.get_ocd_data()
        if ocd_name is None:
            try:
                ocd_name = self.json_data['programming_tool']['name']
            except KeyError as e:
                raise KeyError(f'Invalid settings file structure '
                               f'({self.SETTINGS_FILE})') from e
        return ocd_name

    @property
    def ocd_path(self):
        ocd_path = None
        if ProjectInitializer.is_project():
            _, ocd_path = ProjectInitializer.get_ocd_data()
        if ocd_path is None:
            try:
                ocd_path = self.json_data['programming_tool']['path']
            except KeyError as e:
                raise KeyError(f'Invalid settings file structure '
                               f'({self.SETTINGS_FILE})') from e
        return ocd_path
