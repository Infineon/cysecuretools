"""
Copyright (c) 2019 Cypress Semiconductor Corporation

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

CY_BOOTLOADER_MAP = os.path.join(os.path.dirname(__file__), '../targets/common/prebuilt/cy_bootloader_map.json')


class CyBootloaderMapParser:
    """
    Provides functionality for searching data in CyBootloader map.
    """
    @staticmethod
    def get_json(filename):
        """
        Gets JSON file as a dictionary.
        :param filename: The JSON file.
        :return: JSON file as a dictionary.
        """
        with open(filename) as f:
            file_content = f.read()
            data = json.loads(file_content)
        return data

    @staticmethod
    def get_filename(target, mode, file_type):
        """
        Gets the name of CyBootloader hex, or jwt file based on target, mode and file type.
        :param target: Device name.
        :param mode: CyBootloader mode (debug or release).
        :param file_type: The type of the file (hex or jwt).
        :return: Filename.
        """
        data = CyBootloaderMapParser.get_json(CY_BOOTLOADER_MAP)
        for json_target in data:
            if json_target.lower().strip() in target.lower().strip():
                for json_mode in data[json_target]:
                    if mode == json_mode:
                        return data[json_target][json_mode][file_type]
        return None
