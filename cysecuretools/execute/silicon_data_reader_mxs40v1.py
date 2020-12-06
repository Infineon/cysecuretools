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
import logging
from cysecuretools.execute.provision_device_mxs40v1 import read_silicon_data
from cysecuretools.targets.common.silicon_data_parser import SiliconDataParser

logger = logging.getLogger(__name__)


class SiliconDataReaderMXS40v1:
    def __init__(self, target):
        self.target = target

    def read_die_id(self, tool):
        data = read_silicon_data(tool, self.target)
        if data is None:
            logger.error('Failed to read silicon data')
            return None
        parser = SiliconDataParser(data)
        try:
            die_id = parser.get_die_id()
        except KeyError:
            logger.error('Invalid response. \'die_id\' field not found')
        return die_id

    def read_complete_status(self, tool):
        data = read_silicon_data(tool, self.target)
        if data is None:
            logger.error('Failed to read silicon data')
            return None
        parser = SiliconDataParser(data)
        try:
            die_id = parser.get_complete_status()
        except KeyError:
            logger.error('Invalid response. \'complete\' field not found')
        return die_id
