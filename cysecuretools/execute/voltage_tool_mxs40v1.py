"""
Copyright (c) 2019-2020 Cypress Semiconductor Corporation

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
from time import sleep
from cysecuretools.execute.programmer.base import AP
from cysecuretools.core.target_director import Target
from cysecuretools.core.voltage_tool import VoltageTool

logger = logging.getLogger(__name__)

EFUSE_VOLTAGE = 2.5


class VoltageToolMXS40v1(VoltageTool):
    def __init__(self, target: Target, **kwargs):
        self.reg_map = target.register_map
        if 'efuse_voltage' in kwargs:
            self._efuse_voltage = kwargs['efuse_voltage']
        else:
            self._efuse_voltage = EFUSE_VOLTAGE

    @property
    def voltage_level(self):
        return self._efuse_voltage

    def get_voltage(self, tool):
        ap = tool.get_ap()
        tool.set_ap(AP.CMx)
        voltage_levels = [
            [1.225, 1.2],
            [1.425, 1.4],
            [1.625, 1.6],
            [1.825, 1.8],
            [2.025, 2.0],
            [2.125, 2.1],
            [2.225, 2.2],
            [2.325, 2.3],
            [2.425, 2.4],
            [2.525, 2.5],
            [2.625, 2.6],
            [2.725, 2.7],
            [2.825, 2.8],
            [2.925, 2.9],
            [3.025, 3.0],
            [3.125, 3.1],
        ]

        tool.write32(self.reg_map.PWR_LVD_CTL, 0x80)
        sleep(0.01)
        result = None
        if tool.read32(self.reg_map.PWR_LVD_STATUS) == 0:
            logger.info("Voltage is below %.3f volts" % voltage_levels[0][0])
            result = voltage_levels[0][0]
        else:
            for val in range(0, 16):
                tool.write32(self.reg_map.PWR_LVD_CTL, 0x80 | val)
                sleep(0.01)
                if tool.read32(self.reg_map.PWR_LVD_STATUS) == 0:
                    logger.info("Voltage is in range %.3f ... %.3f volts" % (
                        voltage_levels[val - 1][1], voltage_levels[val][0]))
                    result = (voltage_levels[val - 1][1] + voltage_levels[val][0]) / 2.0
                    break
        if not result:
            result = voltage_levels[15][1]
            logger.info("Voltage is above %.3f volts" % voltage_levels[15][1])
        logger.info(f'Target voltage is {result} V')
        tool.write32(self.reg_map.PWR_LVD_CTL, 0x00)
        tool.set_ap(ap)
        return result
