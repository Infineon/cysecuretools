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
import abc


class RegisterMapBase(abc.ABC):
    """
    Base class for register map representation. Each device register map must implement its methods.
    """

    #
    #  Entrance exam registers and constants
    #

    @property
    @abc.abstractmethod
    def ENTRANCE_EXAM_FW_STATUS_REG(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def ENTRANCE_EXAM_FW_STATUS_VAL(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def ENTRANCE_EXAM_FW_STATUS_MASK(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def ENTRANCE_EXAM_SRAM_ADDR(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def ENTRANCE_EXAM_SRAM_SIZE(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def ENTRANCE_EXAM_REGION_HASH_ADDR(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def ENTRANCE_EXAM_REGION_HASH_SIZE(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def ENTRANCE_EXAM_REGION_HASH_MODE(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def ENTRANCE_EXAM_REGION_HASH_EXPECTED_VAL(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def FB_FW_STATUS_FIRMWARE_RUNNING_CM4(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def FB_FW_STATUS_FIRMWARE_RUNNING_CM0(self):
        raise NotImplementedError

    #
    # PSoC 6 BLE register addresses
    #

    @property
    @abc.abstractmethod
    def CYREG_IPC2_STRUCT_ACQUIRE(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def CYREG_IPC2_STRUCT_NOTIFY(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def CYREG_IPC2_STRUCT_DATA(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def CYREG_IPC2_STRUCT_LOCK_STATUS(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def CYREG_CPUSS_PROTECTION(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def CYREG_EFUSE_SECURE_HASH(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def NVSTORE_AREA_1_ADDRESS(self):
        raise NotImplementedError
