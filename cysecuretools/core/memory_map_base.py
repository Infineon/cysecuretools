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


class MemoryMapBase(abc.ABC):
    """
    Base class for memory map representation. Each device memory map must implement its methods.
    """
    @property
    @abc.abstractmethod
    def FLASH_ADDRESS(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def FLASH_SIZE(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def PROVISION_JWT_PACKET_ADDRESS(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def PROVISION_JWT_PACKET_SIZE(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def MCUBOOT_HEADER_SIZE(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def SPE_IMAGE_ID(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def NSPE_IMAGE_ID(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def SMIF_ID(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def SMIF_MEM_MAP_START(self):
        raise NotImplementedError

    @abc.abstractmethod
    def trailer_size(self):
        pass
