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
from cysecuretools.core import MemoryMapBaseP64


class MemoryMap_cyb06xx5(MemoryMapBaseP64):
    @property
    def FLASH_ADDRESS(self):
        return 0x10000000

    @property
    def FLASH_SIZE(self):
        return 0x00070000

    @property
    def PROVISION_JWT_PACKET_ADDRESS(self):
        return 0x14003600

    @property
    def PROVISION_JWT_PACKET_SIZE(self):
        return 0x4A00

    @property
    def SPE_IMAGE_ID(self):
        return 1

    @property
    def NSPE_IMAGE_ID(self):
        return 16

    @property
    def EXTERNAL_MEM_START(self):
        return 0x18000000

    @property
    def VECTOR_TABLE_ADDR_ALIGNMENT(self):
        return 0x400

    @property
    def MIN_INT_ERASE_SIZE(self):
        return 0x200

    @property
    def MIN_EXT_ERASE_SIZE(self):
        return 0x40000
