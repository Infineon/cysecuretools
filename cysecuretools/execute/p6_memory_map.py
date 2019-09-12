"""
Copyright (c) 2018-2019 Cypress Semiconductor Corporation

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
FLASH_ADDRESS = 0x10000000
FLASH_SIZE = 0x000e0000
PROVISION_JWT_PACKET_ADDRESS = 0x100FB600
PROVISION_JWT_PACKET_SIZE = 0x4A00

# Secure Boot defines
MCUBOOT_HEADER_SIZE = 0x400
MCUBOOT_TRAILER_SIZE = 0x200
SPE_IMAGE_ID = 1
NSPE_IMAGE_ID = 16
SMIF_ID = 1
SMIF_MEM_MAP_START = 0x18000000


def trailer_size():
    """
    Gets MCU Boot trailer size.
    :return: Size in bytes.
    """
    return MCUBOOT_TRAILER_SIZE
