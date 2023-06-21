"""
Copyright (c) 2018-2021 Cypress Semiconductor Corporation

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
from enum import Enum, IntEnum
from collections import namedtuple


class EntranceExamStatus(IntEnum):
    OK = 0
    FAIL = 1
    FLASH_NOT_EMPTY = 2


class RegionHashStatus(IntEnum):
    OK = 0
    FAIL = 1
    FLASH_NOT_EMPTY = 2


class ProvisioningStatus(IntEnum):
    OK = 0
    FAIL = 1
    TERMINATED = 2
    SKIPPED = 3


class ValidationStatus(IntEnum):
    OK = 0,
    ERROR = 1,
    WARNING = 2,
    TERMINATED = 3


class KeyType(Enum):
    """
    Available key types.
    """
    user, encryption, device_public, group_public = range(4)


class KeyAlgorithm:
    """
    Supported key algorithms.
    """
    ECDSA_P256 = 'ECDSA-P256'
    ECDSA_P384 = 'ECDSA-P384'
    RSA2048 = 'RSA2048'
    RSA3072 = 'RSA3072'
    RSA4096 = 'RSA4096'
    AES128 = 'AES128'
    AES256 = 'AES256'
    EC = ECDSA_P256
    RSA = RSA2048
    AES = AES128


class ImageType(Enum):
    """
    Available image types.
    """
    BOOT = 'BOOT'
    UPGRADE = 'UPGRADE'
    BOOTLOADER = 'BOOTLOADER'


KeyPair = namedtuple('KeyPair', 'private public')
