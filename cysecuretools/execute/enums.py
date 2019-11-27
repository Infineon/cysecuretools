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
from enum import IntEnum


class ProtectionState(IntEnum):
    """
    Provides set of device life-cycle stages.
    """
    unknown, virgin, normal, secure, dead = range(5)


class EntranceExamStatus(IntEnum):
    OK = 0
    INVALID_MODE = 1
    FIRMWARE_RUNNING_CM4 = 2
    FIRMWARE_RUNNING_CM0 = 3
    FLASH_NOT_EMPTY = 4


class ProvisioningStatus(IntEnum):
    OK = 0
    FAIL = 1
    TERMINATED = 2
