"""
Copyright 2019-2023 Cypress Semiconductor Corporation (an Infineon company)
or an affiliate of Cypress Semiconductor Corporation. All rights reserved.

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
from .target_builder import XMC7xxxBuilder

target_map = {
    'xmc7100': {
        'class': XMC7xxxBuilder,
        'family': 'Traveo T2G Family',
        'display_name': 'XMC7xxx',
        'type': 'family',
        'platform': 'traveo_t2g'
    },
    'xmc7200': {
        'class': XMC7xxxBuilder,
        'family': 'Traveo T2G Family',
        'display_name': 'XMC7xxx',
        'type': 'family',
        'platform': 'traveo_t2g'
    }
}
