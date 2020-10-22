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
from cysecuretools.targets.cyb06xx7.target_builder import CYB06xx7_Builder
from cysecuretools.targets.cyb06xxa.target_builder import CYB06xxA_Builder
from cysecuretools.targets.cys06xxa.target_builder import CYS06xxA_Builder
from cysecuretools.targets.cyb06xx5.target_builder import CYB06xx5_Builder

target_map = {
    # PSoC64 1M
    'cyb06xx7': {
        'class': CYB06xx7_Builder,
        'family': 'PSoC64 Secure Boot Family',
        'display_name': 'PSoC64 1M'
    },
    'cy8cproto-064s1-sb': {
        'class': CYB06xx7_Builder,
        'family': 'PSOC64 Kit targets',
        'display_name': 'PSoC64 1M'
    },
    'cy8cproto-064b0s1-ble': {
        'class': CYB06xx7_Builder,
        'family': 'PSOC64 Kit targets',
        'display_name': 'PSoC64 1M'
    },

    # PSoC64 2M
    'cy8ckit-064b0s2-4343w': {
        'class': CYB06xxA_Builder,
        'family': 'PSOC64 Kit targets',
        'display_name': 'PSoC64 2M'
    },
    'cy8ckit-064s0s2-4343w': {
        'class': CYS06xxA_Builder,
        'family': 'PSOC64 Kit targets',
        'display_name': 'PSoC64 2M'
    },
    'cyb06xxa': {
        'class': CYB06xxA_Builder,
        'family': 'PSoC64 Secure Boot Family',
        'display_name': 'PSoC64 2M'
    },
    'cys06xxa': {
        'class': CYS06xxA_Builder,
        'family': 'PSoC64 Standard Secure Family',
        'display_name': 'PSoC64 2M'
    },

    # PSoC64 512K
    'cy8cproto-064b0s3': {
        'class': CYB06xx5_Builder,
        'family': 'PSOC64 Kit targets',
        'display_name': 'PSoC64 512K'
    },
    'cyb06xx5': {
        'class': CYB06xx5_Builder,
        'family': 'PSoC64 Secure Boot Family',
        'display_name': 'PSoC64 512K'
    },
}


def print_targets():
    output = {}
    for target in target_map:
        tmp = output.get(target_map[target]['family'], [])
        tmp.append(target)
        output[target_map[target]['family']] = tmp
    print('Supported targets and families:')
    for family in output:
        print(f'{family}:')
        for target in output[family]:
            print(f'\t{target}')
