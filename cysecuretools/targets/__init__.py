"""
Copyright (c) 2019-2022 Cypress Semiconductor Corporation

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
from cysecuretools.targets.cyw20829.target_builder import CYW20829Builder
from cysecuretools.targets.cyw20829_a0.target_builder import CYW20829A0Builder

__target_map = {
    # PSoC64 1M
    'cyb06xx7': {
        'class': CYB06xx7_Builder,
        'family': 'PSoC64 Secure Boot Family',
        'display_name': 'PSoC64 1M',
        'type': 'family',
        'platform': 'psoc64'
    },
    'cy8cproto-064s1-sb': {
        'class': CYB06xx7_Builder,
        'family': 'PSoC64 Kit targets',
        'display_name': 'PSoC64 1M',
        'type': 'kit',
        'platform': 'psoc64'
    },
    'cy8cproto-064b0s1-ble': {
        'class': CYB06xx7_Builder,
        'family': 'PSoC64 Kit targets',
        'display_name': 'PSoC64 1M',
        'type': 'kit',
        'platform': 'psoc64'
    },
    'cy8cproto-064b0s1-ssa': {
        'class': CYB06xx7_Builder,
        'family': 'PSoC64 Kit targets',
        'display_name': 'PSoC64 1M',
        'type': 'kit',
        'platform': 'psoc64'
    },

    # PSoC64 2M
    'cy8ckit-064b0s2-4343w': {
        'class': CYB06xxA_Builder,
        'family': 'PSoC64 Kit targets',
        'display_name': 'PSoC64 2M',
        'type': 'kit',
        'platform': 'psoc64'
    },
    'cy8ckit-064s0s2-4343w': {
        'class': CYS06xxA_Builder,
        'family': 'PSoC64 Kit targets',
        'display_name': 'PSoC64 2M',
        'type': 'kit',
        'platform': 'psoc64'
    },
    'cyb06xxa': {
        'class': CYB06xxA_Builder,
        'family': 'PSoC64 Secure Boot Family',
        'display_name': 'PSoC64 2M',
        'type': 'family',
        'platform': 'psoc64'
    },
    'cys06xxa': {
        'class': CYS06xxA_Builder,
        'family': 'PSoC64 Standard Secure Family',
        'display_name': 'PSoC64 2M',
        'type': 'family',
        'platform': 'psoc64'
    },

    # PSoC64 512K
    'cy8cproto-064b0s3': {
        'class': CYB06xx5_Builder,
        'family': 'PSoC64 Kit targets',
        'display_name': 'PSoC64 512K',
        'type': 'kit',
        'platform': 'psoc64'
    },
    'cyb06xx5': {
        'class': CYB06xx5_Builder,
        'family': 'PSoC64 Secure Boot Family',
        'display_name': 'PSoC64 512K',
        'type': 'family',
        'platform': 'psoc64'
    },

    # CYW20829
    'cyw20829': {
        'default': {
            'class': CYW20829Builder,
            'family': 'MXS40Sv2 Family',
            'display_name': 'CYW20829',
            'type': 'family',
            'platform': 'mxs40sv2'
        },
        'a0': {
            'class': CYW20829A0Builder,
            'family': 'MXS40Sv2 Family',
            'display_name': 'CYW20829',
            'type': 'family',
            'platform': 'mxs40sv2'
        },
        'b0': {
            'class': CYW20829Builder,
            'family': 'MXS40Sv2 Family',
            'display_name': 'CYW20829',
            'type': 'family',
            'platform': 'mxs40sv2'
        },
    },
}


def target_data(target_name, rev=None):
    """Gets target data from the map"""
    target_name = target_name.lower()
    if rev:
        rev = rev.lower()
        if rev in __target_map[target_name]:
            return __target_map[target_name][rev]
        raise ValueError(
            f"Target '{target_name}' does not have revision '{rev}'")
    if 'class' in __target_map[target_name]:
        return __target_map[target_name]
    return __target_map[target_name]['default']


def print_targets():
    """Prints target list"""
    output = {}
    for target_name in __target_map:
        target = target_data(target_name)
        tmp = output.get(target['family'], [])
        tmp.append(target_name)
        output[target['family']] = tmp
    print('Supported targets and families:')
    for family, targets in output.items():
        print(f'{family}:')
        for target_name in targets:
            print(f'\t{target_name}')


def get_target_builder(director, target_name, rev=None):
    """Gets target builder by target name"""
    try:
        target = target_data(target_name, rev=rev)
        director.builder = target['class']()
        return director.builder
    except KeyError as e:
        raise ValueError(f'Unknown target "{target_name}"') from e


def print_targets_extended():
    """Prints extended target list"""
    print('target|type|display_name|family')
    for k in __target_map:
        data = target_data(k)
        print(f'{k}|{data["type"]}|{data["display_name"]}|{data["family"]}')


def is_psoc64(target):
    """Gets a value indicating whether the target belongs
    to MXS40v1 platform"""
    return target_data(target)['platform'] == 'psoc64'


def is_mxs40sv2(target):
    """Gets a value indicating whether the target belongs
    to MXS40Sv2 platform"""
    return target_data(target)['platform'] == 'mxs40sv2'
