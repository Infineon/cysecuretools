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
        'display_name': 'PSoC64 1M',
        'type': 'family'
    },
    'cy8cproto-064s1-sb': {
        'class': CYB06xx7_Builder,
        'family': 'PSoC64 Kit targets',
        'display_name': 'PSoC64 1M',
        'type': 'kit'
    },
    'cy8cproto-064b0s1-ble': {
        'class': CYB06xx7_Builder,
        'family': 'PSoC64 Kit targets',
        'display_name': 'PSoC64 1M',
        'type': 'kit'
    },

    # PSoC64 2M
    'cy8ckit-064b0s2-4343w': {
        'class': CYB06xxA_Builder,
        'family': 'PSoC64 Kit targets',
        'display_name': 'PSoC64 2M',
        'type': 'kit'
    },
    'cy8ckit-064s0s2-4343w': {
        'class': CYS06xxA_Builder,
        'family': 'PSoC64 Kit targets',
        'display_name': 'PSoC64 2M',
        'type': 'kit'
    },
    'cyb06xxa': {
        'class': CYB06xxA_Builder,
        'family': 'PSoC64 Secure Boot Family',
        'display_name': 'PSoC64 2M',
        'type': 'family'
    },
    'cys06xxa': {
        'class': CYS06xxA_Builder,
        'family': 'PSoC64 Standard Secure Family',
        'display_name': 'PSoC64 2M',
        'type': 'family'
    },

    # PSoC64 512K
    'cy8cproto-064b0s3': {
        'class': CYB06xx5_Builder,
        'family': 'PSoC64 Kit targets',
        'display_name': 'PSoC64 512K',
        'type': 'kit'
    },
    'cyb06xx5': {
        'class': CYB06xx5_Builder,
        'family': 'PSoC64 Secure Boot Family',
        'display_name': 'PSoC64 512K',
        'type': 'family'
    },
}


def print_targets():
    """
    Prints target list
    """
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


def get_target_builder(director, target_name):
    try:
        director.builder = target_map[target_name]['class']()
        return director.builder
    except KeyError:
        raise ValueError(f'Unknown target "{target_name}"')


def targets_by_type(target_type):
    """
    Gets dictionary of targets of the specified type
    """
    return {k: v for k, v in target_map.items() if v['type'] == target_type}


def target_names_by_type(target_type):
    """
    Gets list of target names of the specified type
    """
    return [k for k in targets_by_type(target_type).keys()]


def print_targets_extended():
    """
    Prints extended target list
    """
    print('target|type|display_name|family')
    for k, v in target_map.items():
        print(f'{k}|{v["type"]}|{v["display_name"]}|{v["family"]}')
