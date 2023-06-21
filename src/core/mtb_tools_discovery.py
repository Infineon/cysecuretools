"""
Copyright 2023 Cypress Semiconductor Corporation (an Infineon company)
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
import os
import platform
import subprocess

from packaging import version

MTB_FULL_NAME = 'ModusToolbox'
MTB_TOOLS_DIR_PREFIX = 'tools_'


def mtb_tools_dir():
    """Gets a path to the 'tools_X.Y' directory of the latest MTB
    version (where X and Y are the version number of the 'tools' directory)
    """
    cy_tools_paths = os.environ.get('CY_TOOLS_PATHS')

    if cy_tools_paths:
        return cy_tools_paths

    mtb_directory = mtb_dir()
    if mtb_directory is None:
        return None

    tools = [d for d in os.listdir(mtb_directory) if d.startswith(
        MTB_TOOLS_DIR_PREFIX)]
    if len(tools) > 0:
        tools.sort()
        return os.path.join(mtb_directory, tools[-1])

    raise FileNotFoundError(
        f"'tools_X.Y' directory not found in '{mtb_directory}'")


def mtb_dir():
    """Gets a path to the MTB directory"""
    system = platform.system()
    if system in ('Windows', 'Linux'):
        path = os.path.join(os.path.expanduser('~'), MTB_FULL_NAME)
    elif system == 'Darwin':
        path = os.path.join('/Applications', MTB_FULL_NAME)
    else:
        raise RuntimeError('Unsupported operating system')

    return path if os.path.isdir(path) else None


def mtb_version():
    """Gets version of the latest MTB installation"""
    mtb_tools_path = mtb_tools_dir()
    if mtb_tools_path:
        last_dir = os.path.basename(os.path.normpath(mtb_tools_path))
        return last_dir.replace(MTB_TOOLS_DIR_PREFIX, '')
    return None


def mtb_tools():
    """Gets paths to all MTB tools"""
    mtb_tools_path = mtb_tools_dir()
    if mtb_tools_path:
        mtbquery = os.path.join(mtb_tools_path, 'mtbquery', 'mtbquery')
        try:
            out = subprocess.check_output([mtbquery, '--alltools']).decode('utf-8')
        except FileNotFoundError:
            tools = None
        else:
            tools = {}
            for key, value in (ln.split('=') for ln in out.split('\n') if ln):
                tools[key] = value
        return tools
    return None


def mtb_openocd_dir():
    """Gets the path to OpenOCD bundled with MTB"""
    tools = mtb_tools()
    if tools:
        mtb_latest_ver = mtb_version()
        if version.parse(mtb_latest_ver) >= version.parse('3.0'):
            openocd_dir = tools.get('CY_TOOL_openocd_BASE_ABS')
        else:
            openocd_dir = tools.get('CY_TOOL_openocd_BASE')
        if openocd_dir:
            openocd_dir = openocd_dir.strip()
        return openocd_dir
    return None
