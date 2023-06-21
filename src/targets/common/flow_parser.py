"""
Copyright (c) 2021 Cypress Semiconductor Corporation

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
import importlib

from ...core.json_helper import read_json


class FlowParser:
    """ Implements searching data in the provisioning flow map """

    def __init__(self, target, test_pkg_type=None):
        self.test_packages = target.test_packages
        self.project_initializer = target.project_initializer
        self.test_pkg_type = test_pkg_type
        self.default_flows_file = os.path.abspath(os.path.join(
            target.target_dir, 'flows', 'prov_flows.json'))

    @property
    def provisioning_flows(self):
        """ A path to the file containing provisioning flow data """
        if self.test_pkg_type is not None:
            package_data = self.test_packages.get(self.test_pkg_type)
            module = self._import_module(package_data['package'])
            filepath = module.PROVISIONING_FLOWS[package_data['flow_name']]
        else:
            filepath = self.default_flows_file

        return filepath

    @property
    def apps_dir(self):
        """ A path to the directory containing applications """
        if self.test_pkg_type is None or self.project_initializer.is_project():
            dirpath = self.project_initializer.apps_dir
        else:
            package_data = self.test_packages.get(self.test_pkg_type)
            module = self._import_module(package_data['package'])
            dirpath = module.APPS_DIR[package_data['flow_name']]
        return dirpath

    def apps_by_flow(self, flow):
        """
        For the specified provisioning flow, gets a dictionary
        containing application name as a key and its configuration
        file path as a value
        """
        flows_path = self.provisioning_flows
        data = read_json(flows_path)
        apps_data = {}
        dirname = os.path.dirname(flows_path)
        for app in data['flows'][flow]['apps']:
            if os.path.isabs(data['paths'][app]):
                app_path = data['paths'][app]
            else:
                app_path = os.path.join(dirname, data['paths'][app])
            apps_data[app] = app_path
        return apps_data

    def get_apps_paths(self):
        """ Gets a list of applications paths """
        flows_path = self.provisioning_flows
        apps_paths = {}
        apps_dir = os.path.dirname(flows_path)
        data = read_json(flows_path)
        for k, v in data['paths'].items():
            if os.path.isabs(v):
                apps_paths[k] = v
            else:
                apps_paths[k] = os.path.abspath(os.path.join(apps_dir, v))
        return apps_paths

    @staticmethod
    def _import_module(package_name):
        try:
            module = importlib.import_module(package_name)
            if module.__file__ is None:
                raise ImportError(f"No module named '{package_name}'")
        except ImportError as e:
            raise ImportError(
                f'Test applications not found. {e.msg}') from e
        return module
