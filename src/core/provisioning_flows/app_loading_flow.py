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
import json
import logging

from ..enums import ProvisioningStatus
from ...core.provisioning_flows.application import Application
from ...targets.common.flow_parser import FlowParser

logger = logging.getLogger(__name__)


class AppLoadingFlow:
    """ Implements provisioning flow """

    def __init__(self, target, flow_name, app_dir, **kwargs):
        self.target = target
        config = kwargs.get('config', None)
        test_pkg_type = kwargs.get('test_pkg_type')
        self.app_list = []

        if config is not None:
            self.app_list = [Application(config)]
        else:
            flow_parser = FlowParser(target, test_pkg_type=test_pkg_type)
            try:
                for app in flow_parser.apps_by_flow(flow_name):
                    self.app_list.append(Application(app, app_dir=app_dir))
            except KeyError as e:
                msg = f'Field {e} not found ({flow_parser.provisioning_flows})'
                raise KeyError(msg) from e

    def run(self, tool):
        """ Starts loading RAM applications """
        status = ProvisioningStatus.OK

        if not self.app_list:
            logger.warning('Application list is empty')

        self._check_files_exist()

        for app in self.app_list:
            self.target.app_loader.__init__(tool, self.target, app)
            status = self.target.app_loader.load()
            if status == ProvisioningStatus.OK:
                if app == self.app_list[-1]:
                    self.target.app_loader.reset()
                try:
                    self.target.version_provider.log_lifecycle_stage(tool)
                except RuntimeError:
                    logging.error('Unable to read current LCS value')
                    return ProvisioningStatus.FAIL
            elif status == ProvisioningStatus.FAIL:
                break
        return status

    def _check_files_exist(self):
        """ Checks whether all the files necessary for provisioning exist """
        for app in self.app_list:
            file_path = app.dlm_path or app.image_path
            if not file_path:
                raise ValueError(f"Application not specified in '{app.config}'")
            if file_path and not os.path.isfile(file_path):
                raise FileNotFoundError(
                    f"Cannot find '{os.path.abspath(file_path)}'")
            if not app.in_params_optional and app.in_params_path is not None:
                if not os.path.isfile(app.in_params_path):
                    raise FileNotFoundError(
                        f'Application input parameters file not found '
                        f'({app.in_params_path})')

    @staticmethod
    def _get_json(filename):
        """
        Opens JSON file with the provisioning flows description as
        a dictionary
        """
        with open(filename, encoding='utf-8') as f:
            file_content = f.read()
            data = json.loads(file_content)
        return data
