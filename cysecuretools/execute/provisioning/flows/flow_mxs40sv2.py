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
import json
import logging
from cysecuretools.core.provisioning_flows import Flow
from cysecuretools.core.enums import ProvisioningStatus
from cysecuretools.execute.provisioning.flows.application_mxs40sv2 import (
    ApplicationMXS40Sv2)
from cysecuretools.execute.provisioning.load_ram_app import RamAppLoader
from cysecuretools.targets.common.mxs40sv2.flow_parser import FlowParser

logger = logging.getLogger(__name__)


class FlowMXS40Sv2(Flow):
    """ Implements provisioning flow for MXS40Sv2 platform """

    def __init__(self, target, mode, app_dir, **kwargs):
        self.target = target
        config = kwargs.get('config', None)
        test_pkg_type = kwargs.get('test_pkg_type')
        self.app_list = []

        if config is not None:
            self.app_list = [ApplicationMXS40Sv2(config)]
        else:
            flow_parser = FlowParser(target, test_pkg_type=test_pkg_type)
            try:
                for app in flow_parser.apps_by_flow(mode):
                    self.app_list.append(ApplicationMXS40Sv2(app, app_dir))
            except KeyError as e:
                msg = f'Field {e} not found ({flow_parser.provisioning_flows})'
                raise KeyError(msg) from e

    def run(self, tool, **kwargs):
        """ Starts loading RAM applications """
        status = ProvisioningStatus.OK

        if not self.app_list:
            logger.warning('Application list is empty')

        self._check_files_exist()

        for app in self.app_list:
            app_loader = RamAppLoader(
                tool, self.target, kwargs.get('load_app_data'), app)
            status = app_loader.load()

            if status == ProvisioningStatus.OK:
                if app == self.app_list[-1]:
                    app_loader.reset()
                self.target.version_provider.log_lifecycle_stage(tool)
            elif status == ProvisioningStatus.FAIL:
                break

        return status

    def _check_files_exist(self):
        """ Checks whether all the files necessary for provisioning exist """
        for app in self.app_list:
            if not os.path.isfile(app.image_path):
                raise FileNotFoundError(f'Application file '
                                        f'not found ({app.image_path})')
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
