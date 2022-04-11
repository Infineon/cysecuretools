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
from cysecuretools.core.provisioning_flows import Application


class ApplicationMXS40Sv2(Application):
    """
    Implements RAM application data for MXS40Sv2 silicons
    """

    APP_DIR = os.path.abspath(os.path.join(os.path.dirname(
        __file__), '..', '..', '..', 'targets', 'cyw20829', 'packets', 'apps'))

    def __init__(self, app, app_dir=APP_DIR):
        """
        Creates instance of the application
        :param app: Either application name or application
            configuration file. If the application name is specified,
            the application config will be found in the apps directory,
            otherwise the specified file will be used
        """
        super().__init__(app)
        if os.path.isfile(app):
            self.config = app
        else:
            self.config = os.path.join(app_dir, app, 'config.json')
        self.config_data = self._get_json(self.config)

        self._name = app
        self._image_path = self._get_image_path()
        self._image_address = self._get_image_address()
        self._in_params_path = self._get_in_params_path()
        self._in_params_address = self._get_in_params_address()
        self._in_params_optional = self._get_in_params_optional()
        self._allowed_lcs = self._get_allowed_lcs()

    @property
    def name(self):
        """ Application name """
        return self._name

    @property
    def image_path(self):
        """ Application image path """
        return self._image_path

    @property
    def image_address(self):
        """ Address where to program the application """
        return self._image_address

    @property
    def in_params_path(self):
        """ Application input parameters path """
        return self._in_params_path

    @property
    def in_params_address(self):
        """ Address where to program the input parameters """
        return self._in_params_address

    @property
    def in_params_optional(self):
        """ Indicates whether the input parameters are optional """
        return self._in_params_optional

    @property
    def allowed_lcs(self):
        """
        A list of device lifecycles allowed to program the application
        """
        return self._allowed_lcs

    def _get_image_data(self):
        image_data = self.config_data.get('image')
        if image_data is None:
            raise KeyError(f"'image' field not found in '{self.config}'")
        return image_data

    def _get_image_path(self):
        image_data = self._get_image_data()
        image_path = image_data.get('path')
        if image_path is None:
            raise KeyError(f"Image 'path' not found in '{self.config}'")

        try:
            if not os.path.isabs(image_path):
                image_path = os.path.abspath(
                    os.path.join(os.path.dirname(self.config), image_path))
        except ValueError as e:
            raise ValueError(f'{e} ({self.config})') from e
        return image_path

    def _get_image_address(self):
        image_data = self._get_image_data()
        image_address = image_data.get('address')
        if image_address is None:
            raise KeyError(f"Image 'address' not found in '{self.config}'")

        try:
            image_address = int(image_address, 0)
        except ValueError as e:
            raise ValueError(f'{e} ({self.config})') from e
        return image_address

    def _get_in_params_path(self):
        in_params = self.config_data.get('in_params')
        if in_params is None:
            in_params_path = None
        else:
            in_params_path = in_params.get('path')
            if in_params_path is None:
                raise KeyError(
                    f"Input parameters 'path' not found in '{self.config}'")
            try:
                if not os.path.isabs(in_params_path):
                    in_params_path = os.path.abspath(os.path.join(
                        os.path.dirname(self.config), in_params_path))
            except ValueError as e:
                raise ValueError(f'{e} ({self.config})') from e
        return in_params_path

    def _get_in_params_address(self):
        in_params = self.config_data.get('in_params')
        if in_params is None:
            in_params_address = None
        else:
            in_params_address = in_params.get('address')
            if in_params_address is None:
                raise KeyError(
                    f"Input parameters 'address' not found in '{self.config}'")
            in_params_address = int(in_params_address, 0)
        return in_params_address

    def _get_in_params_optional(self):
        in_params = self.config_data.get('in_params')
        return in_params.get('optional', False) if in_params else False

    def _get_allowed_lcs(self):
        return self.config_data.get('allowed_lcs')

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
