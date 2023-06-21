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
import sys
import logging
from importlib import import_module

from .core import package_name
from .core.logging_formatter import CustomFormatter
from .targets import is_mxs40v1, is_mxs40sv2, is_mxs22, is_traveo_t2g

from .api_common import CommonAPI

# Initialize logger
logging.root.setLevel(logging.DEBUG)
fmt = CustomFormatter()
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(fmt)
console_handler.setLevel(logging.INFO)
logger = logging.getLogger(__name__)
logger.root.addHandler(console_handler)


class ProvisioningPackage:
    """
    A class inherited from the class containing common API and a
    class containing target specific API
    """

    def __new__(cls, target=None, policy=None, log_file=True,
                skip_prompts=False, skip_validation=False, rev=None):
        """Creates instance of the class inherited from the class containing
        common API and a class containing target specific API
        @param target: Device manufacturing part number
        @param policy: Provisioning policy file
        @param log_file: Indicates whether to write log into a file
        @param skip_prompts: Indicates whether to skip user interactive
               prompts
        @param skip_validation: Indicates whether to skip policy validation
        @param rev: Device revision
        """
        if target is None:
            api = CommonAPI
        else:
            try:
                if is_mxs40v1(target):
                    api_class = 'api_mxs40v1.Mxs40v1API'
                elif is_mxs40sv2(target):
                    api_class = 'api_mxs40sv2.Mxs40sv2API'
                elif is_mxs22(target):
                    api_class = 'api_mxs22.Mxs22API'
                elif is_traveo_t2g(target):
                    api_class = 'api_traveo_t2g.TraveoT2GAPI'
            except KeyError as e:
                raise ValueError(f'Unknown target "{target}"') from e

            module_name = api_class.split('.', maxsplit=1)[0]
            class_name = api_class.split('.', maxsplit=1)[-1]
            module = import_module(f".{module_name}", package=package_name())
            api = getattr(module, class_name)

        obj = type(cls.__name__, (api,), {})

        return obj(target=target, policy=policy, log_file=log_file,
                   skip_prompts=skip_prompts, skip_validation=skip_validation,
                   rev=rev)


class CySecureTools(ProvisioningPackage):
    """An alias to keep the backward compatibility"""
