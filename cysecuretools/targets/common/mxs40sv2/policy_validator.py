"""
Copyright (c) 2020-2021 Cypress Semiconductor Corporation

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
import json
import os.path
import logging
import jsonschema

from cysecuretools.core import PolicyValidatorBase
from cysecuretools.core.enums import ValidationStatus
from .dependencies_validator import validate as validate_dependencies
from .enums import PolicyType


logger = logging.getLogger(__name__)


class PolicyValidator(PolicyValidatorBase):

    """ Policy type-schema map """
    _schemas = {
        PolicyType.SECURE:
            'cyw20829_secure.json_schema',
        PolicyType.NO_SECURE:
            'cyw20829_no_secure.json_schema',
        PolicyType.REPROVISIONING_SECURE:
            'cyw20829_reprovisioning_secure.json_schema',
        PolicyType.REPROVISIONING_NO_SECURE:
            'cyw20829_reprovisioning_no_secure.json_schema',
        PolicyType.HCI_SECURE:
            'cyw20829_secure.json_schema',
        'normal': None
    }

    def __init__(self, policy_parser):
        self.policy_parser = policy_parser

    def validate(self, skip=None, skip_prompts=False):
        """
        Policy JSON file validation
        :param skip:
            Validator names to be skipped
        :param skip_prompts:
            Indicates whether to skip interactive prompts
        :return
            Validation status
        """
        status = ValidationStatus.OK
        if self.skip_validation is True:
            return status

        if self.policy_parser.json is None:
            raise ValueError('No policy data')

        schema = self._get_schema()
        if schema is not None:
            status = self._validate_by_schema(schema, self.policy_parser.json)

            if status is ValidationStatus.OK:
                status = self._validate_dependencies(skip)

        return status

    @staticmethod
    def _validate_by_schema(schema, data):
        """ Validation against JSON schema """
        status = ValidationStatus.OK
        with open(schema, encoding='utf-8') as f:
            file_content = f.read()
            json_schema = json.loads(file_content)

        try:
            jsonschema.validate(data, json_schema)
            logger.debug('Validation against schema succeed')
        except (jsonschema.exceptions.ValidationError,
                jsonschema.exceptions.SchemaError) as e:
            logger.error('Validation against schema failed')
            logger.error(e)
            status = ValidationStatus.ERROR
        return status

    def _validate_dependencies(self, skip_list):
        is_valid, messages = validate_dependencies(self.policy_parser,
                                                   skip_list)
        for m in messages:
            if m.severity == 'error':
                logger.error(m.message)
            elif m.severity == 'warning':
                logger.warning(m.message)
            elif m.severity == 'info':
                logger.info(m.message)
            elif m.severity == 'debug':
                logger.debug(m.message)
        return ValidationStatus.OK if is_valid else ValidationStatus.ERROR

    def _get_schema(self):
        """ Gets schema filepath based on policy type """
        module_path = os.path.dirname(os.path.realpath(__file__))
        try:
            schema = self._schemas[self.policy_parser.get_policy_type()]
        except KeyError as e:
            raise ValueError(f"Invalid policy type '{e.args[0]}'") from e

        if schema is None:
            return None
        else:
            return os.path.abspath(os.path.join(module_path, 'json', schema))
