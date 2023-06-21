"""
Copyright 2020-2022 Cypress Semiconductor Corporation (an Infineon company)
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


class DependenciesValidatorRunner:
    """Runs over the dependency validators list and validates
    policy dependencies
    """

    def __init__(self, policy_parser, validators):
        self.policy_parser = policy_parser
        self.validators = validators

    def validate(self, skip_list, **_kwargs):
        """ Validates dependencies and returns list of messages """
        is_valid = True
        messages = []
        for k, v in self.validators.items():
            if skip_list is not None and k in skip_list:
                continue
            for item in v:
                validator = item(self.policy_parser)
                validator.validate()
                if not validator.is_valid:
                    is_valid = False
                if validator.messages:
                    messages.extend(validator.messages)
        return is_valid, messages
