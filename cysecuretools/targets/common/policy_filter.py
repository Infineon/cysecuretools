"""
Copyright (c) 2019 Cypress Semiconductor Corporation

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
import errno
import json
from cysecuretools.core import PolicyFilterBase


class PolicyFilter(PolicyFilterBase):
    def __init__(self, policy_parser, policy_template='json/policy_template.json'):
        """
        Creates instance of policy filter.
        :param policy_parser: Specific parser for the policy.
        :param policy_template: Specific template that represents output policy file.
        """
        self.json_data = policy_parser.json
        self.policy_template = policy_template

    def filter_policy(self):
        """
        From aggregated policy file and creates policy file that contains information for provisioning only.
        :return: Path to the filtered policy file.
        """
        sdk_path = os.path.dirname(os.path.realpath(__file__))

        if not os.path.isabs(self.policy_template):
            policy_template = os.path.join(sdk_path, self.policy_template)

        with open(policy_template) as f:
            file_content = f.read()
            json_template = json.loads(file_content)

        self.parse_node(self.json_data, json_template)
        filtered_policy = os.path.join(sdk_path, 'json/filtered.json')

        if not os.path.exists(os.path.dirname(filtered_policy)):
            try:
                os.makedirs(os.path.dirname(filtered_policy))
            except OSError as exc:  # Guard against race condition
                if exc.errno != errno.EEXIST:
                    raise

        with open(filtered_policy, 'w') as fp:
            json.dump(json_template, fp, indent=4)
        return filtered_policy

    def parse_node(self, data, template):
        """
        Recursive function that copies JSON data from the data dictionary to the template dictionary.
        :param data: Dictionary that contains data to copy.
        :param template: Dictionary, which is template that contains placeholders where to copy the data.
        """
        for t_key, t_value in template.items():
            for d_key, d_value in data.items():
                if d_key == t_key:
                    if isinstance(d_value, list):                 # process list
                        d_i = 0
                        t_i = 0
                        for t_elem in t_value:
                            if len(d_value) > d_i:
                                d_elem = d_value[d_i]
                                if not isinstance(d_elem, dict):  # process values in the list
                                    if t_i == d_i:
                                        t_value[t_i] = d_elem
                                        break
                                else:                             # process dictionary in the list
                                    self.parse_node(d_elem, t_elem)
                            else:
                                del t_value[t_i]
                            d_i += 1
                            t_i += 1
                    elif not isinstance(d_value, dict):           # process values in the dictionary
                        template[t_key] = d_value
                        break
                    else:                                         # process dictionary
                        self.parse_node(d_value, t_value)
