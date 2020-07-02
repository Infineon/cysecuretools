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
import json
import os
from cysecuretools.execute.key_reader import load_key


# Cypress Entity
class Entity:
    def __init__(self, state_name, audit_name):
        self.state = {}
        self.state_name = state_name
        self.state_loaded = False
        self.audit_name = audit_name
        Entity.load_state(self)

    def load_state(self):
        if os.path.exists(self.state_name):
            priv_key, pub_key = load_key(self.state_name)
            if priv_key:
                self.state['custom_priv_key'] = priv_key
            if pub_key:
                self.state['custom_pub_key'] = pub_key
        else:
            self.state = {}
            self.state_loaded = False

    def save_state(self):
        if not self.state_loaded:
            raise Exception("Internal error - state not loaded")
        with open(self.state_name, "w") as f:
            f.write(json.dumps(self.state, indent=4))
            f.close()

    def append_audit_record(self, record):
        with open(self.audit_name, "a") as f:
            f.write(json.dumps(record, indent=4) + "\n")
            f.close()
