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
from cysecuretools.execute.provisioning_lib.cyprov_crypto import Crypto


class SiliconDataParser:
    @property
    def jwt(self):
        return self._jwt

    @jwt.setter
    def jwt(self, jwt):
        self._jwt = jwt

    @property
    def data(self):
        if self._data is None:
            self._data = Crypto.readable_jwt(self.jwt)
        return self._data

    def __init__(self, jwt=None):
        self._jwt = jwt
        self._data = Crypto.readable_jwt(jwt) if jwt is not None else None

    def get_die_id(self):
        return self.data['payload']['die_id']

    def get_serial(self):
        die_id = self.get_die_id()
        concat = ''.join(str(x) for x in die_id.values())
        return concat
