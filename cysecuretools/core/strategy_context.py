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
from abc import ABC, abstractmethod


class Strategy(ABC):
    """
    The Strategy interface declares operations common to all supported versions
    of some algorithm.
    """
    @abstractmethod
    def create_certificate(self, cert_name, cert_encoding, **kwargs):
        pass

    @abstractmethod
    def default_certificate_data(self, tool, target, protection_state, probe_id):
        pass


class Context:
    """
    The Context defines the interface of interest to clients.
    """
    def __init__(self, strategy: Strategy):
        self._strategy = strategy

    @property
    def strategy(self) -> Strategy:
        """
        The Context maintains a reference to one of the Strategy objects.
        """
        return self._strategy

    @strategy.setter
    def strategy(self, strategy: Strategy):
        """
        Allows replacing a Strategy object at runtime.
        """
        self._strategy = strategy

    def create_certificate(self, cert_name, cert_encoding, **kwargs):
        """
        Delegates work to the Strategy object.
        """
        self._strategy.create_certificate(cert_name, cert_encoding, **kwargs)

    def default_certificate_data(self, tool, target, protection_state, probe_id):
        """
        Delegates work to the Strategy object.
        """
        return self._strategy.default_certificate_data(tool, target, protection_state, probe_id)
