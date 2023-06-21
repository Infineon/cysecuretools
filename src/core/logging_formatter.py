"""
Copyright (c) 2019-2021 Cypress Semiconductor Corporation

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
import logging

from ..__about__ import __pkg_name__, __pkg_short_name__


class CustomFormatter(logging.Formatter):
    error_fmt = '%(asctime)s : ##_package_## : ERROR : %(message)s'
    debug_fmt = '%(asctime)s : ##_package_## : DEBUG : %(name)s, line %(lineno)d: %(message)s'
    warning_fmt = '%(asctime)s : ##_package_## : WARN  : %(message)s'
    info_fmt = '%(asctime)s : ##_package_## : INFO  : %(message)s'

    def __init__(self):
        super().__init__(fmt="%(levelno)d: %(msg)s", datefmt=None, style='%')
        self.style = self._style = CustomPercentStyle()
        self.original_format = self.style.fmt
        self.package_name = __pkg_name__.lower()

    def format(self, record):
        if record.levelno == logging.DEBUG:
            self.style.fmt = CustomFormatter.debug_fmt

        elif record.levelno == logging.INFO:
            self.style.fmt = CustomFormatter.info_fmt

        elif record.levelno == logging.WARNING:
            self.style.fmt = CustomFormatter.warning_fmt

        elif record.levelno == logging.ERROR:
            self.style.fmt = CustomFormatter.error_fmt

        if 'openocd' in record.name:
            package = 'O'
        elif record.name.startswith(self.package_name):
            package = __pkg_short_name__
            if record.levelno == logging.ERROR:
                self.style.fmt += '. Check the log for details'
        else:
            package = ' '

        self.style.fmt = self.style.fmt.replace('##_package_##', package)

        result = logging.Formatter.format(self, record)

        self.style.fmt = self.original_format

        return result


class CustomPercentStyle(logging.PercentStyle):
    def __init__(self, fmt=None):
        super().__init__(fmt)

    @property
    def fmt(self):
        return self._fmt

    @fmt.setter
    def fmt(self, fmt):
        self._fmt = fmt
