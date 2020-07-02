"""
Copyright (c) 2019-2020 Cypress Semiconductor Corporation

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


class CustomFormatter(logging.Formatter):
    error_fmt = '%(asctime)s : ##_package_## : ERROR : %(message)s'
    debug_fmt = '%(asctime)s : ##_package_## : DEBUG : %(name)s, line %(lineno)d: %(message)s'
    warning_fmt = '%(asctime)s : ##_package_## : WARN  : %(message)s'
    info_fmt = '%(asctime)s : ##_package_## : INFO  : %(message)s'

    def __init__(self):
        super().__init__(fmt="%(levelno)d: %(msg)s", datefmt=None, style='%')

    def format(self, record):
        # Save the original format
        format_orig = self._style._fmt

        # Replace the original format with custom
        if record.levelno == logging.DEBUG:
            self._style._fmt = CustomFormatter.debug_fmt

        elif record.levelno == logging.INFO:
            self._style._fmt = CustomFormatter.info_fmt

        elif record.levelno == logging.WARNING:
            self._style._fmt = CustomFormatter.warning_fmt

        elif record.levelno == logging.ERROR:
            self._style._fmt = CustomFormatter.error_fmt

        if record.name.startswith('pyocd'):
            package = 'P'
        elif record.name.startswith('cysecuretools'):
            package = 'C'
            if record.levelno == logging.ERROR:
                self._style._fmt += \
                    '. Check the log for details'
        else:
            package = ' '

        self._style._fmt = self._style._fmt.replace('##_package_##', package)

        result = logging.Formatter.format(self, record)

        # Restore the original format
        self._style._fmt = format_orig

        return result
