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
import os
import logging
from datetime import datetime

from .project_base import ProjectInitializerBase
from .logging_formatter import CustomFormatter

logger = logging.getLogger(__name__)


class LoggingConfigurator:
    """
    The class that allows configuring the way how the data is logged
    """

    LOG_FORMATTER = CustomFormatter()

    @staticmethod
    def disable_logging():
        """Disable all logging calls of severity 'CRITICAL' and below"""
        logging.disable(logging.CRITICAL)

    @staticmethod
    def enable_logging():
        """Restore disabled logging"""
        logging.disable(logging.NOTSET)

    @staticmethod
    def set_logger_level(level):
        """
        Sets logging level (ERROR, WARNING, INFO, DEBUG)
        """
        root_logger = logging.getLogger()
        root_logger.setLevel(level)
        for handler in root_logger.handlers:
            if isinstance(handler, type(logging.StreamHandler())):
                handler.setLevel(level)

    @staticmethod
    def add_file_logging():
        """
        Adds file logger
        """
        prefix = LoggingConfigurator.LOG_FORMATTER.package_name
        log_filename = datetime.now().strftime(os.path.join(
            LoggingConfigurator.get_log_dir(),
            f'{prefix}_%Y-%m-%d_%H-%M-%S.log'))
        os.makedirs(os.path.dirname(log_filename), exist_ok=True)
        file_handler = logging.FileHandler(log_filename, mode='w+')
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(LoggingConfigurator.LOG_FORMATTER)
        logger.root.addHandler(file_handler)

    @staticmethod
    def get_log_dir():
        if ProjectInitializerBase.is_project():
            cwd = os.path.join(os.getcwd(), 'logs')
        else:
            cwd = os.path.abspath(
                os.path.join(os.path.dirname(__file__), '..', 'logs'))
        return cwd
