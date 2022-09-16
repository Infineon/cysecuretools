"""
Copyright (c) 2021 Cypress Semiconductor Corporation

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
import os
import time

import cysecuretools.data.mxs40sv2.mxs40sv2_ram_app_status_codes as app_status
from cysecuretools.core.enums import ProvisioningStatus
from cysecuretools.execute.programmer.base import AP
from cysecuretools.targets.common.mxs40sv2.enums import LifecycleStage

logger = logging.getLogger(__name__)


class RamAppLoader:
    """ A class that implements loading RAM application routine """

    def __init__(self, tool, target, load_app_data, app):
        self.tool = tool
        self.target = target
        self.reg_map = target.register_map
        self.load_data = load_app_data
        self.app = app

    def load(self):
        """ Loads application and its input parameters into RAM """
        self.tool.set_ap(AP.SYS)
        time.sleep(0.2)
        self.tool.reset()

        ctrl_reg = self.tool.read32(self.reg_map.TST_DEBUG_CTL)
        if (ctrl_reg & self.load_data.TST_DBG_CTL_WFA_Msk) == 0:
            self.tool.write32(self.reg_map.TST_DEBUG_CTL,
                              self.load_data.TST_DBG_CTL_WAIT_APP_RQST)
            self.reset()
            logger.debug('Waiting until BootROM stopped '
                         'and read for application upload...')

        for func in [self.check_bootrom_readiness,
                     self.load_application,
                     self.load_input_parameters]:
            status = func()
            if status != ProvisioningStatus.OK:
                return status

        logger.debug('Clear DEBUG_IMAGE bit in SRSS_TST_DEBUG_CTL register '
                     'to start application')
        self.tool.write32(self.reg_map.TST_DEBUG_CTL, 0)
        self.tool.resume()

        return self.app_completion_status()

    def check_bootrom_readiness(self):
        """ Checks whether BootROM is ready for application programming """
        status = ProvisioningStatus.OK
        counter = 0
        while (self.tool.read32(self.reg_map.TST_DEBUG_CTL) &
               self.load_data.TST_DBG_CTL_WFA_Msk) == 0:
            counter += 1
            if counter > self.load_data.WAIT_FOR_APP_TIMEOUT:
                raise TimeoutError('BootROM did not set flag '
                                   'waiting for application')
            time.sleep(0.1)
        debug_sts = self.tool.read32(self.reg_map.TST_DEBUG_STATUS)
        if debug_sts != self.load_data.TST_DBG_STS_APP_WFA_SET:
            logger.error(
                'TST_DEBUG_STATUS: 0x%x', self.reg_map.TST_DEBUG_STATUS)
            logger.error('TST_DEBUG_CTL: 0x%x', self.reg_map.TST_DEBUG_CTL)
            logger.error('BootROM did not set expected TST_DEBUG_STATUS')
            status = ProvisioningStatus.FAIL
        else:
            logger.debug('Ready for application programming')

        return status

    def load_application(self):
        """ Programs application into RAM """
        lcs = self.target.silicon_data_reader.read_lifecycle_stage(self.tool)
        lcs = LifecycleStage(lcs).name.upper()
        if lcs in self.app.allowed_lcs:
            logger.info(
                "Programming '%s' application at address 0x%x (%s)",
                self.app.name, self.app.image_address, self.app.image_path)
            self.tool.program_ram(
                self.app.image_path, address=self.app.image_address)
            logger.info('Programming complete')
            status = ProvisioningStatus.OK
        else:
            logger.warning("Skip programming '%s' application. The device "
                           "lifecycle stage is %s", self.app.name, lcs)
            status = ProvisioningStatus.SKIPPED
        return status

    def load_input_parameters(self):
        """ Programs application input parameters """
        status = ProvisioningStatus.OK
        if self.app.in_params_path and os.path.isfile(self.app.in_params_path):
            file_size = os.path.getsize(self.app.in_params_path)
            if file_size > self.load_data.INPUT_PARAM_MIN_SIZE:
                logger.info(
                    "Programming '%s' application input parameters at address "
                    "0x%x (%s)", self.app.name, self.app.in_params_address,
                    self.app.in_params_path)
                self.tool.program_ram(self.app.in_params_path,
                                  address=self.app.in_params_address)
                logger.info('Programming complete')
            else:
                raise ValueError(f'Input parameters size must be larger then '
                                 f'{self.load_data.INPUT_PARAM_MIN_SIZE} '
                                 f'bytes ({self.app.in_params_path}')
        else:
            logger.debug('No input parameters provided, skipped')

        return status

    def app_completion_status(self):
        """ Checks application programming status """
        status = ProvisioningStatus.OK
        # Wait until debugger is connected and TST_DEBUG_STATUS is changed
        timeout = 0
        tmp_status = self.load_data.TST_DBG_STS_APP_WFA_SET
        while tmp_status == self.load_data.TST_DBG_STS_APP_WFA_SET:
            timeout += 1
            if timeout > self.load_data.WAIT_APP_END_TIMEOUT:
                raise TimeoutError('Application did not return status')
            time.sleep(0.1)
            try:
                tmp_status = self.tool.read32(self.reg_map.TST_DEBUG_STATUS)
            except RuntimeError:
                tmp_status = self.load_data.TST_DBG_STS_APP_WFA_SET

        # Wait for application completion
        while tmp_status in [self.load_data.TST_DBG_STS_APP_LAUNCHED,
                             self.load_data.TST_DBG_STS_APP_RUNNING]:
            timeout += 1
            if timeout > self.load_data.WAIT_APP_END_TIMEOUT:
                if tmp_status == self.load_data.TST_DBG_STS_APP_WFA_SET:
                    logger.error('BootROM pass control to application timeout '
                                 '(status: 0x%x)', tmp_status)
                elif tmp_status == self.load_data.TST_DBG_STS_APP_RUNNING:
                    logger.error('Application return status timeout '
                                 '(status: 0x%x)', tmp_status)
                else:
                    logger.error('Unexpected error - status 0x%x', tmp_status)
                raise TimeoutError('Application did not return status')
            time.sleep(0.1)
            tmp_status = self.tool.read32(self.reg_map.TST_DEBUG_STATUS)

        # Application completion status
        if tmp_status == self.load_data.TST_DBG_STS_APP_NOT_LAUNCHED:
            logger.error('BootROM did not launch application due to '
                         'verification failure (status: 0x%x)', tmp_status)
            status = ProvisioningStatus.FAIL
        else:
            if tmp_status == app_status.get_code_by_name('CYAPP_SUCCESS'):
                logger.info('Application execution successfully completed')
            else:
                self.print_ram_app_status(tmp_status)
                status = ProvisioningStatus.FAIL

        return status

    def reset(self):
        """ Reset device using RES_SOFT_CTL register """
        logger.debug('Reset device')
        try:
            self.tool.write32(self.reg_map.RES_SOFT_CTL,
                              self.load_data.RES_SOFT_CTL_RESET_RQST)
        except RuntimeError:
            pass  # the mww command fails so catch this fail and continue
        time.sleep(0.1)

    @staticmethod
    def print_ram_app_status(status_code, severity='error'):
        """
        Outputs RAM app status description
        :param status_code: RAM app status code
        :param severity: The severity of the status message
        """
        try:
            status, desc = app_status.get_status_by_code(status_code)
            msg = f'Application execution completed with status code: ' \
                  f'({hex(status_code)}) - {status}: {desc}'
            if severity == 'error':
                logger.error(msg)
            elif severity == 'warning':
                logger.warning(msg)
            elif severity == 'info':
                logger.info(msg)
            elif severity == 'debug':
                logger.debug(msg)
            else:
                raise ValueError('Invalid severity argument')
        except KeyError:
            logger.error(
                'Unexpected RAM app completion status 0x%x', status_code)
