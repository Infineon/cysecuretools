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


class LoadAppData:
    WAIT_FOR_APP_TIMEOUT = 200
    WAIT_APP_END_TIMEOUT = 200
    CYAPP_STATE_FINISHED = 2
    INPUT_PARAM_MIN_SIZE = 8

    RES_SOFT_CTL_RESET_RQST = 0x00000001
    TST_DBG_CTL_WAIT_APP_RQST = 0x00000001
    TST_DBG_CTL_WFA_Msk = 0x80000000

    TST_DBG_STS_APP_WFA_SET = 0x0D500080
    TST_DBG_STS_APP_LAUNCHED = 0x0D500081
    TST_DBG_STS_APP_NOT_LAUNCHED = 0x0D500082
    TST_DBG_STS_APP_RUNNING = 0xF2A00010
