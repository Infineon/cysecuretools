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
from cysecuretools.targets.cy8cproto_064s1_sb.target_builder import CY8CPROTO_064S1_SB_Builder
from cysecuretools.targets.cy8cproto_064s2_sb.target_builder import CY8CPROTO_064S2_SB_Builder
from cysecuretools.targets.cyb06xx5.target_builder import CYB06xx5_Builder
from cysecuretools.targets.cy8ckit_064x0s2_4343w.target_builder import CY8CKIT_064X0S2_4343W_Builder

target_map = {
    'cy8cproto-064s1-sb':            CY8CPROTO_064S1_SB_Builder,
    'cy8cproto-064b0s1-ble':         CY8CPROTO_064S1_SB_Builder,

    'cy8cproto-064s2-sb':            CY8CPROTO_064S2_SB_Builder,
    'cy8ckit-064b0s2-4343w':         CY8CKIT_064X0S2_4343W_Builder,
    'cy8ckit-064s0s2-4343w':         CY8CKIT_064X0S2_4343W_Builder,

    'cyb06445lqi-s3d42':             CYB06xx5_Builder,
    'cy8cproto-064b0s3':             CYB06xx5_Builder,
    'cyb06xx5':                      CYB06xx5_Builder,
}

