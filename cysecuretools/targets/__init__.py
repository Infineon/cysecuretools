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

target_map = {
    'cy8cproto-064s1-sb':        CY8CPROTO_064S1_SB_Builder,
    'cy8cproto-064s1-sb_virgin': CY8CPROTO_064S1_SB_Builder,

    'cy8cproto-064s2-sb':        CY8CPROTO_064S2_SB_Builder,
    'cy8cproto-064s2-sb_virgin': CY8CPROTO_064S2_SB_Builder,
}

