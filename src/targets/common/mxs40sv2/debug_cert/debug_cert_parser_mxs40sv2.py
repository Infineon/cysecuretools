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
import json
import struct
from enum import Enum


class DebugCertificateParserMXS40Sv2:

    ControlWordBit = Enum(
        value='ControlWord',
        names=[
            ('Disable', 0),
            ('Enable', 1)
        ]
    )

    def parse_template(self, template):
        json_cert = {
            'version': self.parse_version(template),
            'device_id': self.parse_device_id(template),
            'control_word': self.parse_control_word(template),
            'die_id_min': self.parse_die_id(template, 'min'),
            'die_id_max': self.parse_die_id(template, 'max')
        }
        return json_cert

    def get_cm33_ap_permission(self, template):
        try:
            value = template['control_word']['cm33_ap']
            return self.ControlWordBit[value]
        except KeyError:
            return self.ControlWordBit.Disable

    def get_sys_ap_permission(self, template):
        try:
            value = template['control_word']['sys_ap']
            return self.ControlWordBit[value]
        except KeyError:
            return self.ControlWordBit.Disable

    def get_rma_permission(self, template):
        try:
            value = template['control_word']['rma']
            return self.ControlWordBit[value]
        except KeyError:
            return self.ControlWordBit.Disable

    def get_cm33_dbg_permission(self, template):
        try:
            value = template["control_word"]["cm33_dbg"]
            return self.ControlWordBit[value]
        except KeyError:
            return self.ControlWordBit.Disable

    def get_cm33_nid_permission(self, template):
        try:
            value = template["control_word"]["cm33_nid"]
            return self.ControlWordBit[value]
        except KeyError:
            return self.ControlWordBit.Disable

    @staticmethod
    def load_template(path):
        with open(path, 'r', encoding='utf-8') as f:
            template = json.loads(f.read())
        return template

    @staticmethod
    def parse_version(template):
        version = [int(i) for i in template['version'].split('.')]
        version = version[:4]
        version.reverse()
        return struct.pack('<BBBB', *version)

    @staticmethod
    def parse_device_id(template):
        silicon_id = int(template['device_id']['silicon_id'], 16)
        family_id = int(template['device_id']['family_id'], 16)
        revision_id = int(template['device_id']['revision_id'], 16)
        silicon_id = family_id << 16 | silicon_id
        return struct.pack('<LL', silicon_id, revision_id)

    def parse_control_word(self, template):
        cm33_ap = self.get_cm33_ap_permission(template).value
        sys_ap = self.get_sys_ap_permission(template).value
        rma = self.get_rma_permission(template).value
        cm33_dbg = self.get_cm33_dbg_permission(template).value
        cm33_nid = self.get_cm33_nid_permission(template).value
        control_word = (rma << 31) | (sys_ap << 2) | (cm33_ap << 0) | \
                       (cm33_dbg << 3) | (cm33_nid << 4)
        return struct.pack('<I', control_word)

    @staticmethod
    def parse_die_id(template, limit):
        die_id = struct.pack('<BBB',
                             template['die_id'][limit]['year'],
                             template['die_id'][limit]['month'],
                             template['die_id'][limit]['day'])

        lot = struct.pack('>L', template['die_id'][limit]['lot'])
        die_id += lot[1:4]

        die_id += struct.pack('<BBBB',
                              template['die_id'][limit]['wafer'],
                              template['die_id'][limit]['ypos'],
                              template['die_id'][limit]['xpos'],
                              template['die_id'][limit]['sort'])
        return die_id
