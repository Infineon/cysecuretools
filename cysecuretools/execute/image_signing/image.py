"""
Copyright (c) 2022 Cypress Semiconductor Corporation

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
import pathlib
import struct
from typing import List
from intelhex import IntelHex

import cysecuretools.execute.imgtool.image as img


class TLV:
    """Class for storing TLV object"""

    def __init__(self, tag, value):
        self.tag = tag
        self.length = len(value)
        self.value = value

    def tlv_bytes(self, endian='little'):
        """Gets TLV bytes"""
        tlv_bytes = b''
        tlv_bytes += self.tag.to_bytes(2, byteorder=endian)
        tlv_bytes += self.length.to_bytes(2, byteorder=endian)
        tlv_bytes += self.value
        return tlv_bytes


class Image:
    """A representation of the MCUboot image"""
    def __init__(self, image_path, endian='little'):
        self.image_path = image_path
        self._data = b''
        self.header = b''
        self.body = b''
        self._protected_tlv = []
        self._tlv = []
        self.trailer = b''
        self.protected_tlv_length = 0
        self.tlv_length = 0
        self.endian = endian
        self.header_size = 0
        self.body_size = 0
        self.magic = 0
        self._load()

    @property
    def has_metadata(self):
        """Indicates whether this is MCUboot format image"""
        return self.magic == img.IMAGE_MAGIC

    @property
    def is_signed(self):
        """Indicates whether the image has been already signed"""
        for tlv in self._tlv:
            if tlv.tag in [img.TLV_VALUES['RSA2048'],
                           img.TLV_VALUES['ECDSA256']]:
                return True
        return False

    @property
    def tlv(self) -> List[TLV]:
        """Gets list of unprotected TLVs"""
        return self._tlv

    @property
    def protected_tlv(self) -> List[TLV]:
        """Gets list of protected TLVs"""
        return self._protected_tlv

    @property
    def tlv_bytes(self):
        """Gets unprotected TLVs bytes"""
        tlv_bytes = b''
        tlv_bytes += img.TLV_INFO_MAGIC.to_bytes(2, byteorder=self.endian)
        tlv_bytes += self.tlv_length.to_bytes(2, byteorder=self.endian)
        for tlv in self._tlv:
            tlv_bytes += tlv.tlv_bytes(endian=self.endian)
        return tlv_bytes

    @property
    def protected_tlv_bytes(self):
        """Gets protected TLVs bytes"""
        tlv_bytes = b''
        tlv_bytes += img.TLV_PROT_INFO_MAGIC.to_bytes(2, byteorder=self.endian)
        tlv_bytes += self.protected_tlv_length.to_bytes(
            2, byteorder=self.endian)
        for tlv in self._protected_tlv:
            tlv_bytes += tlv.tlv_bytes(endian=self.endian)
        return tlv_bytes

    def add_tlv(self, tlv: TLV):
        """Adds unprotected TLV to image"""
        self._tlv.append(tlv)
        self.tlv_length += img.TLV_INFO_SIZE + tlv.length

    def remove_tlv(self, tag):
        """Removes unprotected TLV"""
        for tlv in self._tlv:
            if tlv.tag == tag:
                self._tlv.remove(tlv)
                self.tlv_length -= img.TLV_INFO_SIZE + tlv.length
                break

    def add_protected_tlv(self, tlv: TLV):
        """Adds protected TLV to image"""
        self._protected_tlv.append(tlv)
        self.protected_tlv_length += img.TLV_INFO_SIZE + tlv.length

    @property
    def payload(self):
        """Gets a part of the image that has to be signed"""
        return self.header + self.body + self.protected_tlv_bytes

    @property
    def data(self):
        """Gets image bytes"""
        return self.payload + self.tlv_bytes + self.trailer

    def is_upgrade(self):
        """Checks whether the image is for the upgrade slot"""
        upgrade_img_magic = [0x77, 0xC2, 0x95, 0xF3, 0x60, 0xD2, 0xEF, 0x7F,
                             0x35, 0x52, 0x50, 0x0F, 0x2C, 0xB6, 0x79, 0x80]
        data_index = len(self.data) - 1
        for magic_byte in reversed(upgrade_img_magic):
            if self.data[data_index] == magic_byte:
                data_index -= 1
            else:
                return False
        return True

    def _load(self):
        ext = pathlib.Path(self.image_path).suffix
        if ext == ".hex":
            ih = IntelHex(self.image_path)
            self._data = ih.tobinarray()
        else:
            with open(self.image_path, 'rb') as f:
                self._data = f.read()
        self._decompose()

    def _decompose(self):
        """Decomposes image into header, body, protected, and
        unprotected TLVs
        """
        self.magic, _, self.header_size, _, self.body_size = struct.unpack(
            img.STRUCT_ENDIAN_DICT[self.endian] + 'IIHHI', self._data[:16])

        if self.has_metadata:
            self.header = self._data[:self.header_size]
            self.body = self._data[
                        self.header_size:self.body_size + self.header_size]

            tlv_offset = self.header_size + self.body_size

            tlv_info = self._data[tlv_offset:tlv_offset + img.TLV_INFO_SIZE]
            tlv_magic, self.protected_tlv_length = struct.unpack(
                img.STRUCT_ENDIAN_DICT[self.endian] + 'HH', tlv_info)

            if tlv_magic == img.TLV_PROT_INFO_MAGIC:
                tlv_offset += img.TLV_INFO_SIZE
                self._protected_tlv = self._get_tlv(
                    tlv_offset, self.protected_tlv_length - img.TLV_INFO_SIZE)
                tlv_offset += self.protected_tlv_length - img.TLV_INFO_SIZE

            tlv_info = self._data[tlv_offset:tlv_offset + img.TLV_INFO_SIZE]
            tlv_magic, self.tlv_length = struct.unpack(
                img.STRUCT_ENDIAN_DICT[self.endian] + 'HH', tlv_info)

            if tlv_magic == img.TLV_INFO_MAGIC:
                tlv_offset += img.TLV_INFO_SIZE
                self._tlv = self._get_tlv(
                    tlv_offset, self.tlv_length - img.TLV_INFO_SIZE)

            tlv_offset += self.tlv_length - img.TLV_INFO_SIZE
            self.trailer = self._data[tlv_offset:]

    def _get_tlv(self, start_addr, length) -> List[TLV]:
        """Parses image and adds TLVs into array
        @param start_addr: An address of the first TLV in the payload
        @param length: Total length of all TLVs
        @return: An array of TLV objects
        """
        tlv_info = []
        tlv_end = start_addr + length
        while start_addr < tlv_end:
            tlv = self._data[start_addr:start_addr + img.TLV_SIZE]
            tlv_tag, tlv_length = struct.unpack(
                img.STRUCT_ENDIAN_DICT[self.endian] + 'HH', tlv)
            start_addr += img.TLV_INFO_SIZE
            tlv_value = self._data[start_addr:start_addr + tlv_length]
            tlv_obj = TLV(tlv_tag, tlv_value)
            tlv_info.append(tlv_obj)
            start_addr += tlv_length
        return tlv_info
