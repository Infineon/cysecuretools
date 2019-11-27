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
import os
import json
from enum import Enum
from pathlib import Path
from cysecuretools.core import PolicyParserBase


class PolicyParser(PolicyParserBase):
    """
    Provides functionality for searching data in cysecuretools policy.
    """
    def __init__(self, policy_file):
        """
        Creates instance of policy parser.
        :param policy_file: Path to policy file.
        """
        self.json = self.get_json(policy_file)
        self.policy_dir = os.path.dirname(Path(policy_file).absolute())

    @staticmethod
    def get_json(filename):
        """
        Gets JSON file as a dictionary.
        :param filename: The JSON file.
        :return: JSON file as a dictionary.
        """
        with open(filename) as f:
            file_content = f.read()
            data = json.loads(file_content)
        return data

    def get_keys(self, out=None):
        """
        Gets keys id and filename specified in the policy file.
        :return: List of pairs id-filename.
        """
        keys = []
        for node in self.json['boot_upgrade']['firmware']:
            # Look for boot keys
            if 'boot_keys' in node:
                for item in node['boot_keys']:
                    key = KeyData(item['kid'], item['key'], KeyType.signing, ImageType.BOOT)
                    if key.key_id is not None and key.json_key_path is not None:
                        keys.append(key)

            # Look for upgrade keys
            if 'upgrade_keys' in node:
                for item in node['upgrade_keys']:
                    key = KeyData(item['kid'], item['key'], KeyType.signing, ImageType.UPGRADE)
                    if key.key_id is not None and key.json_key_path is not None:
                        keys.append(key)

            # Look for encryption key
            encrypt = False
            key = KeyData(key_type=KeyType.encryption)
            if 'encrypt' in node:
                encrypt = node['encrypt']
            if 'encrypt_key_id' in node:
                key.key_id = node['encrypt_key_id']
            if 'encrypt_key' in node:
                key.json_key_path = node['encrypt_key']
            if encrypt and key.key_id is not None and key.json_key_path is not None:
                keys.append(key)

            # Look for device public key
            if 'encrypt_peer' in node:
                pub_key = KeyData(key_type=KeyType.device_public, pem_key_path=node['encrypt_peer'])
                pub_key.json_key_path = "{0}.json".format(*os.path.splitext(pub_key.pem_key_path))
                keys.append(pub_key)

        # Resolve keys path
        keys_dir = self.policy_dir if out is None else out
        for pair in keys:
            if out:
                if pair.json_key_path is not None:
                    pair.json_key_path = os.path.basename(pair.json_key_path)
                if pair.pem_key_path is not None:
                    pair.pem_key_path = os.path.basename(pair.pem_key_path)

            if pair.json_key_path is not None and not os.path.isabs(pair.json_key_path):
                pair.json_key_path = os.path.join(keys_dir, pair.json_key_path)
            if pair.pem_key_path is not None and not os.path.isabs(pair.pem_key_path):
                pair.pem_key_path = os.path.join(keys_dir, pair.pem_key_path)

        return keys

    def get_image_data(self, image_id, image_type):
        """
        Gets specified image data.
        :param image_id: The image ID.
        :param image_type: The image type.
        :return: Image address, image size.
        """
        for slot in self.json["boot_upgrade"]["firmware"]:
            if slot['id'] == image_id:
                for res in slot['resources']:
                    if res['type'] == image_type:
                        address = res['address']
                        size = res['size']
                        return address, size
        return None, None

    def get_slot(self, slot_id):
        """
        Gets a slot with specified id.
        :param slot_id: The slot ID.
        :return: Dictionary, which represents the slot data.
        """
        for slot in self.json["boot_upgrade"]["firmware"]:
            if slot['id'] == slot_id:
                return slot

    def get_cybootloader_mode(self):
        """
        Gets mode of CyBootloader specified in the policy file.
        :return: release or debug
        """
        return self.json['cy_bootloader']['mode']

    def get_cybootloader_hex(self):
        """
        Gets hex-file of CyBootloader specified in the policy file.
        :return: release or debug
        """
        path = self.json['cy_bootloader']['hex_path']
        if not os.path.isabs(path):
            path = os.path.join(self.policy_dir, path)
        return path

    def get_cybootloader_jwt(self):
        """
        Gets jwt-file of CyBootloader specified in the policy file.
        :return: release or debug
        """
        path = self.json['cy_bootloader']['jwt_path']
        if not os.path.isabs(path):
            path = os.path.join(self.policy_dir, path)
        return path

    def get_provisioning_packet_dir(self):
        """
        Gets path of the provisioning packet specified in the policy file.
        :return: File path.
        """
        packet_dir = self.json['provisioning']['packet_dir']
        if not os.path.isabs(packet_dir):
            packet_dir = os.path.join(self.policy_dir, packet_dir)
        return packet_dir

    def get_chain_of_trust(self):
        """
        Gets certificates paths specified in the policy file.
        :return: List of certificate paths.
        """
        try:
            certs = self.json['provisioning']['chain_of_trust']
            certs = [os.path.join(self.policy_dir, path) if not os.path.isabs(path) else path for path in certs]
        except KeyError:
            certs = []
        return certs


class KeyData:
    """
    Represents structure for key data.
    """
    def __init__(self, key_id=None, json_key_path=None, key_type=None, image_type=None, pem_key_path=None):
        self.key_id = key_id
        self.key_type = key_type
        self.image_type = image_type

        self.json_key_path = json_key_path
        if pem_key_path is None and self.json_key_path is not None:
            self.pem_key_path = "{0}_PRIV.pem".format(*os.path.splitext(json_key_path))
        else:
            self.pem_key_path = pem_key_path


class KeyType(Enum):
    """
    Available key types.
    """
    signing, encryption, device_public = range(3)


class ImageType(Enum):
    """
    Available image types.
    """
    BOOT = 'BOOT'
    UPGRADE = 'UPGRADE'
