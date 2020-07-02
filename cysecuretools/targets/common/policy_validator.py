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
import jsonschema
import logging
import json
import os.path
from cysecuretools.targets.common.policy_parser import ImageType
from cysecuretools.core import PolicyValidatorBase
from collections import namedtuple
from cysecuretools.execute.key_reader import load_key

MODULE_PATH = os.path.dirname(os.path.realpath(__file__))
POLICY_SCHEMA = os.path.join(MODULE_PATH, 'json', 'schema.json_schema')

logger = logging.getLogger(__name__)


class PolicyValidator(PolicyValidatorBase):
    """
    Validates policy file against JSON schema. Validates values in the file.
    """
    def __init__(self, policy_parser, memory_map):
        """
        Creates instance of policy validator.
        :param policy_parser: Specific parser for the policy.
        :param memory_map: Device memory map.
        """
        self.parser = policy_parser
        self.memory_map = memory_map
        self.policy_dir = self.parser.policy_dir
        self.stage = self.get_policy_stage()

    def validate(self, skip=None):
        """
        Validation of policy.json.
        :return True if validation succeeds, otherwise False.
        """
        skip_list = skip if skip else []
        # First stage validation
        with open(POLICY_SCHEMA) as f:
            file_content = f.read()
            json_schema = json.loads(file_content)

        try:
            jsonschema.validate(self.parser.json, json_schema)
        except (jsonschema.exceptions.ValidationError,
                jsonschema.exceptions.SchemaError) as e:
            logger.error('Validation against schema failed')
            logger.error(e)
            return False
        logger.debug('First stage validation success')

        # Second stage validation
        is_multi_image = self.is_multi_image()
        logger.debug('Validating firmware slots overlapping')
        result = self.validate_address_overlap(slot_overlaps=is_multi_image)
        if not result:
            return result

        for slot in self.parser.json['boot_upgrade']['firmware'][1:]:
            boot_auth = slot['boot_auth'][0]
            boot_keys = slot['boot_keys'][0]
            logger.debug('Validating boot_auth id matches kid in JSON key file')
            result = self.key_id_validation(boot_auth, boot_keys)
            if not result:
                return result

        logger.debug('Validating there is no different JWKs with the same key ID')
        result = self.key_name_validation()
        if not result:
            return result

        if self.stage == 'multi':
            logger.debug('Validating multi-image IDs')
            result = self.validate_multi_image_id()
            if not result:
                return result

            logger.debug('Validating multi-image smif_id')
            result = self.validate_multi_image_smif_id()
            if not result:
                return result

        if self.stage != 'multi':
            logger.debug('Validating whether image ID corresponds to '
                         'CyBootloader launch ID')
            result = self.image_launch_validation()
            if not result:
                return result

        logger.debug('Validating policy for BOOT sections, encryption and SMIF')
        result = self.check_slots()
        if not result:
            return result

        logger.debug('Validating CyBootloader paths')
        result = self.validate_cybootloader_paths()
        if not result:
            return result

        logger.debug('Check aligning to Memory map')
        result = self.memory_map_align()
        if not result:
            return result

        if 'pre_build' not in skip_list:
            logger.debug('Checking integrity of pre-build section')
            result = self.validate_prebuild_section()

        logger.debug('Second stage validation success')
        return result

    def key_id_validation(self, auth, keys):
        """
        Validates keys ID in policy.
        :param auth: Auth ID from policy.
        :param keys: Key ID from policy.
        :return True if validation succeeds, otherwise False.
        """
        key_file = os.path.join(self.policy_dir, keys['key'])
        if os.path.exists(key_file):
            priv, pub = load_key(key_file)

            if priv:
                key_kid = priv['kid']
            elif pub:
                key_kid = pub['kid']
            else:
                key_kid = '-1'

            key_kid = int(key_kid)
            boot_key_kid = int(keys['kid'])

            if not key_kid == auth:
                logger.error(f'ID:"{auth}" NOT equals to kid:"{key_kid}" in JSON key file')
                return False
            if not boot_key_kid == auth:
                logger.error(f'ID:"{auth}" NOT equals to kid:"{boot_key_kid}" in JSON key file')
                return False
        else:
            logger.debug(f'Key file "{key_file}" does not exist')
        return True

    def key_name_validation(self):
        """
        Validates whether there are no key entities with same ID,
        but different filename.
        :return: True if no entities with same ID, but different filename
        found, otherwise False.
        """
        # Create dictionary with key ID and paths
        keys = {}
        for slot in self.parser.json['boot_upgrade']['firmware']:
            for key_type in ['boot_keys', 'upgrade_keys']:
                if key_type in slot:
                    for item in slot[key_type]:
                        try:
                            keys[item['kid']].append(os.path.abspath(item['key']))
                        except KeyError:
                            keys[item['kid']] = [os.path.abspath(item['key'])]

        # Check whether there is a key with same ID, but different path
        for key_list in keys.values():
            if len(set(key_list)) > 1:
                logger.error('JWK entities with same key ID, but different '
                             'file names found')
                return False

        # Check whether same key ID is not used for the different file name
        for k1, v1 in keys.items():
            for k2, v2 in keys.items():
                if k1 != k2:
                    if any(elem in v1 for elem in v2):
                        logger.error('JWK entities with different key IDs, '
                                     'but same file name found')
                        return False

        return True

    def image_launch_validation(self):
        """
        Validates link from the first slot to the next to run image.
        :return True if validation succeeds, otherwise False.
        """
        launch = self.parser.json['boot_upgrade']['firmware'][0]['launch']
        image_id = self.parser.json['boot_upgrade']['firmware'][1]['id']

        if launch != image_id:
            if launch != self.memory_map.SPE_IMAGE_ID:
                logger.error(f'Image ID = {image_id} does not correspond to '
                             f'CyBootloader launch ID = {launch}')
                return False
            else:
                logger.debug(f'NSPE image ID = {image_id}. It will be '
                             f'launched by SPE part.')
        return True

    def check_slots(self):
        """
        Validates types of images, availability of UPGRADE image,
        availability of SMIF
        :return: True if validation passed, otherwise False.
        """
        slot0 = None
        slot1 = None

        if self.stage == 'dual':

            cm4_slot = self.parser.json['boot_upgrade']['firmware'][2]
            cm0_slot = self.parser.json['boot_upgrade']['firmware'][1]

            img_id = cm0_slot['id']

            # check dual stage scheme
            if img_id != self.memory_map.SPE_IMAGE_ID:
                logger.error(f'SPE Image ID = {str(img_id)} is not equal to 1!')
                return False

            if not (self.parser.json['boot_upgrade']['firmware'][0]['launch'] == img_id):
                logger.error(f'Image ID = {str(img_id)} does not correspond '
                             f'to CyBootloader launch ID = {str(self.parser.json["boot_upgrade"]["firmware"][0]["launch"])}')
                return False

            if not (cm0_slot['launch'] == cm4_slot['id']):
                logger.error(f'NSPE image ID = {str(cm4_slot["id"])} does not '
                             f'correspond SPE launch_ID = {str(cm0_slot["launch"])}')
                return False

            # check slots addresses and sizes if upgrade is set to True
            for slot in cm0_slot['resources']:
                if slot['type'] == ImageType.BOOT.name:
                    slot0 = slot
                if cm0_slot['upgrade']:
                    if slot['type'] == ImageType.UPGRADE.name:
                        slot1 = slot
                        smif_id = cm0_slot['smif_id']

                        if 'encrypt' in cm0_slot and cm0_slot['encrypt']:
                            # mark slot1 image as one, that should be encrypted
                            slot1.update({'encrypt': True})
                            logger.debug('Image for UPGRADE SPE will be encrypted per policy settings.')
                else:
                    logger.debug('Upgrade is disabled. Image for UPGRADE will not be generated per policy settings.')
                    break

            slots = [2]
        else:
            slots = [1]
        if self.stage == 'multi':
            slots.append(2)

        for slot_idx in slots:
            slot0 = None
            slot1 = None
            for slot in self.parser.json['boot_upgrade']['firmware'][slot_idx]['resources']:
                if slot['type'] == ImageType.BOOT.name:
                    slot0 = slot

                if self.parser.json['boot_upgrade']['firmware'][slot_idx]['upgrade']:
                    slot1 = slot
                    smif_id = self.parser.json['boot_upgrade']['firmware'][slot_idx]['smif_id']
                    if slot['type'] == ImageType.UPGRADE.name:
                        try:
                            if self.parser.json['boot_upgrade']['firmware'][slot_idx]['encrypt']:
                                # mark slot1 image as one, that should be encrypted
                                slot1.update({'encrypt': True})
                        except KeyError:
                            None
                else:
                    logger.debug('UPGRADE image will not be generated per policy settings.')
                    break

            if slot0 is None:
                logger.error('BOOT section was not found in policy resources.')
                return False

            if slot1:
                if smif_id == 0:
                    if slot1['address'] >= self.memory_map.SMIF_MEM_MAP_START:
                        logger.error(f'Slot 1 address = {hex(slot1["address"])}, '
                                     f'but SMIF is not initialized (smif_id = 0). '
                                     f'UPGRADE image will not be generated')
                        return False
                else:
                    if smif_id < 0 or smif_id > 4:
                        logger.error('Incorrect \'smif_id\' value. '
                                     'The correct values are: 0 - SMIF disabled '
                                     '(no external memory); 1, 2, 3 or 4 - slave '
                                     'select line, which controls memory module')
                        return False

                    if slot1['address'] >= self.memory_map.SMIF_MEM_MAP_START:
                        logger.debug(f'UPGRADE slot will reside in external flash '
                                     f'at address {hex(slot1["address"])}')

                if slot0['size'] != slot1['size']:
                    logger.warning('BOOT and UPGRADE slots sizes are not equal')

        return True

    def validate_cybootloader_paths(self):
        """
        Validates path to CyBootloader hex and jwt file.
        :return: True if CyBootloader hex and jwt files specified in policy and exist, otherwise False.
        """
        node = self.parser.json['cy_bootloader']
        if node['mode'] == 'custom':
            if 'hex_path' not in node or 'jwt_path' not in node:
                logger.error('Paths to CyBootloader hex and jwt files are required when '
                             'CyBootloader mode is set to custom')
                return False
        return True

    def validate_multi_image_id(self):
        """
        Validates multi-image IDs.
        :return: True if multi-image ID matches requirements, otherwise false.
        """
        is_valid = True
        for slot in self.parser.json['boot_upgrade']['firmware']:
            if slot['id'] != 0:
                if 'multi_image' in slot:
                    is_valid &= 1 <= slot['multi_image'] <= 2
                else:
                    is_valid = False
        return is_valid

    def validate_address_overlap(self, slot_overlaps=True):
        """
        Validates whether used flash addresses do not overlap each other.
        :param slot_overlaps: Indicates whether to validate slot overlaps
        :return: True if there are no overlaps, otherwise False.
        """
        AddressSize = namedtuple("AddressSize", "address size")
        all_addresses = []
        for slot in self.parser.json['boot_upgrade']['firmware']:
            # Create list of used addresses
            slot_addresses = []
            for res in slot['resources']:
                if res['type'] in ['BOOT', 'UPGRADE']:
                    slot_addresses.append(AddressSize(res['address'],
                                                      res['size']))
            # Validate overlaps in range of the slot
            if slot_addresses:
                result = self.check_overlaps(slot_addresses)
                if not result:
                    return result
                all_addresses.extend(slot_addresses)

        # Validate overlaps between the slots
        if slot_overlaps:
            return self.check_overlaps(all_addresses)

        return True

    @staticmethod
    def check_overlaps(addr_list):
        """
        Checks whether addresses in the specified list overlap
        :return: True if address intersection detected, otherwise False
        """
        for i in range(len(addr_list)):
            for k in range(len(addr_list)):
                if i != k:
                    x = range(addr_list[i].address,
                              addr_list[i].address + addr_list[i].size)
                    y = range(addr_list[k].address,
                              addr_list[k].address + addr_list[k].size)
                    xs = set(x)
                    if len(xs.intersection(y)) > 0:
                        logger.error(f'Address range '
                                     f'\'{hex(x.start)}-{hex(x.stop)}\' '
                                     f'overlaps address range '
                                     f'\'{hex(y.start)}-{hex(y.stop)}\'')
                        return False
        return True

    def get_policy_stage(self):
        """
        Gets policy stage based on image count.
        :return: The stage.
        """
        # Dual-stage policy contains 3 firmware images (CyBootloader, M0p, M4)
        if len(self.parser.json['boot_upgrade']['firmware']) == 3:
            multi_image = False
            for slot in self.parser.json['boot_upgrade']['firmware']:
                multi_image |= 'multi_image' in slot
            return 'multi' if multi_image else 'dual'

        # Single-stage policy contains 2 firmware images (CyBootloader, M4)
        if len(self.parser.json['boot_upgrade']['firmware']) == 2:
            return "single"

    def memory_map_align(self):
        """
        Compare memory map data with policy.
        Uncompared values are written to logger.error
        :return: True on success else False
        """
        flash_res = []
        smif_res = []
        for item in self.parser.json["debug"]["rma"]["destroy_flash"]:
            flash_res.append([item["start"], item["start"] + item["size"]])

        for item in self.parser.json["boot_upgrade"]["firmware"]:
            for res in item["resources"]:
                if res["type"].startswith("FLASH") or \
                   res["type"].startswith("BOOT"):
                    flash_res.append([res["address"], res["address"] + res["size"]])
                if item["upgrade"] and res["type"].startswith("UPGRADE"):
                    if item["smif_id"] == 0:
                        flash_res.append([res["address"], res["address"] + res["size"]])
                    else:
                        smif_res.append([res["address"], res["address"] + res["size"]])

        # test flash size
        flash_start = self.memory_map.FLASH_ADDRESS
        flash_end = flash_start + self.memory_map.FLASH_SIZE
        for item in flash_res:
            if flash_start > item[0] or flash_end < item[0] or flash_end < item[1]:
                logger.error(f'Address range \'{hex(item[0])}-{hex(item[1])}\' is not in FLASH area (\'{hex(flash_start)}-{hex(flash_end)}\').')
                return False

        # test smif
        smif_start = self.memory_map.SMIF_MEM_MAP_START
        for item in smif_res:
            if smif_start > item[0]:
                logger.error(f'Address range \'{hex(item[0])}-{hex(item[1])}\' is not in SMIF area (\'{hex(smif_start)}\').')
                return False

        return True

    def validate_multi_image_smif_id(self):
        """
        Validates smif_id for multi-image case.
        :return: True if smif_id is the same for all images (with an
        exception for smif_id=0), otherwise false.
        """
        smif_id_list = []
        for slot in self.parser.json['boot_upgrade']['firmware']:
            if slot['id'] != 0:
                if 'smif_id' in slot:
                    smif_id_list.append(slot['smif_id'])

        smif_id_set = set(smif_id_list)
        is_valid = len(smif_id_set) == 1 or \
                   (len(smif_id_set) == 2 and 0 in smif_id_set)

        if not is_valid:
            logger.error('smif_id in multi-image case must be the same for all images (with an exception for '
                         'smif_id=0 which can be combined with other values)')

        return is_valid

    def validate_prebuild_section(self):
        """
        Validates pre_build section of given policy
        :return: true if all needed parameters in place and corresponding
        files exist
        """
        result = True
        if 'pre_build' in self.parser.json:
            # Checking oem_public_key
            try:
                key = self.parser.oem_public_key()
            except KeyError:
                logger.error('Parameter "oem_public_key" is missing')
                result = False
            else:
                if key.count(None) == 2:
                    logger.error('File from "oem_public_key" not found')
                    result = False

            # Checking oem_private_key
            try:
                key = self.parser.oem_private_key()
            except KeyError:
                logger.error('Parameter "oem_private_key" is missing')
                result = False
            else:
                if key.count(None) == 2:
                    logger.error('File from "oem_private_key" not found')
                    result = False

            # Checking hsm_public_key
            try:
                key = self.parser.hsm_public_key()
            except KeyError:
                logger.error('Parameter "hsm_public_key" is missing')
                result = False
            else:
                if key.count(None) == 2:
                    logger.error('File from "hsm_public_key" not found')
                    result = False

            # Checking hsm_private_key
            try:
                key = self.parser.hsm_private_key()
            except KeyError:
                logger.error('Parameter "hsm_private_key" is missing')
                result = False
            else:
                if key.count(None) == 2:
                    logger.error('File from "hsm_private_key" not found')
                    result = False

            # Checking cy_auth
            try:
                key_path = self.parser.get_cy_auth()
            except KeyError:
                logger.error('Parameter "cy_auth" is missing')
                result = False
            else:
                if not os.path.isfile(key_path):
                    logger.error('File from "cy_auth" not found')
                    result = False

            # Checking group_private_key
            if self.parser.provision_group_private_key_state():
                key = self.parser.group_private_key()
                if key.count(None) == 2:
                    logger.error('Group private key file not found')
                    result = False

            # Checking device_private_key
            if self.parser.provision_device_private_key_state():
                key = self.parser.device_private_key()
                if key.count(None) == 2:
                    logger.error('Device private key file not found')
                    result = False
        else:
            logger.error('Section "pre_build" is missing')
            result = False

        return result

    def is_multi_image(self):
        for slot in self.parser.json['boot_upgrade']['firmware']:
            if 'multi_image' in slot:
                return True
        return False
