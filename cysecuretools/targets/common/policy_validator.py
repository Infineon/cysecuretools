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
import jsonschema
import logging
import json
import os.path
from cysecuretools.targets.common.policy_parser import ImageType
from cysecuretools.core import PolicyValidatorBase

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

    def validate(self):
        """
        Validation of policy.json.
        :return True if validation succeeds, otherwise False.
        """
        stage = self.get_policy_stage()

        # First stage validation
        with open(POLICY_SCHEMA) as f:
            file_content = f.read()
            json_schema = json.loads(file_content)

        try:
            jsonschema.validate(self.parser.json, json_schema)
        except (jsonschema.exceptions.ValidationError, jsonschema.exceptions.SchemaError) as e:
            logger.error('Validation against schema failed')
            logger.error(e)
            return False
        logger.debug('First stage validation success...')

        # Second stage validation
        for slot in self.parser.json['boot_upgrade']['firmware'][1:]:
            boot_auth = slot['boot_auth'][0]
            boot_keys = slot['boot_keys'][0]
            logger.debug('Validating boot_auth id to match with kid in JSON key file...')
            result = self.key_id_validation(boot_auth, boot_keys)
            if not result:
                return result

        for slot in self.parser.json['boot_upgrade']['firmware'][1:]:
            upgrade_auth = slot['upgrade_auth'][0]
            upgrade_keys = slot['upgrade_keys'][0]
            logger.debug('Validating upgrade_auth id to match with kid in JSON key file...')
            result = self.key_id_validation(upgrade_auth, upgrade_keys)
            if not result:
                return result

        logger.debug('Validating Image ID to corresponding to CyBootloader launch ID...')
        result = self.image_launch_validation()
        if not result:
            return result

        logger.debug('Validating policy for BOOT sections, encryption and SMIF...')
        result = self.check_slots(stage)
        if not result:
            return result

        logger.debug('Validating CyBootloader paths...')
        result = self.validate_cybootloader_paths()
        if not result:
            return result

        logger.debug('Second stage validation success...')
        return True

    def key_id_validation(self, auth, keys):
        """
        Validates keys ID in policy.
        :param auth: Auth ID from policy.
        :param keys: Key ID from policy.
        :return True if validation succeeds, otherwise False.
        """
        key_file = os.path.join(self.policy_dir, keys['key'])
        if os.path.exists(key_file):
            with open(key_file) as f:
                file_content = f.read()
                key = json.loads(file_content)

            key_kid = int(key['custom_priv_key']['kid']) if 'custom_priv_key' in key else int(key['kid'])
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

    def image_launch_validation(self):
        """
        Validates link from the first slot to the next to run image.
        :return True if validation succeeds, otherwise False.
        """
        if not self.parser.json['boot_upgrade']['firmware'][0]['launch'] == self.parser.json['boot_upgrade']['firmware'][1]['id']:
            if not self.parser.json['boot_upgrade']['firmware'][0]['launch'] == self.memory_map.SPE_IMAGE_ID:
                logger.error(f'Image ID = {str(self.parser.json["boot_upgrade"]["firmware"][1]["id"])} '
                             f'does not correspond to CyBootloader '
                             f'launch ID = {str(self.parser.json["boot_upgrade"]["firmware"][0]["launch"])}')
                return False
            else:
                logger.debug(f'NSPE image ID = {str(self.parser.json["boot_upgrade"]["firmware"][1]["id"])}. '
                             f'It will be launched by SPE part.')
        return True

    def check_slots(self, stage):
        """
        Validates types of images, availability of UPGRADE image, availability of smif
        :param stage: Policy stage.
        :return: True if validation passed, otherwise False.
        """
        slot1 = None

        if stage == 'dual':

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

            cm4_slot = 2
        else:
            cm4_slot = 1

        for slot in self.parser.json['boot_upgrade']['firmware'][cm4_slot]['resources']:
            if slot['type'] == ImageType.BOOT.name:
                slot0 = slot

            if self.parser.json['boot_upgrade']['firmware'][1]['upgrade']:
                slot1 = slot
                smif_id = self.parser.json['boot_upgrade']['firmware'][1]['smif_id']
                if slot['type'] == ImageType.UPGRADE.name:
                    try:
                        if self.parser.json['boot_upgrade']['firmware'][1]['encrypt']:
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

        if slot1 is not None:
            if not int(smif_id) == 0:
                logger.debug('SMIF is enabled. UPGRADE slot can be placed in external flash.')

                if int(smif_id) > self.memory_map.SMIF_ID:
                    logger.warning('SMIF ID is out of range [1, 2] supported by CypressBootloder.',
                                   'Either change it to 1, to 2 or make sure cycfg_qspi_memslot.c is updated respectively '
                                   'in SPE for second-stage bootloading.')

                if slot1['address'] >= self.memory_map.SMIF_MEM_MAP_START:
                    logger.debug(f'UPGRADE slot will reside in external flash at address {hex(int(slot1["address"]))}')
            else:
                if slot1['address'] >= self.memory_map.SMIF_MEM_MAP_START:
                    logger.error(f'Slot_1 start_address = {hex(int(slot1["address"]))} '
                                 f'but SMIF is not initialized (smif_id = 0). UPGRADE image will not be generated.')
                    return False

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

    def get_policy_stage(self):
        """
        Gets policy stage based on image count.
        :return: The stage.
        """
        # Dual-stage policy contains 3 firmware images (CyBootloader, M0p, M4)
        if len(self.parser.json['boot_upgrade']['firmware']) == 3:
            return "dual"
        # Single-stage policy contains 2 firmware images (CyBootloader, M4)
        if len(self.parser.json['boot_upgrade']['firmware']) == 2:
            return "single"
