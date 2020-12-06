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
from math import ceil
from cysecuretools.targets.common.policy_parser import ImageType
from cysecuretools.core import PolicyValidatorBase
from cysecuretools.core.enums import ValidationStatus
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
        self.is_smif = self._is_smif()
        self.is_multi_image = self._is_multi_image()

    def validate(self, skip=None, skip_prompts=False):
        """
        Validation of policy.json.
        :param skip: Validators to skip (e.g. pre_build, dap_disabling)
        :param skip_prompts: Indicates whether to skip interactive prompts
        :return Validation status
        """
        status = ValidationStatus.OK
        skip_list = skip if skip else []
        # First stage validation
        with open(POLICY_SCHEMA) as f:
            file_content = f.read()
            json_schema = json.loads(file_content)

        try:
            jsonschema.validate(self.parser.json, json_schema)
            logger.debug('First stage validation success')
        except (jsonschema.exceptions.ValidationError,
                jsonschema.exceptions.SchemaError) as e:
            logger.error('Validation against schema failed')
            logger.error(e)
            status = ValidationStatus.ERROR

        # Second stage validation
        if self._continue_validation(status):
            is_multi_image = self._is_multi_image()
            logger.debug('Validating firmware slots overlapping')
            result = self.validate_address_overlap(is_multi_image)
            if not result:
                status = ValidationStatus.ERROR

        if self._continue_validation(status):
            for slot in self.parser.json['boot_upgrade']['firmware'][1:]:
                logger.debug('Validating boot_auth id matches kid in JSON '
                             'key file')
                result = self.validate_boot_keys(slot)
                result &= self.validate_key_file_kid(slot)
                if not result:
                    status = ValidationStatus.ERROR

        if self._continue_validation(status):
            logger.debug('Validating there is no different JWKs with the '
                         'same key ID')
            result = self.key_name_validation()
            if not result:
                status = ValidationStatus.ERROR

        if self._continue_validation(status):
            if self.stage == 'multi':
                logger.debug('Validating multi-image IDs')
                result = self.validate_multi_image_id()
                if not result:
                    status = ValidationStatus.ERROR

        if self._continue_validation(status):
            if self.stage == 'multi':
                logger.debug('Validating multi-image smif_id')
                result = self.validate_multi_image_smif_id()
                if not result:
                    status = ValidationStatus.ERROR

        if self._continue_validation(status):
            if self.stage != 'multi':
                logger.debug('Validating whether image ID corresponds to '
                             'CyBootloader launch ID')
                result = self.image_launch_validation()
                if not result:
                    status = ValidationStatus.ERROR

        if self._continue_validation(status):
            logger.debug('Validating policy for BOOT sections, '
                         'encryption and SMIF')
            result = self.check_slots()
            if not result:
                status = ValidationStatus.ERROR

        if self._continue_validation(status):
            logger.debug('Validating monotonic counter')
            result = self.validate_monotonic_counter()
            if not result:
                status = ValidationStatus.ERROR

        if self._continue_validation(status):
            logger.debug('Validating CyBootloader paths')
            result = self.validate_cybootloader_paths()
            if not result:
                status = ValidationStatus.ERROR

        if self._continue_validation(status):
            logger.debug('Validate whether slots address value is aligned '
                         'with the SMPU address limits')
            result = self.validate_slot_address_alignment()
            if not result:
                status = ValidationStatus.ERROR

        if self._continue_validation(status):
            logger.debug('Check aligning to Memory map')
            result = self.memory_map_align()
            if not result:
                status = ValidationStatus.ERROR

        if self._continue_validation(status):
            if 'pre_build' not in skip_list:
                logger.debug('Checking integrity of pre-build section')
                result = self.validate_prebuild_section()
                if not result:
                    status = ValidationStatus.ERROR

        if self._continue_validation(status):
            if 'dap_disabling' not in skip_list:
                result = self.validate_dap_disabling(skip_prompts)
                if result != ValidationStatus.OK:
                    status = result

        if self._continue_validation(status):
            if self.parser.upgrade_mode() == 'swap':
                result = self.validate_status_partition_size()
                if not result:
                    status = ValidationStatus.ERROR

        if status == ValidationStatus.ERROR:
            logger.error('Policy validation finished with error')
        elif status == ValidationStatus.WARNING:
            logger.warning('Policy validation finished with warnings')
        elif status == ValidationStatus.TERMINATED:
            logger.info('Terminated by user')
        else:
            logger.debug('Second stage validation success')

        return status

    @staticmethod
    def _continue_validation(status):
        return status not in [ValidationStatus.ERROR,
                              ValidationStatus.TERMINATED]

    @staticmethod
    def validate_boot_keys(slot):
        """ Validates boot_keys section against boot_auth section """
        result = True
        for a in slot['boot_auth']:
            key_found = False
            for k in slot['boot_keys']:
                if k['kid'] == a:
                    key_found = True
                    break
            result &= key_found
            if not result:
                logger.error(f'Key with ID {a} not found in the \'boot_keys\' '
                             f'section (image ID {slot["id"]})')
                break

        return result

    def validate_key_file_kid(self, slot):
        """ Validates kid field of the key files against boot_auth section """
        result = True
        for a in slot['boot_auth']:
            key_found = False
            for k in slot['boot_keys']:
                if k['kid'] == a:
                    key_file = os.path.join(self.policy_dir, k['key'])
                    if os.path.exists(key_file):
                        private, public = load_key(key_file)
                        if private:
                            file_kid = int(private['kid'])
                        elif public:
                            file_kid = int(public['kid'])
                        else:
                            file_kid = None

                        if file_kid == a:
                            key_found = True
                            break
                    else:
                        key_found = True  # it is ok if file does not exist
                        logger.debug(f'Key file "{key_file}" does not exist')
            result &= key_found
            if not result:
                logger.error(f"Key ID {a}, specified in the 'boot_auth' "
                             f"section does not match the ID in the 'kid' "
                             f"field of JWK (image ID {slot['id']})")
                break

        return result

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
        all_slots_addr = []
        res_area = []
        for slot in self.parser.json['boot_upgrade']['firmware']:
            app_area = []
            for item in slot['resources']:
                if item['type'] in ['BOOT', 'UPGRADE']:
                    app_area.append(AddressSize(item['address'], item['size']))
                if item['type'] in ['FLASH_PC1_SPM', 'STATUS_PARTITION']:
                    res_area.append(AddressSize(item['address'], item['size']))

            # Validate overlaps in range of the slot
            if app_area:
                result = self.check_overlaps(app_area)
                if not result:
                    return result
                all_slots_addr.extend(app_area)

            # Validate overlaps in range of the resources
            if res_area:
                result = self.check_overlaps(res_area)
                if not result:
                    return result

        # Validate overlaps between app and resources
        result = self.check_overlaps(all_slots_addr, res_area)
        if not result:
            return result

        # Validate overlaps between the slots
        if slot_overlaps:
            return self.check_overlaps(all_slots_addr)

        return True

    @staticmethod
    def check_overlaps(addr_list1, addr_list2=None):
        """
        Checks whether addresses in the specified list(s) overlap.
        If single list specified, check overlaps in the range of the list.
        If two lists specified, check overlaps between the lists.
        :return: True if address intersection detected, otherwise False
        """
        single_list = addr_list2 is None
        if single_list:
            addr_list2 = addr_list1

        for i in range(len(addr_list1)):
            for k in range(len(addr_list2)):
                if not single_list or (single_list and i != k):
                    x = range(addr_list1[i].address,
                              addr_list1[i].address + addr_list1[i].size)
                    y = range(addr_list2[k].address,
                              addr_list2[k].address + addr_list2[k].size)
                    xy = range(max(x.start, y.start), min(x.stop, y.stop))
                    if len(xy) > 0:
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
                   res["type"].startswith("BOOT") or \
                   res["type"].startswith("STATUS_PARTITION"):
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
                logger.error(f'Address range \'{hex(item[0])}-{hex(item[1])}\' is out of available FLASH area (\'{hex(flash_start)}-{hex(flash_end)}\').')
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

    def _is_multi_image(self):
        for slot in self.parser.json['boot_upgrade']['firmware']:
            if 'multi_image' in slot:
                return True
        return False

    def validate_slot_address_alignment(self):
        """
        Validates whether slots address is aligned with the SMPU
        address limits
        """
        for slot in self.parser.json['boot_upgrade']['firmware']:
            for res in slot['resources']:
                if res['type'] in ['BOOT', 'UPGRADE']:
                    address = int(res['address'])
                    if address % 1024 != 0:
                        logger.error(f'{res["type"]} slot address '
                                     f'({hex(address)}) is misaligned '
                                     f'with the SMPU address limits for the '
                                     f'CYB06XXX part')
                        return False
        return True

    def validate_dap_disabling(self, skip_prompts=False):
        """
        Validates DAP closure and warns a user about the result
        """
        cm0_closed = self.parser.is_ap_disabled('m0p')
        cm4_closed = self.parser.is_ap_disabled('m4')
        sysap_closed = self.parser.is_ap_disabled('system')
        result = ValidationStatus.OK
        if cm0_closed and cm4_closed:
            if skip_prompts:
                logger.warning('The policy will close out SWD ports on the '
                               'chip, preventing any reprogramming of '
                               'application image via SWD')
                result = ValidationStatus.WARNING
            else:
                answer = input('The policy will close out SWD ports on the '
                               'chip, preventing any reprogramming of '
                               'application image via SWD. Please ensure you '
                               'have a valid image programmed on the chip '
                               'before provisioning the chip. '
                               'Continue? (y/n): ')
                if answer.lower() == 'y':
                    result = ValidationStatus.OK
                else:
                    return ValidationStatus.TERMINATED

        if sysap_closed:
            if skip_prompts:
                logger.warning('The policy will close out System DAP on the '
                               'chip, preventing further reprovisioning')
                result = ValidationStatus.WARNING
            else:
                answer = input('The policy will close out System DAP on the '
                               'chip, preventing further reprovisioning. '
                               'Continue? (y/n): ')
                if answer.lower() != 'y':
                    return ValidationStatus.TERMINATED
        return result

    def validate_monotonic_counter(self):
        """
        Validates 'monotonic' field in the policy
        """
        result = True
        cm0_monotonic = None
        cm4_monotonic = None
        for slot in self.parser.json['boot_upgrade']['firmware']:
            if slot['id'] != 0:
                if self._is_cm0_slot(slot['id']):
                    r = range(0, 16)
                    cm0_monotonic = slot['monotonic']
                    if cm0_monotonic not in r:
                        logger.error(f'CM0 application monotonic counter must '
                                     f'be in range {r.start}-{r.stop-1}')
                        result &= False
                if self._is_cm4_slot(slot['id']):
                    r = range(8, 16)
                    cm4_monotonic = slot['monotonic']
                    if cm4_monotonic not in r:
                        logger.error(f'CM4 application monotonic counter must '
                                     f'be in range {r.start}-{r.stop-1}')
                        result &= False
        if cm0_monotonic and cm4_monotonic and cm0_monotonic == cm4_monotonic:
            logger.error('\'monotonic\' field must be different for different '
                         'applications in multi-image case')
            result &= False
        return result

    def validate_status_partition_size(self):
        result = True

        status_partition = self.parser.status_partition()
        if not status_partition:
            raise ValueError('Status partition not found in the specified '
                             'policy file')

        if self.is_multi_image:
            d_cm0 = self._calc_status_partition_size('cm0')
            d_cm4 = self._calc_status_partition_size('cm4')
            d = d_cm0 + d_cm4
        else:
            d = self._calc_status_partition_size()

        if status_partition.size < d:
            logger.error(f'SWAP status partition is too small. The minimum '
                         f'sufficient size is {d} bytes')
            result = False

        return result

    def _calc_status_partition_size(self, slot_name=None):
        """
        Calculates minimum sufficient status partition size
        for the specified slot
        :param slot_name: cm0 or cm4. If None, the maximum image size
        between both slots will be used
        :return: Status partition size in bytes
        """
        int_mem_sector_size = 512  # internal memory sector size
        ext_mem_sector_size = 256 * 1024  # external memory sector size
        trailer = int_mem_sector_size  # trailer is 64B, one slice is enough
        duplicates = 2  # status partition duplicates
        boot_max_size = self._max_image_size('BOOT', slot_name)
        if self.is_smif:
            sector_size = ext_mem_sector_size
        else:
            sector_size = int_mem_sector_size
        boot_sectors = boot_max_size / sector_size
        sector_count = ceil(boot_sectors / sector_size)
        dx = int_mem_sector_size * sector_count + trailer
        d = dx * duplicates
        d = d * 2  # add UPGRADE slot
        return d

    @staticmethod
    def _is_bootloader_slot(image_id):
        return image_id == 0

    @staticmethod
    def _is_cm0_slot(image_id):
        return image_id in [1, 2, 3]

    @staticmethod
    def _is_cm4_slot(image_id):
        return image_id in [4, 16]

    @staticmethod
    def _is_app_slot(image_id):
        return PolicyValidator._is_cm0_slot(image_id) or \
               PolicyValidator._is_cm4_slot(image_id)

    def _is_smif(self):
        for slot in self.parser.json['boot_upgrade']['firmware']:
            if 'smif_id' in slot and slot['smif_id'] > 0:
                return True
        return False

    def _max_image_size(self, image_type, slot_name=None):
        """
        Gets the maximum size between the images of the
        specified type and slot
        """
        img_max_size = 0
        max_size_list = dict()
        for slot in self.parser.json['boot_upgrade']['firmware']:
            for item in slot['resources']:
                if item['type'] == image_type:
                    if item['size'] > img_max_size:
                        if self._is_cm0_slot(slot['id']):
                            max_size_list['cm0'] = item['size']
                        if self._is_cm4_slot(slot['id']):
                            max_size_list['cm4'] = item['size']
        if 'cm0' == slot_name:
            img_max_size = max_size_list['cm0']
        elif 'cm4' == slot_name:
            img_max_size = max_size_list['cm4']
        else:
            try:
                img_max_size = max(max_size_list['cm0'], max_size_list['cm4'])
            except KeyError:
                img_max_size = list(max_size_list.values())[0]
        return img_max_size
