"""
Copyright (c) 2018-2021 Cypress Semiconductor Corporation

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
import logging
from time import sleep
import cysecuretools.execute.provisioning_packet.provisioning_packet_mxs40v1 as prov_packet
from cysecuretools.core.connect_helper import ConnectHelper
from cysecuretools.core.target_director import Target
from cysecuretools.core.enums import (EntranceExamStatus, ProvisioningStatus)
from cysecuretools.execute.provisioning_packet.lib.cyprov_pem import PemKey
from cysecuretools.execute.sys_call \
    import (provision_keys_and_policies, read_lifecycle, dap_control,
            get_prov_details, FB_POLICY_JWT)
from cysecuretools.execute.programmer.base import AP
from cysecuretools.execute.programmer.pyocd_wrapper import ResetType
from cysecuretools.core.strategy_context.provisioning_strategy_ctx import \
    ProvisioningStrategy
from cysecuretools.core.strategy_context.encrypted_programming_strategy_ctx \
    import EncryptedProgrammingContext
from cysecuretools.execute.encrypted_programming.aes_header_strategy import \
    AesHeaderStrategy
from cysecuretools.data.mxs40v1.mxs40v1_sfb_status_codes import \
    sfb_status_codes
from cysecuretools.targets.common.p64.policy_parser import PolicyParser
from cysecuretools.targets.common.p64.enums import ProtectionState, KeyId
from cysecuretools.execute.provisioning_packet.lib import Crypto

logger = logging.getLogger(__name__)


class ProvisioningMXS40v1(ProvisioningStrategy):

    def provision(self, tool,
                  target: Target, bootloader, **kwargs) -> ProvisioningStatus:
        """
        Programs Cypress Bootloader and calls system calls for device
        provisioning.
        :param tool: Programming/debugging tool used for communication
        :param target: The target object.
        :param bootloader: Path to Cypress Bootloader program file.
        :param kwargs: Dictionary with the following fields:
               - ap: Access port to use
               - probe_id: Probe ID to use
        :return: Provisioning status.
        """
        if 'ap' in kwargs:
            ap = kwargs['ap']
        else:
            ap = 'cm0'

        if 'skip_prompts' in kwargs:
            skip_prompts = kwargs['skip_prompts']
        else:
            skip_prompts = None

        if 'probe_id' in kwargs:
            probe_id = kwargs['probe_id']
        else:
            probe_id = None

        prov_packets = self._get_provisioning_packet(target)
        status = _provision_identity(
            tool, target, prov_packets['prov_identity'], skip_prompts)

        if status == ProvisioningStatus.OK:
            status = _provision_complete(tool, target,
                                         prov_packets['prov_cmd'], bootloader,
                                         False, ap=ap, probe_id=probe_id)

        if status == ProvisioningStatus.OK:
            logger.info('*****************************************')
            logger.info('       PROVISIONING PASSED               ')
            logger.info('*****************************************\n')

        return status

    def re_provision(self, tool, target: Target, bootloader, **kwargs) \
            -> ProvisioningStatus:
        """
        Programs Cypress Bootloader and calls system calls for device
        provisioning.
        :param tool: Programming/debugging tool used for communication
        :param target: The target object.
        :param bootloader: Path to Cypress Bootloader program file.
        :param kwargs: Dictionary with the following fields:
               - erase_boot: Indicates whether to erase BOOT slot
               - control_dap_cert: Certificate for AP control
               - ap: Access port to use
               - probe_id: Probe ID to use
        :return: Provisioning status.
        """
        # Process keyword arguments
        if 'erase_boot' in kwargs:
            erase_boot = kwargs['erase_boot']
        else:
            erase_boot = False

        if 'control_dap_cert' in kwargs:
            control_dap_cert = kwargs['control_dap_cert']
        else:
            control_dap_cert = None

        if 'ap' in kwargs:
            ap = kwargs['ap']
        else:
            ap = 'cm0'

        if 'probe_id' in kwargs:
            probe_id = kwargs['probe_id']
        else:
            probe_id = None

        prov_packets = self._get_re_provisioning_packet(target)
        tool.reset_and_halt(ResetType.HW)
        status = _provision_complete(
            tool, target, prov_packets['prov_cmd'], bootloader, True,
            erase_boot, control_dap_cert, ap, probe_id)

        if status == ProvisioningStatus.OK:
            logger.info('*****************************************')
            logger.info('       RE-PROVISIONING PASSED               ')
            logger.info('*****************************************\n')

        return status

    def erase_flash(self, tool, target):
        """
        Erases allowed (w/o bootloader, data only) flash area
        :param tool: Programming/debugging tool used for communication
        :param target: The target object
        """
        erase_flash(tool, target)

    def convert_to_rma(self, tool, target, **kwargs):
        """ N/A for MXS40v1 platform """
        raise NotImplementedError

    @staticmethod
    def _get_provisioning_packet(target):
        packet_dir = target.policy_parser.get_provisioning_packet_dir()
        prov_identity = os.path.join(packet_dir, prov_packet.PROV_IDENTITY_JWT)
        prov_cmd = os.path.join(packet_dir, prov_packet.PROV_CMD_JWT)

        if not os.path.isfile(prov_identity):
            logger.error('Cannot find provisioning packet %s', prov_identity)
            return False
        if not os.path.isfile(prov_cmd):
            logger.error('Cannot find provisioning packet %s', prov_cmd)
            return False

        return {'prov_identity': prov_identity, 'prov_cmd': prov_cmd}

    @staticmethod
    def _get_re_provisioning_packet(target):
        packet_dir = target.policy_parser.get_provisioning_packet_dir()
        prov_cmd = os.path.join(packet_dir, prov_packet.PROV_CMD_JWT)

        if not os.path.isfile(prov_cmd):
            logger.error('Cannot find provisioning packet %s', prov_cmd)
            return False

        return {'prov_cmd': prov_cmd}


def read_silicon_data(tool, target: Target):
    """
    Reads silicon data from device
    :param tool: Programming/debugging tool used for communication
    :param target: The target object.
    :return: Device response
    """
    logger.debug('Read silicon data')
    tool.reset(ResetType.HW)
    _, response = provision_keys_and_policies(tool, None, target.register_map)
    return response


def erase_flash(tool, target):
    logger.info('Erase main flash:')
    addr = target.memory_map.FLASH_ADDRESS
    size = target.memory_map.FLASH_SIZE
    logger.info('erasing address 0x%x, size 0x%x ...', addr, size)
    ap = tool.get_ap()
    tool.set_ap(AP.CMx)
    tool.halt()
    tool.erase(addr, size)
    logger.info('Erasing complete')
    tool.set_ap(ap)
    erase_smif(tool, target)


def erase_smif(tool, target):
    smif_resources = target.policy_parser.get_smif_resources()
    if len(smif_resources) > 0:
        logger.info('Erase main smif slots:')
        ap = tool.get_ap()
        tool.set_ap(AP.CMx)
        for (addr, size) in smif_resources:
            # Aligning start address to erase to minimal erase size of smif
            actual_addr = addr - addr % target.memory_map.MIN_EXT_ERASE_SIZE
            # Aligning size to erase to minimal erase size of smif
            if size % target.memory_map.MIN_EXT_ERASE_SIZE == 0:
                actual_size = size
            else:
                actual_size = size + target.memory_map.MIN_EXT_ERASE_SIZE - \
                              size % target.memory_map.MIN_EXT_ERASE_SIZE
            logger.info('erasing address 0x%x, size 0x%x ...', actual_addr,
                        actual_size)
            tool.erase(actual_addr, actual_size)
            logger.info('Erasing complete')
        tool.set_ap(ap)


def erase_status_partition(tool, target):
    memory_area = target.policy_parser.status_partition()
    if memory_area is not None:
        logger.info('Erase SWAP status partition memory region:')
        ap = tool.get_ap()
        tool.set_ap(AP.CMx)
        logger.info('erasing address 0x%x, size 0x%x ...',
                    memory_area.address, memory_area.size)
        tool.erase(memory_area.address, memory_area.size)
        logger.info('Erasing complete')
        tool.set_ap(ap)


def erase_scratch_area(tool, target):
    memory_area = target.policy_parser.scratch_area()
    if memory_area is not None:
        logger.info('Erase SCRATCH memory region:')
        ap = tool.get_ap()
        tool.set_ap(AP.CMx)
        logger.info('erasing address 0x%x, size 0x%x ...',
                    memory_area.address, memory_area.size)
        tool.erase(memory_area.address, memory_area.size)
        logger.info('Erasing complete')
        tool.set_ap(ap)


def erase_slots(tool, target, slot_type, first_only=False):
    """
    Erases slot(s) of specific type.
    :param tool: Programming/debugging tool
    :param target: The target object
    :param slot_type: Slot type - BOOT, UPGRADE
    :param first_only: For performance, erase first image only, it is
                       enough to prevent application from starting
    """
    data = target.policy_parser.get_image_data(slot_type)
    logger.info('Erase %s slot:', slot_type)
    for addr, size in data:
        logger.info('erasing address 0x%x, size 0x%x ...', addr, size)
        ap = tool.get_ap()
        tool.set_ap(AP.CMx)
        tool.halt()
        tool.erase(addr, size)
        logger.info('Erasing complete')
        tool.set_ap(ap)
        if first_only:
            break


def _provision_identity(tool, target: Target,
                        prov_identity_jwt, skip_prompts) -> ProvisioningStatus:
    lifecycle = read_lifecycle(tool, target.register_map)

    if lifecycle == ProtectionState.secure:
        status = target.entrance_exam.execute(tool)
        if status == EntranceExamStatus.FLASH_NOT_EMPTY:
            if skip_prompts:
                logger.error('Cannot start provisioning. '
                             'User firmware running on chip detected')
                return ProvisioningStatus.FAIL
            else:
                answer = input('Erase user firmware running on chip? (y/n): ')
                if answer.lower() == 'y':
                    erase_flash(tool, target)
                else:
                    return ProvisioningStatus.TERMINATED
        elif status != EntranceExamStatus.OK:
            return ProvisioningStatus.FAIL
    else:
        erase_flash(tool, target)

    tool.reset_and_halt()
    sleep(0.2)

    is_exam_pass, response = provision_keys_and_policies(
        tool, prov_identity_jwt, target.register_map)
    _save_device_response(target, response)

    if not is_exam_pass:
        logger.error('Unexpected ProvisionKeysAndPolicies syscall response')
        return ProvisioningStatus.FAIL
    else:
        return ProvisioningStatus.OK


def _provision_complete(tool, target: Target, prov_cmd_jwt, bootloader,
                        re_provision, erase_boot=False,
                        control_dap_cert=None, ap='cm0', probe_id=None) \
        -> ProvisioningStatus:
    flash_ops_allowed = True
    if re_provision:
        # Check whether cm0 is open
        cm0_open = read_cm0_permissions(tool, target.register_map)
        if cm0_open:
            ConnectHelper.disconnect(tool)
            ConnectHelper.connect(tool, target, probe_id=probe_id, ap='cm0')
            tool.reset_and_halt(ResetType.HW)
        flash_ops_allowed = cm0_open or ap == 'cm4'

    reg_map = target.register_map

    if flash_ops_allowed:
        erase_status_partition(tool, target)
        erase_scratch_area(tool, target)

    # Read firmware status
    logger.info('Read FlashBoot firmware status:')
    sfb_fw_status = tool.read32(reg_map.ENTRANCE_EXAM_FW_STATUS_REG)
    if re_provision:
        expected = reg_map.ENTRANCE_EXAM_FW_STATUS_RE_VAL
    else:
        expected = reg_map.ENTRANCE_EXAM_FW_STATUS_VAL
    received = sfb_fw_status & reg_map.ENTRANCE_EXAM_FW_STATUS_MASK
    logger.info('FlashBoot firmware status = 0x%x', sfb_fw_status)
    logger.info('Received FB_FW_STATUS = 0x%x', received)
    logger.info('Expected FB_FW_STATUS = 0x%x', expected)

    if expected != received:
        try:
            status = sfb_status_codes[received]
            logger.info('SFB status: %s: %s', status['status'], status['desc'])
        except KeyError:
            logger.debug('Unexpected SFB status 0x%x', received)

    # Open cm0 AP
    if control_dap_cert:
        logger.info('Opening cm0 AP')
        cm_open = dap_control(tool, reg_map, 0, 1, False, control_dap_cert)
        logger.info('cm0 AP %s', 'open' if cm_open else 'closed')
        if cm_open:
            logger.info('Use cm0 AP')
            ConnectHelper.disconnect(tool)
            ConnectHelper.connect(tool, target, probe_id=probe_id, ap='cm0',
                                  acquire=False)
            tool.set_skip_reset_and_halt(True)
            tool.examine_ap()
        flash_ops_allowed = cm_open

    if erase_boot:
        if flash_ops_allowed:
            erase_slots(tool, target, 'BOOT')
        else:
            logger.warning('Skip erasing BOOT slot, AP cm0 is closed')
    else:
        logger.info('BOOT slot will remain the same and can affect '
                    'rollback counter')

    smif_enabled = len(target.policy_parser.get_smif_resources()) > 0
    if smif_enabled:
        if flash_ops_allowed:
            erase_smif(tool, target)
        else:
            logger.warning('Skip erasing external memory, AP cm0 is closed')

    context = EncryptedProgrammingContext(AesHeaderStrategy)

    # Program user application
    for encrypted, app in target.policy_parser.get_user_apps():
        if not os.path.isabs(app):
            app = os.path.join(target.policy_parser.policy_dir, app)
        if encrypted:
            logger.info("Programming encrypted user application '%s':", app)
            result = context.program(tool, target, app)
            if not result:
                logger.error('User application encrypted programming failed')
                return ProvisioningStatus.FAIL
        else:
            if flash_ops_allowed:
                current_ap = tool.get_ap()
                tool.set_ap(AP.CMx)
                logger.info("Programming user application '%s':", app)
                tool.reset_and_halt(reset_type=ResetType.HW)
                tool.program(app)
                tool.set_ap(current_ap)
            else:
                logger.warning('Skip programming user application, '
                               'AP cm0 is closed')

    # Program bootloader
    is_custom_bootloader = target.policy_parser.is_custom_bootloader()
    is_encrypted_bootloader = target.policy_parser.is_encrypted_bootloader()
    if is_custom_bootloader and is_encrypted_bootloader:
        cy_bootloader_hex = target.policy_parser.get_cybootloader_hex()
        logger.info(
            "Programming encrypted bootloader '%s':", cy_bootloader_hex)
        result = context.program(tool, target, cy_bootloader_hex)
        if not result:
            logger.error('Bootloader encrypted programming failed')
            return ProvisioningStatus.FAIL
    else:
        if not flash_ops_allowed:
            logger.warning('Skip programming bootloader, AP cm0 is closed')
        elif bootloader is None:
            logger.warning('Skip programming bootloader')
        else:
            sleep(3)
            current_ap = tool.get_ap()
            tool.set_ap(AP.CMx)
            logger.info("Programming bootloader '%s':", bootloader)
            tool.halt()
            tool.program(bootloader)
            logger.info('Programming bootloader complete')
            tool.set_ap(current_ap)

    if control_dap_cert:
        tool.set_skip_reset_and_halt(False)

    if flash_ops_allowed and re_provision:
        ConnectHelper.disconnect(tool)
        ConnectHelper.connect(tool, target, probe_id=probe_id, ap=ap)

    tool.reset(ResetType.HW)
    sleep(3)

    _save_device_public_key(tool, target)

    # Run provisioning syscall
    logger.info('Run provisioning syscall:')
    is_exam_pass, response = provision_keys_and_policies(tool, prov_cmd_jwt,
                                                         target.register_map)
    if not is_exam_pass:
        return ProvisioningStatus.FAIL

    _save_device_response(target, response)

    tool.reset()

    if not target.policy_parser.is_sys_ap_enabled():
        if not target.policy_parser.is_cmx_ap_enabled(re_provision):
            logger.info('All APs closed by policy. Final verification is '
                        'unavailable.')
            return ProvisioningStatus.OK
        else:
            tool.set_ap(AP.CMx)

    logger.debug('Access through %s', tool.get_ap())

    sleep(3)
    sfb_fw_status = tool.read32(reg_map.ENTRANCE_EXAM_FW_STATUS_REG)
    logger.info('FlashBoot firmware status = 0x%x', sfb_fw_status)
    is_exam_pass = sfb_fw_status == reg_map.FB_FW_STATUS_FIRMWARE_RUNNING_CM0

    if not is_exam_pass:
        logger.error('FlashBoot firmware status is not as expected')

    return ProvisioningStatus.OK if is_exam_pass else ProvisioningStatus.FAIL


def read_cm0_permissions(tool, reg_map):
    logger.info('Checking cm0 AP permissions')
    passed, data = get_prov_details(tool, reg_map, FB_POLICY_JWT)
    if passed and len(data) > 0:
        policy = Crypto.readable_jwt(data)
        silicon_policy_parser = PolicyParser(policy['payload'])
        cm0_open = silicon_policy_parser.is_cmx_ap_enabled(True)
        logger.info('cm0 AP %s', 'open' if cm0_open else 'closed')
    else:
        logger.error('Failed to read policy from device while getting AP '
                     'permission')
        logger.warning('Flash operations will be skipped')
        cm0_open = False
    return cm0_open


def _save_device_public_key(tool, target):
    try:
        jwk_path, pem_path = target.policy_parser.device_public_key_path()
        key = target.key_reader.read_public_key(tool, KeyId.DEVICE, 'jwk')
        if key:
            with open(jwk_path, 'w', encoding='utf-8') as f:
                f.write(json.dumps(key, indent=4))
            pem = PemKey(jwk_path)
            pem.save(pem_path, private_key=False)
    except (KeyError, OSError, ValueError, TypeError) as e:
        logger.error('Failed to save device public key')
        logger.error(e)


def _save_device_response(target, response):
    try:
        packet_dir = target.policy_parser.get_provisioning_packet_dir()
        filename = os.path.join(packet_dir, prov_packet.DEVICE_RESPONSE_JWT)
        if response:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(response)
        logger.info("Saved device response to '%s'", filename)
    except (KeyError, OSError, TypeError) as e:
        logger.error('Failed to save device response')
        logger.error(e)
