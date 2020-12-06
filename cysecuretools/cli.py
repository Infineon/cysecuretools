"""
Copyright (c) 2020 Cypress Semiconductor Corporation

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
import re
import sys
import json
import click
import logging
import traceback
from intelhex import HexRecordError
from json.decoder import JSONDecodeError
from cryptography.hazmat.primitives import serialization
from cysecuretools import CySecureTools
from cysecuretools.execute.image_cert import ImageCertificate
from cysecuretools.execute.version_helper import VersionHelper
from cysecuretools.targets import print_targets, print_targets_extended, target_names_by_type, get_target_builder
from cysecuretools.core.enums import KeyAlgorithm
from cysecuretools.core.exceptions import ValidationError
from cysecuretools.core.target_director import TargetDirector
from cysecuretools.core.logging_configurator import LoggingConfigurator

logger = logging.getLogger(__name__)


def require_target():
    return not (('--help' in sys.argv)
                or ('device-list' in sys.argv)
                or ('version' in sys.argv)
                or ('probe-list' in sys.argv))


@click.group(chain=True)
@click.pass_context
@click.option('-t', '--target', type=click.STRING, required=require_target(),
              help='Device name or family')
@click.option('-p', '--policy', type=click.File(), required=False,
              help='Provisioning policy file')
@click.option('-v', '--verbose', is_flag=True, help='Provides debug-level log')
@click.option('--logfile-off', is_flag=True, help='Avoids logging into file')
@click.option('--no-interactive-mode', is_flag=True, hidden=True,
              help='Skips user interactive prompts')
def main(ctx, target, policy, verbose, logfile_off, no_interactive_mode):
    """
    Common options (e.g. -t, -p, -v) are common for all commands and must
    precede them:

    \b
    cysecuretools -t <TARGET> -p <POLICY> <COMMAND> --<COMMAND_OPTION>

    \b
    For detailed help for command use:

    \b
    cysecuretools <COMMAND> --help

    \b
    For detailed description of using CySecureTools please refer to readme.md
    """
    if verbose:
        LoggingConfigurator.set_logger_level(logging.DEBUG)
    ctx.ensure_object(dict)
    log_file = not logfile_off

    if require_target():
        if 'init' in sys.argv:
            validate_init_cmd_args()
            policy_path = default_policy(target)
            log_file = False
        else:
            policy_path = policy.name if policy else None
        try:
            ctx.obj['TOOL'] = CySecureTools(target, policy_path, log_file,
                                            no_interactive_mode)
        except ValidationError:
            pass
        except Exception as e:
            logger.error(e)
            logger.debug(e, exc_info=True)
    else:
        if 'version' in sys.argv:
            if '--target' in sys.argv or '-t' in sys.argv:
                try:
                    ctx.obj['TOOL'] = CySecureTools(
                        target, log_file=log_file,
                        skip_prompts=no_interactive_mode)
                except ValidationError:
                    pass
                except Exception as e:
                    logger.error(e)
                    logger.debug(e, exc_info=True)
        else:
            try:
                ctx.obj['TOOL'] = CySecureTools(
                    log_file=log_file, skip_prompts=no_interactive_mode)
            except Exception as e:
                logger.error(e)
                logger.debug(e, exc_info=True)
                exit(1)


@main.resultcallback()
def process_pipeline(processors, target, policy, verbose, logfile_off,
                     no_interactive_mode):
    for func in processors:
        res = func()
        if not res:
            raise click.ClickException('Failed processing!')


def print_assertion_error():
    _, _, tb = sys.exc_info()
    tb_info = traceback.extract_tb(tb)
    stack_trace = ''
    for item in traceback.StackSummary.from_list(tb_info).format():
        stack_trace += item
    stack_trace = stack_trace.rstrip('\n')
    logger.debug(stack_trace)
    filename, line, func, text = tb_info[-1]
    logger.error(f'An error occurred in file \'{filename}\' on line {line} '
                 f'in statement {text}')


def default_policy(target_name):
    director = TargetDirector()
    target_name = target_name.lower()
    get_target_builder(director, target_name)
    target = director.get_target(None, target_name, None)
    return target.policy


def validate_init_cmd_args():
    if '--policy' in sys.argv:
        sys.stderr.write('Error: invalid argument used with "init" '
                         'command: --policy')
        exit(1)
    if '-p' in sys.argv:
        sys.stderr.write('Error: invalid argument used with "init" '
                         'command: -p')
        exit(1)


@main.command('create-keys', help='Creates keys specified in policy file')
@click.pass_context
@click.option('--overwrite/--no-overwrite', 'overwrite', is_flag=True,
              default=None, required=False,
              help='Indicates whether overwrite keys in the output directory '
                   'if they already exist')
@click.option('-o', '--out', type=click.Path(), default=None, required=False,
              help='Output directory for generated keys. By default keys '
                   'location is as specified in the policy file')
@click.option('--kid', type=click.INT, default=None, required=False,
              help='The ID of the key to create. If not specified, all the '
                   'keys found in the policy will be generated')
@click.option('-a', '--algorithm', default=None,
              type=click.Choice([KeyAlgorithm.EC, KeyAlgorithm.RSA],
                                case_sensitive=False),
              help='Key algorithm')
def cmd_create_keys(ctx, overwrite, out, kid, algorithm):
    def process():
        if 'TOOL' not in ctx.obj:
            return False
        try:
            result = ctx.obj['TOOL'].create_keys(overwrite, out, kid, algorithm)
        except Exception as e:
            result = False
            logger.error(e)
            logger.debug(e, exc_info=True)
        return result is not False

    return process


@main.command('version', short_help='Show CyBootloader and Secure Flash Boot '
                                    'version')
@click.option('--probe-id', 'probe_id', type=click.STRING, default=None,
              help='Probe serial number')
@click.option('--ap', hidden=True, type=click.Choice(['cm0', 'cm4', 'sysap']),
              default='sysap',
              help='The access port used to read CyBootloader and '
                   'Secure Flash Boot version from device')
@click.pass_context
def cmd_version(ctx, probe_id, ap):
    def process():
        result = False
        try:
            if ctx.obj:
                if 'TOOL' not in ctx.obj:
                    return False
                ctx.obj['TOOL'].print_version(probe_id, ap)
            else:
                VersionHelper.print_version(target_names_by_type('family'))
            result = True
        except AssertionError:
            print_assertion_error()
        except Exception as e:
            logger.error(e)
            logger.debug(e, exc_info=True)
        return result

    return process


@main.command('sign-image', short_help='Signs firmware image with the key '
                                       'specified in the policy file')
@click.pass_context
@click.option('-h', '--hex', 'hex_file', type=click.Path(), required=True,
              help='User application hex file')
@click.option('-i', '--image-id', type=click.INT, default=4, required=False,
              help='The ID of the firmware image in the policy file')
@click.option('--image-type', default=None,
              type=click.Choice(['BOOT', 'UPGRADE'], case_sensitive=False),
              help='Indicates which type of image is signed - boot or '
                   'upgrade. If omitted, both types will be generated')
@click.option('-e', '--encrypt', 'encrypt_key', type=click.Path(),
              default=None,
              help='Public key PEM-file for the image encryption')
@click.option('-R', '--erased-val',
              type=click.Choice(['0', '0xff'], case_sensitive=False),
              help='The value that is read back from erased flash')
@click.option('--boot-record', metavar='sw_type', default='default',
              help='Create CBOR encoded boot record TLV. The sw_type '
                   'represents the role of the software component (e.g. CoFM '
                   'for coprocessor firmware). [max. 12 characters]')
def cmd_sign_image(ctx, hex_file, image_id, image_type, encrypt_key,
                   erased_val, boot_record):
    def process():
        if 'TOOL' not in ctx.obj:
            return False
        try:
            result = ctx.obj['TOOL'].sign_image(hex_file, image_id, image_type,
                                                encrypt_key, erased_val,
                                                boot_record)
        except Exception as e:
            result = None
            logger.error(e)
            logger.debug(e, exc_info=True)
        return result is not None

    return process


@main.command('create-provisioning-packet',
              help='Creates JWT packet for device provisioning')
@click.pass_context
def cmd_create_provisioning_packet(ctx):
    def process():
        if 'TOOL' not in ctx.obj:
            return False
        try:
            result = ctx.obj['TOOL'].create_provisioning_packet()
        except Exception as e:
            result = False
            logger.error(e)
            logger.debug(e, exc_info=True)
        return result

    return process


@main.command('provision-device', help='Executes device provisioning')
@click.pass_context
@click.option('--probe-id', 'probe_id', type=click.STRING, default=None,
              help='Probe serial number')
@click.option('--existing-packet', 'use_existing_packet', is_flag=True,
              help='Skip provisioning packet creation and use existing one')
@click.option('--ap', hidden=True, type=click.Choice(['cm0', 'cm4', 'sysap']),
              default='cm4', help='The access port used for provisioning')
def cmd_provision_device(ctx, probe_id, use_existing_packet, ap):
    def process():
        if 'TOOL' not in ctx.obj:
            return False
        try:
            if use_existing_packet:
                result = True
            else:
                result = ctx.obj['TOOL'].create_provisioning_packet()
            if result:
                result = ctx.obj['TOOL'].provision_device(probe_id, ap)
        except AssertionError:
            result = False
            print_assertion_error()
        except Exception as e:
            result = False
            logger.error(e)
            logger.debug(e, exc_info=True)
        return result

    return process


@main.command('re-provision-device', help='Executes device re-provisioning')
@click.pass_context
@click.option('--probe-id', type=click.STRING, required=False, default=None,
              help='Probe serial number')
@click.option('--existing-packet', is_flag=True,
              help='Skip provisioning packet creation and use existing one')
@click.option('--ap', hidden=True, type=click.Choice(['cm0', 'cm4', 'sysap']),
              default='sysap', help='The access port used for re-provisioning')
@click.option('--erase-boot', is_flag=True,
              help='Indicates whether erase BOOT slot')
@click.option('--control-dap-cert', default=None,
              help='The certificate that provides the access to control DAP')
@click.option('--skip-bootloader', is_flag=True, hidden=True, default=False,
              help='Skips bootloader programming')
def cmd_re_provision_device(ctx, probe_id, existing_packet, ap, erase_boot,
                            control_dap_cert, skip_bootloader):
    def process():
        if 'TOOL' not in ctx.obj:
            return False
        try:
            if existing_packet:
                result = True
            else:
                result = ctx.obj['TOOL'].create_provisioning_packet()
            if result:
                result = ctx.obj['TOOL'].re_provision_device(
                    probe_id, ap, erase_boot, control_dap_cert,
                    skip_bootloader)
        except AssertionError:
            result = False
            print_assertion_error()
        except Exception as e:
            result = False
            logger.error(e)
            logger.debug(e, exc_info=True)
        return result

    return process


@main.command('create-certificate', help='Creates certificate in x509 format')
@click.pass_context
@click.option('-t', '--type', 'cert_type', default='x509', hidden=True,
              help='Certificate type (x509)')
@click.option('-n', '--name', 'cert_name', type=click.File(mode='wb'),
              default='psoc_cert.pem', help='Certificate filename')
@click.option('-e', '--encoding', default='PEM',
              help='Certificate encoding (PEM, DER)')
@click.option('--probe-id', default=None, help='Probe serial number')
@click.option('--subject-name', default=None, help='Certificate subject name')
@click.option('--country', default=None, help='Certificate country code')
@click.option('--state', default=None, help='Certificate issuer state')
@click.option('--organization', default=None,
              help='Certificate issuer organization')
@click.option('--issuer-name', default=None, help='Certificate issuer name')
@click.option('--private-key', type=click.File(), default=None,
              help='Private key to sign the certificate')
def cmd_create_certificate(ctx, cert_type, cert_name, encoding, probe_id,
                           subject_name, country, state, organization,
                           issuer_name, private_key):
    def process():
        if 'TOOL' not in ctx.obj:
            return False
        if encoding.upper() == 'PEM':
            enc = serialization.Encoding.PEM
        elif encoding.upper() == 'DER':
            enc = serialization.Encoding.DER
        else:
            logger.error(f'Invalid certificate encoding \'{encoding}\'')
            return False

        d = {
            'subject_name': subject_name,
            'country': country,
            'state': state,
            'organization': organization,
            'issuer_name': issuer_name,
            'private_key': private_key.name if private_key else None
        }

        result = False
        if cert_type == 'x509':
            try:
                cert = ctx.obj['TOOL'].create_x509_certificate(
                    cert_name.name, enc, probe_id, **d)
                result = cert is not None
            except AssertionError:
                print_assertion_error()
            except Exception as e:
                logger.error(e)
                logger.debug(e, exc_info=True)
        else:
            logger.error(f'Invalid certificate type \'{cert_type}\'')
        return result

    return process


@main.command('image-certificate', help='Creates Bootloader image certificate')
@click.pass_context
@click.option('-i', '--image', type=click.File('r'), required=True,
              help='Image in the Intel HEX format')
@click.option('-k', '--key', type=click.File('r'), default=None, required=True,
              help='Private key in the JWK format to sign certificate')
@click.option('-o', '--cert', type=click.File('w'),
              default='image_certificate.jwt',
              help='The output file - image certificate in the JWT format')
@click.option('-v', '--version', callback=ImageCertificate.validate_version,
              help='Image version')
@click.option('--image-id', type=click.INT, default=0, help='Image ID')
@click.option('-d', '--exp-date', default='Jan 1 2031',
              callback=ImageCertificate.validate_date,
              help='Certificate expiration date. Date format '
                   'is \'Jan 1 2031\'')
def cmd_image_certificate(ctx, image, key, cert, version, image_id,
                          exp_date):
    def process():
        if 'TOOL' not in ctx.obj:
            return False
        result = False
        try:
            key_path = key.name if key else None
            result = ctx.obj['TOOL'].create_image_certificate(
                image.name, key_path, cert.name, version, image_id, exp_date)
        except JSONDecodeError as e:
            logger.error(f'Invalid certificate signing key')
            logger.error(e)
        except HexRecordError as e:
            logger.error(f'Invalid image \'{image.name}\'')
            logger.error(e)
        except Exception as e:
            logger.error(e)
            logger.debug(e, exc_info=True)
        return result
    return process


@main.command('entrance-exam', short_help='Checks device life cycle, '
                                          'FlashBoot firmware and Flash state')
@click.option('--probe-id', type=click.STRING, required=False, default=None,
              help='Probe serial number')
@click.option('--ap', hidden=True, type=click.Choice(['cm0', 'cm4', 'sysap']),
              default='cm4', help='The access port used for entrance-exam')
@click.option('--erase-flash', hidden=True, is_flag=True,
              help='Erase flash before the command execution')
@click.pass_context
def cmd_entrance_exam(ctx, probe_id, ap, erase_flash):
    def process():
        if 'TOOL' not in ctx.obj:
            return False
        result = False
        try:
            result = ctx.obj['TOOL'].entrance_exam(probe_id, ap, erase_flash)
        except AssertionError:
            print_assertion_error()
        except Exception as e:
            logger.error(e)
            logger.debug(e, exc_info=True)
        return result

    return process


@main.command('device-list', help='List of supported devices')
@click.option('--extended', hidden=True, is_flag=True,
              help='Provides targets extended data')
@click.pass_context
def cmd_device_list(ctx, extended):
    def process():
        result = False
        try:
            if extended:
                print_targets_extended()
            else:
                print_targets()
            result = True
        except Exception as e:
            logger.error(e)
            logger.debug(e, exc_info=True)
        return result
    return process


@main.command('encrypt-image',
              short_help='Creates encrypted image for encrypted programming')
@click.pass_context
@click.option('-i', '--image', type=click.File('r'),  required=True,
              help='The image to encrypt')
@click.option('-h', '--host-key-id', type=click.INT, required=True,
              help='Host private key ID (4 - HSM, 5 - OEM)')
@click.option('-d', '--device-key-id', type=click.INT, required=True,
              help='Device public key ID (1 - device, 12 - group)')
@click.option('-a', '--algorithm', 'algorithm', default='ECC',
              help='Asymmetric algorithm for key derivation function')
@click.option('--key-length', type=click.INT, default=16,
              help='Derived key length')
@click.option('-o', '--encrypted-image', required=True, type=click.File('w+'),
              help='Output file of encrypted image for encrypted programming')
@click.option('--padding-value', default=0, type=click.INT,
              help='Value for image padding')
@click.option('--probe-id', default=None,
              help='Probe serial number. '
                   'Used to read device public key from device.')
def cmd_encrypt_image(ctx, image, host_key_id, device_key_id, algorithm,
                      key_length, encrypted_image, padding_value, probe_id):
    def process():
        if 'TOOL' not in ctx.obj:
            return False
        result = False
        try:
            result = ctx.obj['TOOL'].encrypt_image(
                image.name, host_key_id, device_key_id, algorithm, key_length,
                encrypted_image.name, padding_value, probe_id)
        except AssertionError:
            print_assertion_error()
        except Exception as e:
            logger.error(e)
            logger.debug(e, exc_info=True)
        return result
    return process


@main.command('encrypted-programming', help='Programs encrypted image')
@click.pass_context
# w+ is for -i option necessary if encryption and programming are run together
@click.option('-i', '--encrypted-image', type=click.File('w+'), required=True,
              help='The encrypted image to program')
@click.option('--probe-id', default=None, help='Probe serial number')
def cmd_encrypted_programming(ctx, encrypted_image, probe_id):
    def process():
        if 'TOOL' not in ctx.obj:
            return False
        result = False
        try:
            result = ctx.obj['TOOL'].encrypted_programming(
                encrypted_image.name, probe_id)
        except AssertionError:
            print_assertion_error()
        except Exception as e:
            logger.error(e)
            logger.debug(e, exc_info=True)
        return result

    return process


@main.command('slot-address', short_help='Gets slot address from given policy')
@click.option('-i', '--image-id', type=click.INT, required=True,
              help='Image ID')
@click.option('-t', '--image-type', default='BOOT',
              help='The image type - BOOT or UPGRADE')
@click.option('-h', 'display_hex', is_flag=True,
              help='Display result as hexadecimal')
@click.pass_context
def cmd_slot_address(ctx, image_id, image_type, display_hex):
    def process():
        if 'TOOL' not in ctx.obj:
            return False
        try:
            address, size = ctx.obj['TOOL'].flash_map(image_id, image_type)
        except Exception as e:
            address = None
            logger.error(e)
            logger.debug(e, exc_info=True)
        if address:
            print(hex(address) if display_hex else address)
            return True
        else:
            return False

    return process


@main.command('slot-size', short_help='Gets slot size from given policy')
@click.option('-i', '--image-id', type=click.INT, required=True,
              help='Image ID')
@click.option('-t', '--image-type', default='BOOT',
              help='The image type - BOOT or UPGRADE')
@click.option('-h', 'display_hex', is_flag=True,
              help='Display result as hexadecimal')
@click.pass_context
def cmd_slot_size(ctx, image_id, image_type, display_hex):
    def process():
        if 'TOOL' not in ctx.obj:
            return False
        try:
            address, size = ctx.obj['TOOL'].flash_map(image_id, image_type)
        except Exception as e:
            size = None
            logger.error(e)
            logger.debug(e, exc_info=True)
        if size:
            print(hex(size) if display_hex else size)
            return True
        else:
            return False

    return process


@main.command('read-public-key', help='Reads public key from device')
@click.option('-k', '--key-id', type=click.INT, required=True,
              help='Key ID to read (1 - DEVICE, 4 - HSM, 5 - OEM, 12 - GROUP')
@click.option('-f', '--key-format', default='jwk',
              help='Key format (jwk or pem)')
@click.option('-o', '--out-file', default=None,
              help='Filename where to save the key')
@click.option('--probe-id', default=None,
              help='Probe serial number')
@click.pass_context
def cmd_read_public_key(ctx, key_id, key_format, out_file, probe_id):
    def process():
        if 'TOOL' not in ctx.obj:
            return False
        key = None
        try:
            key = ctx.obj['TOOL'].read_public_key(key_id, key_format, out_file,
                                                  probe_id)
        except AssertionError:
            print_assertion_error()
        except Exception as e:
            logger.error(e)
            logger.debug(e, exc_info=True)
        if key:
            if type(key) is dict:
                logger.info(json.dumps(key, indent=4))
            elif type(key) is bytes:
                logger.info(key.decode("utf-8"))
            else:
                logger.info(key)
            return True
        else:
            return False

    return process


@main.command('read-die-id', help='Reads die ID from device')
@click.option('-o', '--out-file', default=None,
              help='Filename where to save die ID')
@click.option('--probe-id', default=None,
              help='Probe serial number')
@click.option('--ap', hidden=True, type=click.Choice(['cm0', 'cm4', 'sysap']),
              default='sysap', help='The access port used to read the data')
@click.pass_context
def cmd_read_die_id(ctx, out_file, probe_id, ap):
    def process():
        if 'TOOL' not in ctx.obj:
            return False
        data = None
        try:
            data = ctx.obj['TOOL'].read_die_id(probe_id, ap)
        except AssertionError:
            print_assertion_error()
        except Exception as e:
            logger.error(e)
            logger.debug(e, exc_info=True)
        if data:
            logger.info(f'die_id = {json.dumps(data, indent=4)}')
            if out_file:
                with open(out_file, 'w') as f:
                    json.dump(data, f, indent=4)
            return True
        else:
            return False

    return process


@main.command('sign-cert', help='Signs JSON certificate with the private key')
@click.option('-j', '--json-file', type=click.File('r'), required=True,
              help='JSON file to be signed')
@click.option('-k', '--key-id', type=click.INT, required=True,
              help='Private Key ID to sign the certificate with '
                   '(1 - DEVICE, 4 - HSM, 5 - OEM, 12 - GROUP')
@click.option('-o', '--out-file', default=None,
              help='Filename where to save the JWT. If not specified, the '
                   'input file name with "jwt" extension will be used')
@click.pass_context
def cmd_sign_cert(ctx, json_file, key_id, out_file):
    def process():
        if 'TOOL' not in ctx.obj:
            return False
        try:
            token = ctx.obj['TOOL'].sign_json(json_file.name, key_id, out_file)
        except Exception as e:
            token = None
            logger.error(e)
            logger.debug(e, exc_info=True)
        return True if token else False

    return process


@main.command('probe-list', hidden=True,
              help='Prints a list of connected probes')
@click.pass_context
def cmd_probe_list(ctx):
    def process():
        if 'TOOL' not in ctx.obj:
            return False
        try:
            probes = ctx.obj['TOOL'].get_probe_list()
            if probes:
                for probe in probes:
                    probe_name = re.sub('[\[].*?[\]]', '', probe.description)
                    print(probe_name.strip(), probe.unique_id)
            else:
                print('No available debug probes are connected',
                      file=sys.stderr)
        except Exception as e:
            logger.error(e)
            logger.debug(e, exc_info=True)
        return True

    return process


@main.command('device-info', hidden=True,
              help='Gets device information')
@click.option('--probe-id', default=None,
              help='Probe serial number')
@click.option('--ap', type=click.Choice(['cm0', 'cm4', 'sysap']),
              default='sysap', help='The access port used to read the data')
@click.pass_context
def cmd_device_info(ctx, probe_id, ap):
    def process():
        if 'TOOL' not in ctx.obj:
            return False
        try:
            dev_info = ctx.obj['TOOL'].get_device_info(probe_id, ap)
            if dev_info:
                logger.info(f'Silicon: {hex(dev_info.silicon_id)}, '
                            f'Family: {hex(dev_info.family_id)}, '
                            f'Rev.: {hex(dev_info.silicon_rev)}')
        except Exception as e:
            logger.error(e)
            logger.debug(e, exc_info=True)
        return True

    return process


@main.command('init', help='Initializes new project')
@click.pass_context
def cmd_init(ctx):
    def process():
        if 'TOOL' not in ctx.obj:
            return False
        try:
            ctx.obj['TOOL'].init()
            result = True
        except Exception as e:
            result = False
            logger.error(e)
            logger.debug(e, exc_info=True)
        return result

    return process
