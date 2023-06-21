"""
Copyright 2021-2023 Cypress Semiconductor Corporation (an Infineon company)
or an affiliate of Cypress Semiconductor Corporation. All rights reserved.

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
import sys
import logging
import traceback

import json
import click

from . import pkg_globals
from . import ProvisioningPackage

from .__about__ import __version__, __pkg_name__
from .api_common import CommonAPI
from .execute.imgtool.main import get_dependencies, validate_security_counter
from .targets import get_target_builder
from .core.target_director import TargetDirector
from .core.logging_configurator import LoggingConfigurator
from .targets import print_targets, print_targets_extended
from .core.project_base import ProjectInitializerBase
from .execute.programmer.programmer import ProgrammingTool

logger = logging.getLogger(__name__)


def require_target():
    """Indicates whether sys.argv contains a command that require target
    option"""
    commands = [
        'device-list', 'version', 'probe-list', 'set-ocd', 'bin2hex',
        'convert-key', 'sign-image', 'image-metadata', 'extract-payload',
        'add-signature', 'verify-image'
    ]
    return not any(x in sys.argv for x in commands)


@click.group(chain=True)
@click.pass_context
@click.option('-t', '--target', help='Device name or family')
@click.option('--rev', help='Device revision')
@click.option('-p', '--policy', type=click.File(), required=False,
              help='Provisioning policy file')
@click.option('-v', '--verbose', is_flag=True, help='Provides debug-level log')
@click.option('-q', '--quiet', is_flag=True, help='Quiet display option')
@click.option('--logfile-off', is_flag=True, help='Avoids logging into file')
@click.option('--no-interactive-mode', is_flag=True, hidden=True,
              help='Skips user interactive prompts')
@click.option('--skip-validation', is_flag=True, hidden=True,
              help='Skips policy validation')
def main(ctx, target, rev, policy, verbose, quiet,
         logfile_off, no_interactive_mode, skip_validation):
    """
    Common options (e.g. -t, --rev, -p, -v, -q) are common for all commands and
    must precede them:

    <PACKAGE_NAME> -t <TARGET> -p <POLICY> <COMMAND> --<COMMAND_OPTION>

    To see command options:

    <PACKAGE_NAME> <COMMAND> --help
    """
    if quiet:
        LoggingConfigurator.disable_logging()
    elif verbose:
        LoggingConfigurator.set_logger_level(logging.DEBUG)
    logger.debug(sys.argv)

    ctx.ensure_object(dict)
    log_file = not logfile_off

    if 'init' in sys.argv:
        validate_init_cmd_args()
        try:
            policy_path = default_policy(target, rev=rev)
        except ValueError as e:
            logger.error(e)
            sys.exit(2)
        log_file = False
    else:
        policy_path = policy.name if policy else None
    try:
        ctx.obj['TOOL'] = ProvisioningPackage(
            target=target,
            policy=policy_path,
            log_file=log_file,
            skip_prompts=no_interactive_mode,
            skip_validation=skip_validation,
            rev=rev)
    except ValueError as e:
        logger.error(e)
        sys.exit(2)


@main.result_callback()
def process_pipeline(processors, **_):
    for func in processors:
        res = func()
        if not res:
            sys.stderr.write('Failed processing!')
            sys.exit(2)


@main.command('power-on', hidden=True, help='Turns the power on')
@click.option('-v', '--voltage', type=click.INT,
              help='Sets target power voltage in mV')
@click.pass_context
def cmd_power_on(ctx, voltage):
    @process_handler()
    def process():
        if 'TOOL' not in ctx.obj:
            return False
        return ctx.obj['TOOL'].power_on(voltage)

    return process


@main.command('power-off', hidden=True, help='Turns the power off')
@click.pass_context
def cmd_target_power_off(ctx):
    @process_handler()
    def process():
        if 'TOOL' not in ctx.obj:
            return False
        return ctx.obj['TOOL'].power_off()

    return process


@main.command('device-list', help='List of supported devices')
@click.option('--extended', hidden=True, is_flag=True,
              help='Provides targets extended data')
@click.pass_context
def cmd_device_list(_ctx, extended):
    @process_handler()
    def process():
        if extended:
            print_targets_extended()
        else:
            print_targets()
        return True

    return process


@main.command('probe-list', hidden=True,
              help='Prints a list of connected probes')
@click.pass_context
def cmd_probe_list(_ctx):
    """Prints a list of connected probes"""
    @process_handler()
    def process():
        sys.stderr.write(
            "Error: The selected OCD does not support this feature.\n")
        return True

    return process


@main.command('set-ocd', help='Sets on-chip debugger')
@click.option('-n', '--name', required=True, help='Tool name',
              type=click.Choice(['openocd', 'serial']))
@click.option('-p', '--path', help='Path to the tool root directory')
@click.pass_context
def cmd_set_ocd(_ctx, name, path):
    @process_handler()
    def process():
        ocd_path = path
        tool = ProgrammingTool.create(name)
        if ProjectInitializerBase.is_project():
            if not ocd_path and tool.require_path:
                with open(
                        pkg_globals.SETTINGS_FILE, 'r', encoding='utf-8') as f:
                    file_content = f.read()
                    data = json.loads(file_content)
                if data['programming_tool']['path']:
                    ocd_path = data['programming_tool']['path']
                    ProjectInitializerBase.set_ocd_data(name, ocd_path)
                    logger.info(
                        "The OCD path is not specified. Global settings "
                        "applied: '%s'", data['programming_tool']['path'])
                else:
                    validate_args(tool)
            else:
                ProjectInitializerBase.set_ocd_data(name, ocd_path)
            logger.info('Data in the project settings file changed')
        else:
            validate_args(tool)
            with open(pkg_globals.SETTINGS_FILE, 'r+', encoding='utf-8') as f:
                file_content = f.read()
                data = json.loads(file_content)
                data['programming_tool']['name'] = name
                data['programming_tool']['path'] = ocd_path
                f.seek(0)
                f.write(json.dumps(data, indent=4))
                f.truncate()
            logger.info('Data in the package settings file changed')

        if tool.require_path and ocd_path and not os.path.exists(ocd_path):
            logger.warning("Path '%s' does not exist", ocd_path)

        return True

    def validate_args(tool):
        if path is None:
            if tool.require_path:
                sys.stderr.write(f"Error: Missing option '--path'. Using "
                                 f"'{tool.name}' requires a path to be set.\n")
                sys.exit(2)

    return process


@main.command('version', short_help='Show package version info')
@click.pass_context
def cmd_version(_ctx):
    @process_handler()
    def process():
        print(f'{__pkg_name__}: {__version__}')
        return True

    return process


@main.command('bin2hex', help='Converts binary image to hex',
              short_help='Converts binary image to hex')
@click.option('--image', type=click.Path(), required=True,
              help='Input bin file')
@click.option('-o', '--output', type=click.Path(), required=True,
              help='Output hex file')
@click.option('--offset', default='0',
              help='Starting address offset for loading bin')
@click.pass_context
def cmd_bin2hex(_ctx, image, output, offset):
    @process_handler()
    def process():
        return CommonAPI.bin2hex(image, output, int(offset, 0))

    return process


@main.command('convert-key', help='Converts  key to other formats')
@click.option('-f', '--fmt', 'fmt',
              type=click.Choice(
                  ['pem', 'der', 'jwk', 'c_array', 'secure_boot'],
                  case_sensitive=False
              ), required=True, help='Output key format')
@click.option('-k', '--key-path', type=click.Path(), required=True,
              help='Input key path')
@click.option('-o', '--output', type=click.Path(), required=True,
              help='Output file')
@click.option('--endian', 'endian',
              type=click.Choice(['big', 'little'], case_sensitive=False),
              default='little', help='Byte order')
@click.pass_context
def cmd_convert_key(_ctx, fmt, key_path, output, endian):
    @process_handler()
    def process():
        CommonAPI.convert_key(
            key_path, fmt, endian=endian, output=output
        )
        return True

    return process


@main.command('sign-image', hidden=True,
              short_help='Signs the user application with a key. Optionally '
                         'encrypts the signed application',
              help='Signs the user application with a key. Optionally '
                   'encrypts the signed application')
@click.option('-i', '--image', type=click.Path(), required=True,
              help='The user application file. The output file format is based '
                   'on the input file extension (bin or hex)')
@click.option('-o', '--output', type=click.Path(), required=True,
              help='The signed image output file')
@click.option('--key', '--key-path', 'key', type=click.Path(), required=True,
              help='The path to the key used to sign the image')
@click.option('--image-config', type=click.Path(), hidden=True,
              help='The path to the image configuration file')
@click.option('-R', '--erased-val', default='0',
              type=click.Choice(['0', '0xff'], case_sensitive=False),
              help='The value, which is read back from erased flash. Default: 0')
@click.option('-H', '--header-size', default=32,
              help='Sets the image header size. Default: 32')
@click.option('-S', '--slot-size', default=0x100000,
              help='Sets the maximum slot size. Default: 0x100000')
@click.option('--image-version', default='0.0.0',
              help='Sets the image version in the image header')
@click.option('-s', '--security-counter', callback=validate_security_counter,
              help='Specify the value of security counter. Use the `auto` '
                   'keyword to automatically generate it from the image version')
@click.option('--align', type=click.Choice(['1', '2', '4', '8']), default='8',
              help='Flash alignment. Default: 8')
@click.option('--pad', is_flag=True, help='Add padding to the image trailer')
@click.option('--confirm', is_flag=True, help='Add image OK status to trailer')
@click.option('--overwrite-only', is_flag=True,
              help='Use overwrite mode instead of swap')
@click.option('--hex-addr', help='Adjust the address in the hex output file')
@click.option('-d', '--dependencies', callback=get_dependencies,
              required=False, help='Add dependence on another image. Format: '
              '"(<image_ID>,<image_version>), ... "')
@click.option('--encrypt', type=click.Path(),
              help='Encrypt image using the provided public key')
@click.option('-e', '--endian', type=click.Choice(['little', 'big']),
              default='little', help="Byte order")
@click.option('--protected-tlv', required=False, nargs=2, default=[],
              multiple=True, metavar='[tag] [value]',
              help='The custom TLV to be placed into a protected area (the '
                   'signed part). Add the "0x" prefix for the value to be '
                   'interpreted as an integer, otherwise it will be '
                   'interpreted as a string. Specify the option multiple times '
                   'to add multiple TLVs')
@click.option('--tlv', required=False, nargs=2, default=[],
              multiple=True, metavar='[tag] [value]',
              help='The custom TLV to be placed into a non-protected area. '
                   'Add the "0x" prefix for the value to be interpreted as an '
                   'integer, otherwise it will be interpreted as a string. '
                   'Specify the option multiple times to add multiple TLVs')
@click.pass_context
def cmd_sign_image(ctx, image, output, key, image_config, erased_val,
                   header_size, slot_size, image_version, security_counter,
                   align, pad, confirm, overwrite_only, hex_addr, dependencies,
                   encrypt, endian, protected_tlv, tlv):
    """Signs application image"""
    @process_handler()
    def process():
        if 'TOOL' not in ctx.obj:
            return False
        result = ctx.obj['TOOL'].sign_image(
            image,
            output=output,
            key_path=key,
            image_config=image_config,
            erased_val=erased_val,
            header_size=header_size,
            slot_size=slot_size,
            image_version=image_version,
            security_counter=security_counter,
            align=align,
            pad=pad,
            confirm=confirm,
            overwrite_only=overwrite_only,
            hex_addr=hex_addr,
            dependencies=dependencies,
            encrypt=encrypt,
            endian=endian,
            prot_tlv=protected_tlv,
            tlv=tlv
        )
        return result is not None

    return process


@main.command('image-metadata', hidden=True,
              short_help='Adds MCUboot metadata to a firmware image',
              help='Adds MCUboot metadata to a firmware image')
@click.option('-i', '--image', type=click.Path(), required=True,
              help='The user application file (bin or hex)')
@click.option('-o', '--output', type=click.Path(), required=True,
              help='The path to the binary file to save the image with metadata')
@click.option('--decrypted', type=click.Path(),
              help='The path where to save decrypted image payload')
@click.option('--key-type', type=click.Choice(
              ['ECDSA-P256', 'RSA2048', 'RSA4096'], case_sensitive=False),
              help='The key type for creating a placeholder')
@click.option('--image-config', type=click.Path(), hidden=True,
              help='The path to the image configuration file')
@click.option('-R', '--erased-val', default='0',
              type=click.Choice(['0', '0xff'], case_sensitive=False),
              help='The value, which is read back from erased flash. Default: 0')
@click.option('-H', '--header-size', default=32,
              help='Sets the image header size. Default: 32')
@click.option('-S', '--slot-size', default=0x100000,
              help='Sets the maximum slot size. Default: 0x100000')
@click.option('--image-version', default='0.0.0',
              help='Sets the image version in the image header')
@click.option('-s', '--security-counter', callback=validate_security_counter,
              help='Specify the value of security counter. Use the `auto` '
                   'keyword to automatically generate it from the image version')
@click.option('--align', type=click.Choice(['1', '2', '4', '8']), default='8',
              help='Flash alignment. Default: 8')
@click.option('--pad', is_flag=True, help='Add padding to the image trailer')
@click.option('--confirm', is_flag=True, help='Add image OK status to trailer')
@click.option('-d', '--dependencies', callback=get_dependencies,
              required=False, help='Add dependence on another image. Format: '
              '"(<image_ID>,<image_version>), ... "')
@click.option('--encrypt', type=click.Path(),
              help='Encrypt image using the provided public key')
@click.option('--protected-tlv', required=False, nargs=2, default=[],
              multiple=True, metavar='[tag] [value]',
              help='The custom TLV to be placed into a protected area (the '
                   'signed part). Add the "0x" prefix for the value to be '
                   'interpreted as an integer, otherwise it will be '
                   'interpreted as a string. Specify the option multiple times '
                   'to add multiple TLVs')
@click.option('--tlv', required=False, nargs=2, default=[],
              multiple=True, metavar='[tag] [value]',
              help='The custom TLV to be placed into a non-protected area. '
                   'Add the "0x" prefix for the value to be interpreted as an '
                   'integer, otherwise it will be interpreted as a string. '
                   'Specify the option multiple times to add multiple TLVs')
@click.pass_context
def cmd_image_metadata(ctx, image, output, decrypted, key_type, image_config,
                       erased_val, header_size, slot_size, image_version,
                       security_counter, align, pad, confirm, dependencies,
                       encrypt, protected_tlv, tlv):
    """Adds MCUboot metadata to a firmware image"""
    @process_handler()
    def process():
        if 'TOOL' not in ctx.obj:
            return False
        validate_args()
        result = ctx.obj['TOOL'].image_metadata(
            image,
            output=output,
            decrypted=decrypted,
            key_type=key_type,
            image_config=image_config,
            erased_val=erased_val,
            header_size=header_size,
            slot_size=slot_size,
            image_version=image_version,
            security_counter=security_counter,
            align=align,
            pad=pad,
            confirm=confirm,
            dependencies=dependencies,
            encrypt=encrypt,
            prot_tlv=protected_tlv,
            tlv=tlv
        )
        return result is not None

    def validate_args():
        if encrypt and not decrypted:
            sys.stderr.write("If encryption is being used, the '--decrypted' "
                             "argument is required.\n")

    return process


@main.command('extract-payload', hidden=True,
              help='Extracts a part of image to be signed',
              short_help='Extracts a part of image to be signed')
@click.option('--image', type=click.Path(), required=True,
              help='Image with MCUboot metadata (bin)')
@click.option('-o', '--output', type=click.Path(), required=True,
              help='The path where to save the image to be signed (bin)')
@click.pass_context
def cmd_extract_payload(ctx, image, output):
    """Extracts a part of image to be signed"""
    @process_handler()
    def process():
        if 'TOOL' not in ctx.obj:
            return False
        ctx.obj['TOOL'].extract_payload(image, output)
        return True

    return process


@main.command('add-signature', hidden=True,
              help='Adds signature to the existing MCUboot format image',
              short_help='Adds signature to the existing MCUboot format image')
@click.option('--image', type=click.Path(), required=True,
              help='Image with MCUboot metadata (bin)')
@click.option('-s', '--signature', type=click.Path(), required=True,
              help='Binary file containing signature')
@click.option('--alg', type=click.Choice(
              ['ECDSA-P256', 'RSA2048', 'RSA4096'], case_sensitive=False),
              required=True, help='Signature algorithm')
@click.option('-o', '--output', type=click.Path(), required=True,
              help='The path where to save the image with the signature (bin)')
@click.pass_context
def cmd_add_signature(ctx, image, signature, alg, output):
    """Adds signature to the existing MCUboot format image"""
    @process_handler()
    def process():
        if 'TOOL' not in ctx.obj:
            return False
        ctx.obj['TOOL'].add_signature(image, signature, output, alg=alg)
        return True

    return process


@main.command('verify-image', hidden=True, help='Verifies image with a key')
@click.option('--image', type=click.Path(), required=True,
              help='The path to the image')
@click.option('--key', '--key-path', 'key', type=click.Path(),
              help='The path to the public key')
@click.pass_context
def cmd_verify_image(ctx, image, key):
    """Verifies image with a key"""
    @process_handler()
    def process():
        if 'TOOL' not in ctx.obj:
            return False
        return ctx.obj['TOOL'].verify_image(image, key=key)

    return process


def print_assertion_error():
    _, _, tb = sys.exc_info()
    tb_info = traceback.extract_tb(tb)
    stack_trace = ''
    for item in traceback.StackSummary.from_list(tb_info).format():
        stack_trace += item
    stack_trace = stack_trace.rstrip('\n')
    logger.debug(stack_trace)
    filename, line, _, text = tb_info[-1]
    logger.error("An error occurred in file '%s' on line %d in statement %s",
                 filename, line, text)


def default_policy(target_name, rev=None):
    director = TargetDirector()
    target_name = target_name.lower()
    get_target_builder(director, target_name, rev=rev)
    target = director.get_target(None, target_name, None)
    return target.policy


def validate_init_cmd_args():
    if '--policy' in sys.argv:
        sys.stderr.write('Error: invalid argument used with "init" '
                         'command: --policy\n')
        sys.exit(1)
    if '-p' in sys.argv:
        sys.stderr.write('Error: invalid argument used with "init" '
                         'command: -p\n')
        sys.exit(1)


def process_handler(process_fail_value=False):
    def function_decorator(func):
        def inner_function(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except AssertionError:
                print_assertion_error()
            except Exception as e:  # pylint: disable=broad-except
                logger.error(e)
                logger.debug(e, exc_info=True)
            return process_fail_value
        return inner_function
    return function_decorator
