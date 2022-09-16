"""
Copyright (c) 2021-2022 Cypress Semiconductor Corporation

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
import re
import sys
import json
import click
import logging
import traceback
from . import pkg_globals
from cysecuretools import CySecureTools
from cysecuretools.targets import get_target_builder
from cysecuretools.core.target_director import TargetDirector
from cysecuretools.core.logging_configurator import LoggingConfigurator
from cysecuretools.targets import print_targets, print_targets_extended
from .core.project import ProjectInitializer
from .execute.programmer.programmer import ProgrammingTool

logger = logging.getLogger(__name__)


def require_target():
    return not (('device-list' in sys.argv)
                or ('version' in sys.argv)
                or ('probe-list' in sys.argv)
                or ('set-ocd' in sys.argv)
                or ('bin2hex' in sys.argv))


@click.group(chain=True)
@click.pass_context
@click.option('-t', '--target', type=click.STRING, required=require_target(),
              help='Device name or family')
@click.option('-p', '--policy', type=click.File(), required=False,
              help='Provisioning policy file')
@click.option('-v', '--verbose', is_flag=True, help='Provides debug-level log')
@click.option('-q', '--quiet', is_flag=True, help='Quiet display option')
@click.option('--logfile-off', is_flag=True, help='Avoids logging into file')
@click.option('--no-interactive-mode', is_flag=True, hidden=True,
              help='Skips user interactive prompts')
@click.option('--skip-validation', is_flag=True, hidden=True,
              help='Skips policy validation')
def main(ctx, target, policy, verbose, quiet,
         logfile_off, no_interactive_mode, skip_validation):
    """
    Common options (e.g. -t, -p, -v, -q) are common for all commands and must
    precede them:

    \b
    cysecuretools -t <TARGET> -p <POLICY> <COMMAND> --<COMMAND_OPTION>

    \b
    For detailed help for command use:

    \b
    cysecuretools <COMMAND> --help

    \b
    For detailed usage description refer to readme.md
    """
    if quiet:
        LoggingConfigurator.disable_logging()
    elif verbose:
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
        ctx.obj['TOOL'] = CySecureTools(target, policy_path, log_file,
                                        no_interactive_mode,
                                        skip_validation)
    else:
        if 'version' in sys.argv:
            if '--target' in sys.argv or '-t' in sys.argv:
                ctx.obj['TOOL'] = CySecureTools(
                    target, policy.name if policy else None,
                    log_file=log_file, skip_prompts=no_interactive_mode,
                    skip_validation=skip_validation)
        else:
            ctx.obj['TOOL'] = CySecureTools(
                target, policy.name if policy else None,
                log_file=log_file, skip_prompts=no_interactive_mode,
                skip_validation=skip_validation)
    logger.debug(sys.argv)


@main.result_callback()
def process_pipeline(processors, **_):
    for func in processors:
        res = func()
        if not res:
            raise click.ClickException('Failed processing!')


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
def cmd_probe_list(ctx):
    @process_handler()
    def process():
        if 'TOOL' not in ctx.obj:
            return False
        if ctx.obj['TOOL'].ocd_name == 'pyocd':
            probes = ctx.obj['TOOL'].get_probe_list()
            if probes:
                for probe in probes:
                    probe_name = re.sub(r'[\[].*?[\]]', '', probe.description)
                    print(probe_name.strip(), probe.unique_id)
            else:
                print('No available debug probes are connected',
                      file=sys.stderr)
        else:
            sys.stderr.write("Error: The selected OCD does not support "
                             "this feature.\n")
        return True

    return process


@main.command('set-ocd', help='Sets on-chip debugger')
@click.option('-n', '--name', required=True, help='Tool name',
              type=click.Choice(['pyocd', 'openocd']))
@click.option('-p', '--path', default=None,
              help='Path to the tool root directory')
@click.pass_context
def cmd_set_ocd(_ctx, name, path):
    @process_handler()
    def process():
        ocd_path = path
        tool = ProgrammingTool.create(name)
        if ProjectInitializer.is_project():
            if not ocd_path and tool.require_path:
                with open(
                        pkg_globals.SETTINGS_FILE, 'r', encoding='utf-8') as f:
                    file_content = f.read()
                    data = json.loads(file_content)
                if data['programming_tool']['path']:
                    ocd_path = data['programming_tool']['path']
                    ProjectInitializer.set_ocd_data(name, ocd_path)
                    logger.info(
                        "The OCD path is not specified. Global settings "
                        "applied: '%s'", data['programming_tool']['path'])
                else:
                    validate_args(tool)
            else:
                ProjectInitializer.set_ocd_data(name, ocd_path)
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
                exit(2)

    return process


@main.command('version', short_help='Show package version info')
@click.pass_context
def cmd_version(_ctx):
    @process_handler()
    def process():
        from cysecuretools.version import __version__
        print(f'CySecureTools: {__version__}')
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
def cmd_bin2hex(ctx, image, output, offset):
    @process_handler()
    def process():
        if 'TOOL' not in ctx.obj:
            return False
        return ctx.obj['TOOL'].bin2hex(image, output, int(offset, 0))

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


def default_policy(target_name):
    director = TargetDirector()
    target_name = target_name.lower()
    get_target_builder(director, target_name)
    target = director.get_target(None, target_name, None)
    return target.policy


def validate_init_cmd_args():
    if '--policy' in sys.argv:
        sys.stderr.write('Error: invalid argument used with "init" '
                         'command: --policy\n')
        exit(1)
    if '-p' in sys.argv:
        sys.stderr.write('Error: invalid argument used with "init" '
                         'command: -p\n')
        exit(1)


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
