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
import os
import sys
import click

from cysecuretools.targets import target_map
from cysecuretools import cli as base_cli


class CliCreator:
    @staticmethod
    def create():
        is_help = '--help' in sys.argv[1:]

        target = CliCreator.option_from_args(['-t', '--target'])

        common_commands = CliCreator._command_list(base_cli.main)
        if not any(a in common_commands for a in sys.argv[1:]):
            if target is None and is_help:
                CliCreator._print_help_instructions()
                sys.stderr.write("Error: Missing option '-t' / '--target'.\n")
                sys.exit(2)

        CliCreator.validate_target_presence(target)

        platform = CliCreator._get_platform(target)
        if platform == 'mxs40sv2':
            if not is_help:
                CliCreator.validate_policy_presence(target)
            from cysecuretools import cli_mxs40sv2
            cli_mxs40sv2.main()  # pylint: disable=no-value-for-parameter
        elif platform == 'psoc64':
            from cysecuretools import cli_mxs40v1
            cli_mxs40v1.main()  # pylint: disable=no-value-for-parameter
        else:
            CliCreator.unknown_target_error(target)

    @staticmethod
    def validate_target_presence(target):
        """ Validates 'target' option presence. Exits the process
        on error.

        Specifying target is necessary for all commands except the
        common commands (those which do not require specifying target)
        """
        platform = CliCreator._get_platform(target)
        if target is None or platform is None:
            common_commands = CliCreator._command_list(base_cli.main)
            if any(a in common_commands for a in sys.argv[1:]):
                base_cli.main()  # pylint: disable=no-value-for-parameter
            elif target is None:
                CliCreator.option_error(target, ['-t', '--target'])

    @staticmethod
    def validate_policy_presence(target):
        """ Validates 'policy' option presence. Exits the process
        on error.

        For the mxs40sv2 platform, specifying policy is necessary for
        all commands except the common commands (those which do not
        require specifying target) and 'init' command
        """
        platform = CliCreator._get_platform(target)
        if platform == 'mxs40sv2':
            common_cmds = CliCreator._command_list(base_cli.main)
            from cysecuretools import cli_mxs40sv2
            mxs40v2_cmds = CliCreator._command_list(cli_mxs40sv2.main)
            mxs40v2_cmds = [c for c in mxs40v2_cmds if c not in common_cmds]
            mxs40v2_cmds.remove('init')
            mxs40v2_cmds.remove('extend-image')
            mxs40v2_cmds.remove('device-info')
            mxs40v2_cmds.remove('read-die-id')
            mxs40v2_cmds.remove('load-and-run-app')
            mxs40v2_cmds.remove('convert-to-rma')
            policy = CliCreator.option_from_args(['-p', '--policy'])
            if policy is None:
                if any(a in mxs40v2_cmds for a in sys.argv[1:]):
                    CliCreator.option_error(target, ['-p', '--policy'])

    @staticmethod
    def option_error(target, opt):
        """ Shows missing option error and exits the process """
        if len(opt) == 0:
            raise ValueError('No options specified')
        if len(opt) > 2:
            raise ValueError('More than two options specified')

        app_name = os.path.basename(sys.argv[0])
        if target is not None:
            sys.stderr.write(
                f"Try '{app_name} -t {target} --help' for help.\n\n")

        if len(opt) == 1:
            sys.stderr.write(f"Error: Missing option '{opt[0]}'.\n")
        if len(opt) == 2:
            sys.stderr.write(
                f"Error: Missing option '{opt[0]}' / '{opt[1]}'.\n")
        sys.exit(2)

    @staticmethod
    def unknown_target_error(target):
        """ Shows unknown target error and exits the process """
        app_name = os.path.basename(sys.argv[0])
        sys.stderr.write(f"Try '{app_name} device-list' for output of the "
                         f"supported devices list.\n\n")
        sys.stderr.write(f'Error: Unknown target \'{target}\'.\n')
        sys.exit(2)

    @staticmethod
    def option_from_args(opt):
        """ Gets specified option from command line arguments """
        args = sys.argv[1:]
        try:
            return [args[i + 1] for i in range(len(args)) if args[i] in opt][0]
        except IndexError:
            return None

    @staticmethod
    def _get_platform(target):
        platform = None
        if target is not None:
            try:
                platform = target_map[target.lower()].get('platform')
            except KeyError:
                platform = None
        return platform

    @staticmethod
    def _command_list(obj):
        if isinstance(obj, click.Group):
            return [name for name, value in obj.commands.items()]

    @staticmethod
    def _print_help_instructions():
        app_name = os.path.basename(sys.argv[0])
        print('Command line interfaces are different for different targets.\n')
        print('To see a list of commands supported for a specific target:')
        print(f'{app_name} -t <TARGET> --help\n')
        print('To see a list of options for a specific command:')
        print(f'{app_name} -t <TARGET> <COMMAND> --help\n')
        print('To see a list of available targets:')
        print(f'{app_name} device-list\n')
