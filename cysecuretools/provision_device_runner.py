"""
Copyright (c) 2018-2019 Cypress Semiconductor Corporation

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
from cysecuretools.execute.enums import ProtectionState
from cysecuretools.execute.provision_device import provision_execution
from cysecuretools.execute.programmer.programmer import ProgrammingTool
from cysecuretools.prepare.provisioning_lib.cyprov_pem import PemKey

TOOL_NAME = 'pyocd'  # Programming/debugging tool used for communication with device


@click.command()
@click.option('--prov-jwt', 'prov_cmd_jwt',
              default='packet/prov_cmd.jwt',
              type=click.STRING,
              help='Path to provisioning JWT file (packet which contains all data necessary '
                   'for provisioning, including policy, authorization packets and keys)')
@click.option('--hex', 'cy_bootloader_hex',
              default='prebuild/CyBootloader_Release/CypressBootloader_CM0p.hex',
              type=click.STRING,
              help='Path to Cypress Bootloader HEX binary file')
@click.option('--pubkey-json', 'pub_key_json',
              default='keys/dev_pub_key.json',
              type=click.STRING,
              help='File where to save public key in JSON format')
@click.option('--pubkey-pem', 'pub_key_pem',
              default='keys/dev_pub_key.pem',
              type=click.STRING,
              help='File where to save public key in PEM format')
@click.option('--protection-state', 'protection_state',
              default=ProtectionState.secure,
              type=click.INT,
              help='Expected target protection state. The argument is for Cypress internal use only.',
              hidden=True)
@click.option('--probe-id', 'probe_id',
              default=None,
              type=click.STRING,
              help='Probe ID. The argument is used to avoid prompt to select HW when more than one HW connected.',
              hidden=True)
@click.option('--target', 'target',
              default=None,
              type=click.STRING,
              help='The name of the target used for provisioning.',
              hidden=True)
def main(prov_cmd_jwt, cy_bootloader_hex, pub_key_json, pub_key_pem, protection_state, target, probe_id=None):
    """
    Parses command line arguments and provides high level support for
    provisioning device with the specified programming tool.
    """
    test_status = False
    tool = ProgrammingTool.create(TOOL_NAME)
    if tool.connect(target, probe_id=probe_id):
        test_status = provision_execution(tool, pub_key_json, prov_cmd_jwt, cy_bootloader_hex,
                                          ProtectionState(protection_state))
        tool.disconnect()

    if test_status:
        # Read device public key from response file and save the key in pem format
        if os.path.exists(pub_key_json):
            pem = PemKey(pub_key_json)
            pem.save(pub_key_pem, private_key=False)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
