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
import sys
import click
import logging
from cryptography.hazmat.primitives import serialization
from cysecuretools import CySecureTools
from cysecuretools.execute.enums import ProtectionState

logger = logging.getLogger(__name__)


def is_help():
    return '--help' in sys.argv


@click.group(chain=True)
@click.pass_context
@click.option('-t', '--target', 'target', type=click.STRING, required=not is_help(),
              help='Device manufacturing part number')
@click.option('-p', '--policy', 'policy', type=click.File(), required=False,
              help='Provisioning policy file')
@click.option('-v', '--verbose', is_flag=True, help='Provides debug-level log')
def main(ctx, target, policy, verbose):
    if verbose:
        logger.root.setLevel(logging.DEBUG)
    ctx.ensure_object(dict)

    if not is_help():
        ctx.obj['TOOL'] = CySecureTools(target, policy.name if policy else None)


@main.resultcallback()
def process_pipeline(processors, target, policy, verbose):
    for func in processors:
        res = func()
        if not res:
            raise click.ClickException('Failed processing!')


@main.command('create-keys', help='Creates keys specified in policy file')
@click.pass_context
@click.option('--overwrite/--no-overwrite', 'overwrite', is_flag=True, default=None, required=False,
              help='Indicates whether overwrite keys in the output directory if they already exist')
@click.option('-o', '--out', 'out', type=click.Path(), default=None, required=False,
              help='Output directory for generated keys. By default keys location is as specified in the policy file')
def cmd_create_keys(ctx, overwrite, out):
    def process():
        result = ctx.obj['TOOL'].create_keys(overwrite=overwrite, out=out)
        return result is not False

    return process


@main.command('sign-image', short_help='Signs firmware image with the key specified in the policy file')
@click.pass_context
@click.option('-h', '--hex', 'hex_file', type=click.Path(), required=True, help='User application hex file')
@click.option('-i', '--image-id', 'image_id', type=click.INT, default=4, required=False,
              help='The ID of the firmware image in the policy file')
def cmd_sign_image(ctx, hex_file, image_id):
    def process():
        result = ctx.obj['TOOL'].sign_image(hex_file, image_id)
        return result is not None

    return process


@main.command('create-provisioning-packet', help='Creates JWT packet for device provisioning')
@click.pass_context
def cmd_create_provisioning_packet(ctx):
    def process():
        result = ctx.obj['TOOL'].create_provisioning_packet()
        return result

    return process


@main.command('provision-device', help='Executes device provisioning')
@click.pass_context
@click.option('--probe-id', 'probe_id', type=click.STRING, required=False, default=None,
              help='Probe serial number')
@click.option('--protection-state', 'protection_state', type=click.INT, required=False, default=ProtectionState.secure,
              hidden=True)
@click.option('--existing-packet', 'use_existing_packet', is_flag=True,
              help='Skip provisioning packet creation and use existing one')
def cmd_provision_device(ctx, probe_id, protection_state, use_existing_packet):
    def process():
        result = True if use_existing_packet else ctx.obj['TOOL'].create_provisioning_packet()
        if result:
            result = ctx.obj['TOOL'].provision_device(probe_id, protection_state)
        return result

    return process


@main.command('create-certificate', help='Creates certificate in a x509 format')
@click.pass_context
@click.option('-t', '--type', 'cert_type', type=click.STRING, required=False, default='x509', hidden=True,
              help='Certificate type (x509)')
@click.option('-n', '--name', 'cert_name', type=click.File(mode='wb'), required=False, default='psoc_cert.pem',
              help='Certificate filename')
@click.option('-e', '--encoding', 'encoding', type=click.STRING, required=False, default='PEM',
              help='Certificate encoding (PEM, DER)')
@click.option('--probe-id', 'probe_id', type=click.STRING, required=False, default=None,
              help='Probe serial number')
@click.option('--protection-state', 'protection_state', type=click.INT, required=False, default=ProtectionState.secure,
              hidden=True)
@click.option('--subject-name', 'subject_name', type=click.STRING, required=False, default=None,
              help='Certificate subject name')
@click.option('--country', 'country', type=click.STRING, required=False, default=None,
              help='Certificate country code')
@click.option('--state', 'state', type=click.STRING, required=False, default=None,
              help='Certificate issuer state')
@click.option('--organization', 'organization', type=click.STRING, required=False, default=None,
              help='Certificate issuer organization')
@click.option('--issuer-name', 'issuer_name', type=click.STRING, required=False, default=None,
              help='Certificate issuer name')
@click.option('--private-key', 'private_key', type=click.File(), required=False, default=None,
              help='Private key to sign the certificate')
def cmd_create_certificate(ctx, cert_type, cert_name, encoding, probe_id, protection_state,
                           subject_name, country, state, organization, issuer_name, private_key):
    def process():
        if encoding.upper() == 'PEM':
            enc = serialization.Encoding.PEM
        elif encoding.upper == 'DER':
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

        if cert_type == 'x509':
            result = ctx.obj['TOOL'].create_x509_certificate(cert_name.name, enc, probe_id, protection_state, **d)
        else:
            logger.error(f'Invalid certificate type \'{cert_type}\'')
            result = False
        return result

    return process


@main.command('entrance-exam', short_help='Checks device life-cycle, FlashBoot firmware and Flash state')
@click.pass_context
def cmd_entrance_exam(ctx):
    def process():
        result = ctx.obj['TOOL'].entrance_exam()
        return result

    return process
