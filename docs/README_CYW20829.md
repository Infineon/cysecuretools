# Table of Contents
- [Main features](#main-features)
- [Quick start](#quick-start)
- [Usage example](#usage-example)
- [Policy](#policy)
- [Keys](#keys)
- [Command-line interface](#command-line-interface)
    - [Tool help](#tool-help)
    - [Common options](#common-options)
    - [Create key](#create-key)
    - [Provision device](#provision-device)
    - [Reprovision device](#reprovision-device)
    - [Create provisioning data packet](#create-provisioning-data-packet)
    - [Sign image](#sign-image)
    - [Extend image](#extend-image)
    - [Convert bin to hex](#convert-bin-to-hex)
    - [Create debug certificate](#create-debug-certificate)
    - [Read die ID](#read-die-id)
    - [Get firmware version](#get-firmware-version)
    - [Get device info](#get-device-info)
    - [Converting binary packet to policy](#converting-binary-packet-to-policy)
    - [Return Merchandise Authorization (RMA)](#return-merchandise-authorization-rma)
- [Using package together with HSM](#using-package-together-with-hsm)
    - [Signing application with HSM](#signing-application-with-hsm)
    - [Creation and signing debug certificate with HSM](#creation-and-signing-a-debug-certificate-with-hsm)
    - [Signing reprovisioning data packet with HSM](#signing-reprovisioning-data-packet-with-HSM)
    - [Converting RSA key public numbers to PEM](#converting-rsa-key-public-numbers-to-pem)
- [Encrypt user application](#encrypt-the-user-application)
    - [Create encryption key](#create-encryption-key)
    - [Program encryption key](#program-encryption-key)
    - [Sign and encrypt an image](#sign-and-encrypt-an-image)


# Main features
* [Create a key](#create-a-key) - Creates an RSA private/public key pair or AES key for image encryption.
* [Provisioning a device](#provision-a-device) - Provisioning is the act of configuring a device with an authorized set of keys, policies, and optionally certificates.
* [Sign a user application](#sign-an-image) - Signs a user application with a private key locally or with a Hardware Security Module.
* [Encrypt a user application](#encrypt-the-user-application) - Signs and encrypts a user application.
* [Create a debug certificate](#create-debug-certificate) - The debug certificate is used by BootROM to enable CM33-AP and/or Sys-AP when it is temporarily disabled.


# Quick start
## 1. Set a path to the On-Chip debugger
```bash
$ cysecuretools set-ocd --name openocd --path <PATH_TO_OPENOCD_ROOT_DIRECTORY>
```
Make sure you provide the path to the root directory of OpenOCD (NOT _bin_ directory).
Specifying the path is not mandatory if you have ModusToolbox™ installed on your machine. OpenOCD from the ModusToolbox™ directory is used by default.

_Example:_
```bash
$ cysecuretools set-ocd --name openocd --path /Users/username/tools/openocd
```

## 2. Define a target
Run the following command and find the name of your target in the list of supported targets.
```bash
$ cysecuretools device-list
```
This target name will be used as a `-t` option value with each command.

_Example_:
```bash
$ cysecuretools -t cyw20829 -p <POLICY> <COMMAND> [OPTIONS]
# or
$ cysecuretools -t cyw89829 -p <POLICY> <COMMAND> [OPTIONS]
```
**Note**: All examples are provided for the CYW20829 device. For CYW89829 devices use `-t cyw89829`.

## 3. Create a new project
This copies the list of files required to start using the tool to the current working directory.
```bash
$ cysecuretools -t <TARGET> init
```

## 4. Define the policy
Select the policy with which the device will be provisioned. All available policy files are located in the _policy_ directory of the project.
 - for non-secure devices - _policy_no_secure.json_
 - for secure devices - _policy_secure.json_
 - for secure HCI devices - _policy_hci_secure.json_

This policy file will be used as a `-p` option value with each command. Refer to the [Policy types](#policy-types) section for more details about the policies.

_Example:_:
```bash
$ cysecuretools -t <TARGET> -p policy/policy_no_secure.json <COMMAND> [OPTIONS]
```

## 5. Create keys (for secure devices only)
Create a private/public key pair. The public key is used for the provisioning, the private key is used to sign the image with the user application.
```bash
$ cysecuretools -t <TARGET> -p <POLICY> create-key -k 0
```

## 6. Provision the device
```bash
$ cysecuretools -t <TARGET> -p <POLICY> provision-device
```

## 7. Sign the image
```bash
$ cysecuretools -t <TARGET> -p <POLICY> sign-image -i image.bin -o image_signed.bin -k 0
```


# Usage example
## Non-secure device
```bash
$ cysecuretools set-ocd --name openocd --path /Users/username/tools/openocd
$ cysecuretools -t cyw20829 init
$ cysecuretools -t cyw20829 -p policy/policy_no_secure.json provision-device
$ cysecuretools -t cyw20829 -p policy/policy_reprovisioning_no_secure.json reprovision-device
```
## Secure device
```bash
$ cysecuretools set-ocd --name openocd --path /Users/username/tools/openocd
$ cysecuretools -t cyw20829 init
$ cysecuretools -t cyw20829 -p policy/policy_secure.json create-key -k 0
$ cysecuretools -t cyw20829 -p policy/policy_secure.json provision-device
$ cysecuretools -t cyw20829 -p policy/policy_secure.json sign-image -i image.bin -o image_signed.bin -k 0
$ cysecuretools -t cyw20829 -p policy/policy_reprovisioning_secure.json reprovision-device -k 0
```


# Policy
Policy - is a text file in the JSON format, which contains a set of properties for the device configuration (e.g. enabling/disabling debug access ports, Serial Memory Interface configuration, keys information, etc.)

Policy files are located in the _policy_ directory of the user project and the path to a file is specified when almost any command is run. The user selects a policy file based on their needs.
## Policy types
The package contains the following policy types for the CYW20829 target:
 - `secure` – For provisioning a device with a key(s) and then converting the device to the SECURE lifecycle stage.
 - `no_secure` – For provisioning a device without a key(s) and then converting the device to the NORMAL_NO_SECURE lifecycle stage.
 - `reprovisioning_secure` – For reprovisioning an already secure device (previously provisioned with the _secure_ policy type). Allows configuring a limited set of settings. The file contains only those settings that can be changed during reprovisioning.
 - `reprovisioning_no_secure` – For reprovisioning a non-secure device (previously provisioned with the _no_secure_ policy type). Allows configuring a very limited set of settings. The file contains only those settings that can be changed during reprovisioning.
 - `hci` - Allows a device working without external memory by launching the HCI application placed in ROM.


# Keys
There are the following key types:
 - ICV (Integrated Chip Vendor) - This is Cypress/Infineon key bundled at the factory.
 - OEM (Original Equipment Manufacturer) - A key of the company that makes parts and products for other companies that sell them under their own name or use them in their own products.
 - Encryption key - A key used to encrypt an image in the external memory.

## Keys provisioning
### OEM key
During provisioning, the OEM keys are not transferred to a device in their original view. Only a key hash (16 bytes) is provisioned. For the image verification, the image must contain an OEM public key (added automatically by the _sign-image_ command). This public key hash will be compared to the provisioned key hash.
### Encryption key
A 128-bit encryption key is provisioned as is. There is an option to have two OEM keys (_oem_pub_key_0_ and _oem_pub_key_1_). However, if the encryption is used, then only _oem_pub_key_0_ can be used. The encryption key will be placed instead of the second OEM key hash.

 _NOTE_: An encryption key can be transferred to a device during provisioning only (NOT reprovisioning). Also, if encryption is used, oem_key_0 cannot be revoked during reprovisioning.


# Command-line interface
This section contains the main CLI commands. More commands can be found in the tool help.

## Tool help
To see the list of commands supported for a specific target:
```bash
$ cysecuretools -t <TARGET> --help
```
To see the list of options for a specific command:
```bash
$ cysecuretools -t <TARGET> <COMMAND> --help
```

## Common options
The interface provides common options. These options are common for all commands and must precede them:
| Name           | Description                 |
| -------------- | --------------------------- |
| -t, --target   | Device name or family.      |
| -p, --policy   | Provisioning policy file.   |
| -v, --verbose  | Provides debug-level log.   |
| -q, --quiet    | Quiet display option.       |
| --logfile-off  | Avoids logging into file.   |


## Create key
Creates an RSA private/public key pair to provision a device and to sign a user application. There must be a common key pair between the secure device and user application. A device must be provisioned with a public key, the user application must be signed with a corresponding private key from the same pair. Also, the command can be used to generate an AES key for image encryption.
### Command: `create-key`
### Parameters
| Name &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Optional/Required  | Description  |
| --------------------------------|:------------------:| -------------|
| -k, --key-id [0\|1]             | optional (mutually exclusive with the _--output_ option) | The OEM key ID. This ID defines the paths where the public and private keys will be saved based on the selected policy _pre_build_ and _post_build_ sections. Depending on the selected value 0 or 1, _oem_key_0_ or _oem_key_1_ will be used. |
| -o, --output [private] [public] | optional (mutually exclusive with the _--key-id_ option) | Key pair output files. This is an alternative option and can be used to create a key in the different from the policy location. If it is specified, the _--key-id_ option will be ignored. However, using _--key-id_ is preferable. It allows avoiding accidental provisioning and signing with a key from the different pairs. As the option value, provide private and public key paths. Specify the option multiple times to create multiple key pairs. |
| --aes                           | optional (mutually exclusive with the _--key-id_ and _--output_ options)          | Indicates whether to generate an AES key for image encryption. The key will be saved by the path specified in the policy _smif_aes_key_ field.
| --key-path    | optional        | Used to generate a key into a specific path. Applicable with _--aes_ or _--template_ option. |
| --overwrite / --no-overwrite    | optional           | Indicates whether overwrite a key if it already exists. |
| --template    | optional        | A JSON file containing public key modulus and exponent. The option is used for creating a PEM file based on public key modulus and exponent. |
| --hash-path   | optional        | A path where to save the public key hash.|
### Usage example
```bash
$ cysecuretools -t cyw20829 -p policy/policy_secure.json create-key -k 0
```


## Provision device
Configuring a device with a set of keys and policies.
### Command: `provision-device`
### Parameters
| Name &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Optional/Required  | Description  |
| -------------------|:-----------------:| -------------|
| --probe-id         | optional          | Probe serial number. |
| --existing-packet  | optional          | Skip provisioning packet creation and use the existing packet. This may be useful when a packet with RAM application input parameters already exists and the tool does not have to generate it again. |
### Usage example
```bash
$ cysecuretools -t cyw20829 -p policy/policy_secure.json provision-device
```


## Reprovision device
Once a device has been provisioned it can only be reprovisioned. Reprovisioning allows configuring a limited set of settings (e.g. provisioning an additional OEM key, revoking _icv_pubkey_0_ and oem_pubkey_0 keys, changing anti-rollback counter, etc). The _policy_reprovisioning_secure.json_ file contains only those settings that can be changed.
### Command: `reprovision-device`
### Parameters
| Name &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Optional/Required  | Description  |
| --------------------|:------------------:| -------------|
| -k, --key-id [0\|1] | optional           | The OEM private key ID used to sign the reprovisioning packet. This ID informs the tool about the key location. The tool will use the path specified in the selected policy _post_build_ section. |
| --key-path          | optional           | Sets OEM private key that is used to sign the reprovisioning packet. Overrides --key-id option.|
| --probe-id          | optional           | Probe serial number. |
| --existing-packet   | optional           | Skip reprovisioning packet creation and use the existing packet. This may be useful when a packet with RAM application input parameters already exists and the tool does not have to generate it again. |
| --signature         | optional           | The name of the file containing the signature.|
### Usage example
```bash
$ cysecuretools -t cyw20829 -p policy/policy_secure.json reprovision-device -k 0
```


## Create provisioning data packet
Creates provisioning/reprovisioning data packet without starting the device provisioning process.
### Command: `create-provisioning-packet`
### Parameters
| Name &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Optional/Required  | Description  |
| --------------------|:------------------:| -------------|
| -k, --key-id [0\|1] | optional           | The OEM private key ID used to sign the reprovisioning packet. Applicable with reprovisioning policy type only. The ID informs the tool about the key location. The tool will use the path specified in the selected policy _post_build_ section. |
| --key-path          | optional           | Key file path to sign the reprovisioning packet. Applicable with reprovisioning policy type only. This is an alternative option and can be used to specify different from the policy key file location. If it is specified, the _--key-id_ option will be ignored. However, using _--key-id_ is preferable. It allows avoiding accidental provisioning and signing with keys from the different pairs. |
| --signature         | optional           | The file path containing the signature. Used to sign the reprovisioning packet by HSM ([Signing reprovisioning data packet with HSM](#signing-reprovisioning-data-packet-with-HSM)). |
| --pubkey            | optional           | The public key to be added to the reprovisioning packet. Used to sign the reprovisioning packet by HSM ([Signing reprovisioning data packet with HSM](#signing-reprovisioning-data-packet-with-HSM)). |
| --non-signed        | optional           | The flag indicating that reprovisioning packet will not be signed. Used to create the reprovisioning packet for signing by HSM ([Signing reprovisioning data packet with HSM](#signing-reprovisioning-data-packet-with-HSM)). |
### Usage example
```bash
$ cysecuretools -t cyw20829 -p policy/policy_secure.json create-provisioning-packet
```
```bash
$ cysecuretools -t cyw20829 -p policy/policy_reprovisioning_secure.json create-provisioning-packet -k 0
```


## Sign image
Signs a user application with a key. Optionally encrypts the signed application.
### Command: `sign-image`
### Parameters
| Name &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Optional/Required  | Description   |
| ------------------------- |:------------------:| ------------- |
| -i, --image               | required           | User application file. The output file format is based on the input file extension (bin or hex) |
| -k, --key-id [0\|1]       | optional (mutually exclusive with the _--key-path_ option) | The OEM key ID. This ID defines the key location based on the selected policy _post_build_ section. Depending on the selected value 0 or 1, _oem_priv_key_0_ or _oem_priv_key_1_ will be used. |
| --key-path                | optional (mutually exclusive with the _--key-id_ option) | Key file path to sign the image. This is an alternative option and can be used to specify different from the policy key file location. If it is specified, the _--key-id_ option will be ignored. However, using _--key-id_ is preferable. It allows avoiding accidental provisioning and signing with keys from the different pairs. |
| --signature                | optional           | The name of the file containing the signature. Used to add an existing signature to the image. |
| -R, --erased-val [0\|0xff] | optional           | The value that is read back from erased flash. |
| -o, --output              | optional           | Signed image output file. If not specified, a copy of the input file will be created with the _unsigned_ prefix, then the input file will be signed. |
| --encrypt                 | optional           | Enable the encryption feature. If present, the image will be encrypted after signing. |
| --enckey                  | optional           | Path to the AES key. If absent, the key path is taken from the policy _smif_aes_key_ field. |
| --hex-addr                | optional           | Adjusts address in .hex output file. The default value is 0. Ignored for output images in .bin format|
| --app-addr                | optional           | The address of the application to encrypt. Accepts values as hexadecimal or decimal numbers. The default value is 0. |
| -f, --image-format        | optional           | The image format defines the image header size, signing and encryption algorithms. Values: _bootrom_ram_app_ - RAM application started by BootROM; _bootrom_next_app_ - external memory application started by BootROM (e.g. MCUBoot); _mcuboot_user_app_ - application started by MCUBoot. The default value is _mcuboot_user_app_. |
| -H, --header-size         | optional           | Sets image header size. Overrides header size defined by the --image-format option. |
| -S, --slot-size           | optional           | Sets maximum slot size. The default value is 0x20000.
| --pad                     | optional           | Adds padding to the image trailer up to maximum slot size. Adds padding to 32-byte Boot Magic to the end of the trailer. Needed for MCUBoot image upgrade.|
| --confirm                 | optional           | Adds Image OK byte to image trailer. Needed for MCUBoot image upgrade.|
| --overwrite-only          | optional           | Sets Overwrite mode in MCUBoot image header instead of Swap.|
| --update-key-id [0\|1]    | optional           | Sets OEM private key ID used to sign the update data packet.|
| --update-key-path         | optional           | The key used to sign the update data packet. Overrides the --update-key-id option.|
| --min-erase-size          | optional           | Sets minimum erase size.|
| --align [1\|2\|4\|8]      | optional           | Sets flash alignment. The default value is 8.|
| -v, --version             | optional           | Sets image version in the image header.|
| -d, --dependencies        | optional           | Add dependency on another image, format: "(<image_ID>,<image_version>), ... ".|
| --image-id                | optional           | Image ID. The value is used to update NV counter. The default value is 0.|
### Usage example
#### Sign without encryption:
```bash
$ cysecuretools -t cyw20829 -p policy/policy_secure.json sign-image --image image.bin --output image_signed.bin --key-id 0 --image-type APP_PC0
```
#### Sign and encrypt:
```bash
$ cysecuretools -t cyw20829 -p policy/policy_secure.json sign-image --image image.bin --output image_signed.bin --key-id 0 --image-type APP_PC0--encrypt --app-addr 0x08000200
```
Refer to [Encrypt the user application](#encrypt-the-user-application) for more details about image encryption.


## Extend image
Extends a firmware image with the protected TLV area and [mcuboot header](https://github.com/mcu-tools/mcuboot/blob/master/docs/design.md#image-format), but does not sign the image. Usually, this command is useful for [signing and image with a Hardware Security Module](#signing-application-with-hsm).
### Command: `extend-image`
### Parameters
| Name &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Optional/Required | Description |
| ----------------------------- |:------------------:| ------------- |
| -i, --image                   | required           | User application file. The output file format is based on the input file extension (bin or hex). |
| --pubkey                      | optional           | The public key to be added to the image. Necessary for the image further verification. |
| -R, --erased-val [0\|0xff]    | optional           | The value that is read back from erased flash.    |
| -o, --output                  | optional           | Extended image output file. If not specified, a copy of the input file will be created with the _orig_ prefix, then the input file will be processed.|
| --protected-tlv [tag] [value] | optional           | Custom TLV that will be placed into a protected area. Basically, this is the user's custom data. Add the "0x" prefix if the value should be interpreted as an integer, otherwise, it will be interpreted as a string. Specify the option multiple times to add multiple TLVs. |
| -f, --image-format        | optional           | The image format defines the image header size, signing and encryption algorithms. Values: _bootrom_ram_app_ - RAM application started by BootROM; _bootrom_next_app_ - external memory application started by BootROM (e.g. MCUBoot); _mcuboot_user_app_ - application started by MCUBoot. The default value is _mcuboot_user_app_. |
| -H, --header-size         | optional           | Sets image header size. Overrides header size defined by the --image-format option. |
| -S, --slot-size           | optional           | Sets maximum slot size. The default value is 0x20000.|
| --pad                     | optional           | Adds padding to the image trailer up to maximum slot size. Adds padding to 32-byte Boot Magic to the end of the trailer. Needed for MCUBoot image upgrade.|
| --confirm                 | optional           | Adds Image OK byte to image trailer. Needed for MCUBoot image upgrade.|
| --overwrite-only          | optional           | Sets Overwrite mode in MCUBoot image header instead of Swap.|
| --align [1\|2\|4\|8]      | optional           | Sets flash alignment. The default value is 8.|
| --update-key-id [0\|1]    | optional           | Sets OEM private key ID used to sign the update data packet.|
| --update-key-path         | optional           | The key used to sign the update data packet. Overrides the --update-key-id option.|
| --image-id                | optional           | Image ID. The value is used to update NV counter. The default value is 0.|
### Usage example
#### Unsigned image with metadata:
```bash
$ cysecuretools -t cyw20829 -p policy/policy_secure.json extend-image -i image.bin -o image_extended.bin --protected-tlv 0x1A 0x1000 --protected-tlv 0x3E 0123456789 --pubkey keys/pub_key.pem
```
#### Unsigned image with metadata and update package:
```bash
$ cysecuretools -t cyw20829 -p policy/policy_reprovisioning_secure.json extend-image -i image.bin -o image_extended.bin --pubkey keys/pub_key.pem --update-key-id 0 --image-id 1
```


## Convert bin to hex
Converts image of bin format to hex format.
### Command: `bin2hex`
### Parameters
| Name          | Optional/Required  | Description     |
| ------------- |:------------------:| --------------- |
| --image       | required           | Input bin file  |
| -o, --output  | required           | Output hex file |
| --offset      | optional           | Starting address offset for loading bin |
### Usage example
```bash
$ cysecuretools bin2hex --image image.bin --output image.hex --offset 0x20000
```


## Create debug certificate
The debug certificate is used by BootROM to enable CM33-AP and/or Sys-AP when it is temporarily disabled. Note that the certificate cannot enable an access port that is permanently disabled by the access restrictions. Also, the debug certificate can be used to enable/disable invasive or non-invasive debug for CM33-AP.

The command creates a debug or RMA certificate binary based on the template. The certificate must contain a public key for further verification. If it is signed using the local private key then the public key is extracted from the private. If the certificate is going to be signed using HSM, then create a non-signed certificate and specify the public key.
### Command: `debug-certificate`
### Parameters
| Name &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Optional/Required  | Description   |
| ------------------------- |:------------------:| ------------- |
| --non-signed              | optional           | The flag indicating that debug certificate will not be signed. |
| -t, --template            | optional           | The path to the certificate template in the JSON format. |
| -k, --key-id [0\|1]       | optional (mutually exclusive with the _--key-path_ option) | The OEM private key ID used to sign the certificate. This ID defines the key location based on the selected policy _post_build_ section. Depending on the selected value 0 or 1, _oem_priv_key_0_ or _oem_priv_key_1_ will be used. |
| --key-path                | optional (mutually exclusive with the _--key-id_ option) | Either a private key path for signing the certificate or a public key to be added to the certificate. This is an alternative option and can be used to specify different from the policy key file location. If it is specified, the _--key-id_ option will be ignored. |
| --sign [cert] [signature] | optional           | The option for signing an existing certificate using existing signature file. |
| -o, --output              | required           | The file where to save the debug certificate. |

The certificate template is located in the _packets_ directory of the project (_debug_cert.json_). By default, the template is configured to be applicable for any die ID. See the [Read die id](#read-die-id) section to the find die ID of your device. See the [Get device info](#get-a-device-info) section to find silicon ID, family ID, and revision ID needed to create a certificate.
### Usage example
```bash
$ cysecuretools -t cyw20829 -p policy/policy_secure.json debug-certificate -t packets/debug_cert.json -o packets/debug_cert.bin -k 0
```


## Read die ID
Reads the die ID from device.
### Command: `read-die-id`
### Parameters
| Name           | Optional/Required  | Description   |
| -------------- |:------------------:| ------------- |
| -o, --out-file | optional           | The name of the file where to save the die ID. If not specified, the information will be displayed in the console. |
| --probe-id     | optional           | Probe serial number. |
### Usage example
```bash
$ cysecuretools -t cyw20829 -p policy/policy_secure.json read-die-id
```


## Get firmware version
Shows BootROM version and RAM applications version used for provisioning.
### Command: `version`
### Parameters
| Name           | Optional/Required  | Description   |
| -------------- |:------------------:| ------------- |
| --probe-id     | optional           | Probe serial number. |
### Usage example
```bash
$ cysecuretools -t cyw20829 -p policy/policy_secure.json version
```


## Get device info
Gets device information - silicon ID, silicon revision, and family ID.
### Command: `device-info`
### Parameters
| Name           | Optional/Required  | Description   |
| -------------- |:------------------:| ------------- |
| --probe-id     | optional           | Probe serial number. |
| --ap [cm33\|sysap] | optional       | The access port used to read the data. The default value is sysap.|
### Usage example
```bash
$ cysecuretools -t cyw20829 -p policy/policy_secure.json device-info
```


## Converting binary packet to policy
This command is for debugging purposes only. It creates a policy file (JSON) based on an application input parameters binary.
### Command: `prov-packet-to-policy`
### Parameters
| Name          | Optional/Required  | Description   |
| ------------- |:------------------:| ------------- |
| --packet      | required           | Binary with input parameters. |
| -o, --output  | required           | The file where to save the policy. |
### Usage example
```bash
$ cysecuretools -t cyw20829 -p policy/policy_secure.json prov-packet-to-policy --packet packets/apps/prov_oem/in_params.bin --output policy/policy_secure_debug.json
```


## Return Merchandise Authorization (RMA)
The command advances the device lifecycle stage to RMA. If the device is in the SECURE LCS the transition process requires a certificate. Use debug certificate with the RMA flag enabled (refer to [Create debug certificate](#create-debug-certificate)). The certificate must be signed with the OEM private key.
### Command: `convert-to-rma`
### Parameters
| Name          | Optional/Required  | Description   |
| ------------- |:------------------:| ------------- |
| -c, --cert    | optional           | Debug certificate with the RMA flag enabled. Signed with the OEM private key. |
| --probe-id    | optional           | Probe serial number. |
### Usage example
```bash
$ cysecuretools -t cyw20829 convert-to-rma --cert packets/debug_cert.bin
```


# Using package together with HSM
To protect your private keys, the cryptographic operations can be delegated to a Hardware Security Module (HSM). The flow of using the package with an HSM is different from the standard flow because of the necessity to sign the image on the remote machine. The HSM machine gets an image as an input, then signs it, and returns a signature without a payload. Then this signature has to be added to the payload in a specific format.

## Signing application with HSM
The flow:
1. Export the HSM public key to a file.
2. Convert the exported key to the PEM format.
3. Extend the image with the data that have to be signed.
4. Get the signature using HSM.
5. Add a signature returned by the HSM to the image.

### Step 1
Using the tools provided by your HSM provider, export the HSM public key to a file. The key will be added to the image for further verification.
### Step 2
If your HSM provider allows exporting public keys directly to the PEM format, then this step can be skipped. However, if the HSM provider exports the public part of the key as a modulus and exponent, this data must be converted to the PEM format (see [Converting RSA key public numbers to PEM](#converting-rsa-key-public-numbers-to-pem)).
### Step 3
Add the data that have to be signed - protected TLV, the public key, and [mcuboot header](https://github.com/mcu-tools/mcuboot/blob/master/docs/design.md#image-format) (added by default).
```bash
$ cysecuretools -t cyw20829 -p policy/policy_secure.json extend-image -i image.bin -o image_extended.bin --protected-tlv 0x1A 0x1000 --protected-tlv 0x3E 0123456789 --pubkey keys/pub_key.pem
```
### Step 4
Use the tools provided by your HSM provider to sign the extended image on the HSM machine. Save the signature returned by the HSM to a file.
### Step 5
Run the _sign-image_ command with the _--signature_ parameter and provide the signature file created by the HSM. Use the extended image, which was sent to the HSM.
```bash
$ cysecuretools -t cyw20829 -p policy/policy_secure.json sign-image -i image_extended.bin -o image_signed.bin --signature signature.sig
```

## Creation and signing a debug certificate with HSM
The flow:
1. Export the HSM public key to a file.
2. Convert the exported key to the PEM format.
3. Create a non-signed debug certificate.
4. Get the signature using HSM.
5. Add a signature returned by the HSM to the certificate.

### Step 1
Using the tools provided by your HSM provider, export the HSM public key to a file. The key will be added to the image for further verification.
### Step 2
If your HSM provider allows exporting public keys directly to the PEM format then this step can be skipped. However, if the HSM provider exports the public part of the key as a modulus and exponent, this data must be converted to the PEM format (see [Converting RSA key public numbers to PEM](#converting-rsa-key-public-numbers-to-pem)).
### Step 3
Create a certificate using _--non-signed_ option.
```bash
$ cysecuretools -t cyw20829 -p policy/policy_secure.json debug-certificate --template packets/debug_cert.json --non-signed --key-path keys/pub_key.pem --output packets/cert_unsigned.bin
```
### Step 4
Use the tools provided by your HSM provider to sign the extended image on the HSM machine. Save the signature returned by the HSM to a file.
### Step 5
Run the _debug-certificate_ command with the _--sign_ parameter and provide the unsigned certificate and the signature file created by the HSM.
```bash
$ cysecuretools -t cyw20829 -p policy/policy_secure.json debug-certificate --sign packets/cert_unsigned.bin signature.sig --output packets/cert_signed.bin
```


## Signing reprovisioning data packet with HSM
The flow:
1. Export the HSM public key to a file.
2. Convert the exported key to the PEM format.
3. Create a non-signed reprovisioning data packet.
4. Get the signature using HSM.
5. Add a signature returned by the HSM to the data packet.

### Step 1
Using the tools provided by your HSM provider, export the HSM public key to a file. The key will be added to the image for further verification.
### Step 2
If your HSM provider allows exporting public keys directly to the PEM format then this step can be skipped. However, if the HSM provider exports the public part of the key as a modulus and exponent, this data must be converted to the PEM format (see [Converting RSA key public numbers to PEM](#converting-rsa-key-public-numbers-to-pem)).
### Step 3
Create a reprovisioning data packet using _--non-signed_ option. Also, add the public key to for the packet further verification.
```bash
$ cysecuretools -t cyw20829 -p policy/policy_reprovisioning_secure.json create-provisioning-packet --non-signed --pubkey keys/pub_key.pem
```
### Step 4
Use the tools provided by your HSM provider to sign the data packet on the HSM machine. You can find the packet location in the previous step output. Save the signature returned by the HSM to a file.
### Step 5
Run the same command with the _--signature_ parameter and provide the unsigned packet and the signature file created by the HSM.
```bash
$ cysecuretools -t cyw20829 -p policy/policy_reprovisioning_secure.json create-provisioning-packet --signature keys/hsm_signature.bin
```
Now, you can run the _reprovision-device_ command and the _--existing-packet_ option to make the tool not generate the packet again.

Or you can skip adding the signature to the packet as a separate step and directly run the _reprovision-device_ command with the _--signature_ option.
```bash
$ cysecuretools -t cyw20829 -p policy/policy_reprovisioning_secure.json reprovision-device --signature keys/hsm_signature.bin
```
__IMPORTANT:__ Make sure not to add the signature more than one time for further reprovisioning.


## Converting RSA key public numbers to PEM
If the HSM provider exports public part of the key as a modulus and exponent, this data must be converted to the PEM format.

Example of the Utimaco CryptoServer public key format:
```ini
# RSA key
MOD=D141C13F1277977BAD60D49D87E7B1A4F35C3BD03A07F16AC36A9F48A1E626B88BB2717FDEA7E7B2EC810F810B8F11CF1A2A7142D94DB7DE57CDFE62F637074CBCF78AAA2251843B03716D6B2CD53111229EA6117FED50DF638811892F015F44F77C689FBF8D35B0237FE9F73875C10D471D6FEBEAAC334D60320553EE8EDFE21FA4EC20C44F083A6CE02514EAB43622CB236D0EB1803A09C960BF89800386B0B3BC196A479350C619B49B75D45BE4BE61D55C894902A3755A4A7999F37DC109DA1BD71530682CC67A435495D6442D88BCB31F0B56DD6952BE277645368C1887236B2709CD0369C5E33B62409466F148D4C070F7107AA4B274E04204F939ABFB
PEXP=010001
```
Copy the modulus and exponent from the exported key to the _rsa_key_tmpl.json_ file located in the _packets_ directory of your project and convert it to PEM:
```bash
$ cysecuretools -t cyw20829 -p policy/policy_secure.json create-key --template packets/rsa_key_tmpl.json --key-path keys/pub_key.pem
```


# Encrypt the user application
Protect confidential images by encrypting an image before transmissioning it to the device.

There must be a 128-bit encryption key that has to be provisioned to the device. Then user's application must be signed with a private key and encrypted with this encryption key.

The following example shows how to create an encryption key, provision it to the device and encrypt the image:
## Create encryption key
This example creates a binary file containing a 128-bit encryption key in the _keys_ directory of the project.
```bash
$ cysecuretools -t cyw20829 -p policy/policy_secure.json create-key --aes --key-path keys/encrypt_key.bin
```
## Program encryption key
The device must be able to decrypt the image. Therefore, the encryption key must be specified in the provisioning policy. The entire encryption key is provisioned to a device unlike the OEM key, where only a hash of the key is provisioned.

In the secure policy, enable the encryption and provide the path to the encryption key. The encryption key will be placed at the _oem_key_1_hash_ location, so, programming _oem_key_1_hash_ must be disabled.
```json
"flow_control":
{
    ...

    "program_oem_key_1_hash": {
        "description": "Programs the OEM key 1 hash and makes it immutable (this can be done only once)",
        "value": false
    }
}
```
```json
"smif_config":
{
    ...

    "encryption": {
        "description": "Enables SMIF encryption",
        "value": true
    }
}
```
```json
"pre_build":
{
    "keys":
    {
        ...

        "encrypt_key": {
            "description": "Path to the AES-128 key for image encryption in external memory",
            "value": "../keys/encrypt_key.bin"
        }
    }
}
```
Then run a device provisioning.
```bash
$ cysecuretools -t cyw20829 -p policy/policy_secure.json provision-device
```

## Sign and encrypt an image
The image encryption process is similar to signing but with the additional option _--encrypt_. Another important option that needs to be specified is _--app-addr_. This is the image base address in the external memory. Points to the address from where the image needs to be encrypted:
 - for L1 application (mcuboot) - TOC2 address + TOC2 size + L1 application descriptor size.
 - for the next user applications - user application base address

Example for BootROM next application - the external memory application started by BootROM:
```bash
$ cysecuretools -t cyw20829 -p policy/policy_secure.json sign-image --image image.bin --output image_signed.bin --key-id 0 --image-format bootrom_next_app --encrypt --app-addr 0x08000030
```
Example for MCUboot user application - the application started by MCUboot:
```bash
$ cysecuretools -t cyw20829 -p policy/policy_secure.json sign-image --image image.bin --output image_signed.hex --key-path keys/p256_priv_key.pem --encrypt --enckey keys/ec256_pub_key.pem --image-format mcuboot_user_app --app-addr 0x08020000 --hex-addr 0x60020000
```
__NOTE:__ RSA key is not supported for MCUboot user application encryption. Use ECDSA key.
