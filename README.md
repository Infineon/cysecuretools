This package contains security tools for creating keys, creating certificates, signing user applications, and provisioning Cypress MCUs.

# Table of Contents
- [Features](#features)
- [Documentation](#documentation)
- [Prerequisites](#prerequisites)
- [Installing package](#installing-package)
- [Init project](#init-project)
- [Quick start](#quick-start)
- [Interface description](#interface-description)
    - [Common options](#common-options)
    - [Create keys](#create-keys)
    - [Create provisioning packet](#create-provisioning-packet)
    - [Provision device](#provision-device)
    - [Re-provision device](#re-provision-device)
    - [Sign image](#sign-image)
    - [Entrance exam](#entrance-exam)
    - [Create a certificate](#create-a-certificate)
    - [Create image certificate](#create-image-certificate)
    - [Flash map methods](#flash-map-methods)
    - [List of supported devices](#list-of-supported-devices)
    - [Encrypted programming](#encrypted-programming)
       - [Create encrypted image](#create-encrypted-image)
       - [Program encrypted image](#program-encrypted-image)
       - [Programming encrypted bootloader](#programming-encrypted-bootloader)
       - [Programming encrypted user application](#programming-encrypted-user-application)
    - [CyBootloader and Secure Flash Boot version](#cybootloader-and-secure-flash-boot-version)
    - [Sign certificate](#sign-certificate)
    - [Read public key from device](#read-public-key-from-device)
    - [Read die ID from device](#read-die-id-from-device)
- [Closing All Access Ports](#closing-all-access-ports)
- [Open CM0 Access Port](#open-cm0-access-port)
- [Policy and Keys](#policy-and-keys)
    - [Provisioning Policies](#provisioning-policies)
    - [Policy Location](#policy-location)
    - [Custom Data Sections](#custom-data-sections)
    - [Keys Location](#keys-location)
- [CyBootloader](#cybootloader)
    - [Custom Bootloader](#custom-bootloader)
    - [Encrypted Bootloader](#encrypted-bootloader)
- [Using Different On-Chip Debugger](#using-different-on-chip-debugger)
- [Package Installation Directory](#package-installation-directory)
- [License and Contributions](#license-and-contributions)

# Features

* [Create keys](#create-keys) - A key is a file used to authorize access to device data. There must be a common key pair between the secure device and user application. A device must be provisioned with a public key and the user application must be signed with a corresponding private key from the same pair.

* [Entrance exam](#entrance-exam) - Passing an entrance exam before provisioning a device is an option to ensure that the device has the valid state.

* [Provisioning a device](#provision-device) - Provisioning is the act of configuring a device with an authorized set of keys, certificates, and policies.

* [Sign a user application](#sign-image) - To run a user application on a secure device, the application must be signed with the key provisioned to the device earlier.

* [Create a certificate](#create-a-certificate) - Create a certificate in the X.509 format: with the device public key inside and signed with the private key. The certificate can be used when connecting to a cloud service.

* [Create image certificate](#create-image-certificate) - Based on an image, create a JWT that certifies the image's validity.

* [Output CyBootloader and Secure Flash Boot version](#output-cybootloader-and-secure-flash-boot-version) - Outputs CyBootloader and Secure Flash Boot version.

# Documentation

* [PSoC64 Secure MCU Secure Boot SDK User Guide](https://www.cypress.com/documentation/software-and-drivers/psoc-64-secure-mcu-secure-boot-sdk-user-guide)
* [Changelog](CHANGELOG.md)

# Prerequisites

* Python 3.6 or later
* Installed the libusb driver

   **Windows**
   - Download and unzip libusb-1.0.21.7z from https://github.com/libusb/libusb/releases/tag/v1.0.21
   - Run the following command to determine if a Python shell is executing in 32-bit or 64-bit mode on the OS: `python -c "import struct; print(struct.calcsize('P') * 8)"`
   - Copy *libusb-1.0.dll* file into the Python root folder (in same folder with *python.exe*). Use the 64-bit version of DLL for the 64-bit Python (MinGW64 directory) and the 32-bit version of DLL for the 32-bit Python (MinGW32 directory).
   - Ensure the Python path is located at the beginning of the Path environment variable.

   **Linux/Mac OS**
   - Use [homebrew](https://brew.sh/) to install the driver from the terminal: `homebrew install libusb`

# Installing Package

Invoke `pip install` from the command line:

```bash
pip install cysecuretools
```

# Init Project
Initialize new project. The command creates the sufficient list of files for the specified target to start working with the tool.

If the project is not initialized, the tool refers to the package directory for the necessary files.

**CLI**
```bash
cysecuretools -t <TARGET> init
```

Use your real target name, taken from the `cysecuretools device-list` command, instead of `<TARGET>`

# Quick Start

## To get supported devices list:

CySecureTools contains a command `device-list` for an output of the supported devices list. The list of supported devices will be output to the console.

**CLI**
```bash
cysecuretools device-list
```

**Python**
```python
from cysecuretools import CySecureTools
tools = CySecureTools()
```

A possible output of this command:
```
Supported targets and families:
PSoC64 Secure Boot Family:
	cyb06xx7
	cyb06xxa
	cyb06xx5
PSOC64 Kit targets:
	cy8cproto-064s1-sb
	cy8cproto-064b0s1-ble
	cy8ckit-064b0s2-4343w
	cy8ckit-064s0s2-4343w
	cy8cproto-064b0s3
PSoC64 Standard Secure Family:
	cys06xxa
```

## Full cycle example:

This example shows how to provision a device with a new key and default policy. To run the above code, use your real target name, taken from the `cysecuretools device-list` command, instead of `<TARGET>`.

If you use a custom policy, you can specify the policy file with the `-p` paramether in the CLI or a second paramether in the API (`tools = CySecureTools('<TARGET>', '<POLICY>')`).

**CLI**

Default policy example:
```bash
cysecuretools -t <TARGET> entrance-exam create-keys provision-device
```
Custom policy example:
```bash
cysecuretools -t <TARGET> -p <POLICY> entrance-exam create-keys provision-device
```
**Python**

Default policy example:
```python
from cysecuretools import CySecureTools

tools = CySecureTools('<TARGET>')

# Ensure that the device has a valid state by passing an entrance exam
tools.entrance_exam()

# Create a common key pair used by the secure device and user application
tools.create_keys()

# Create a JWT packet that contains the policy and keys to be provisioned to a device
tools.create_provisioning_packet()

# Execute device provisioning
tools.provision_device()

# Sign the user application with the keys
tools.sign_image('example-blinky.hex')
```
Custom policy example:
```python
from cysecuretools import CySecureTools

tools = CySecureTools('<TARGET>', '<CUSTOM_POLICY>')

# Ensure that the device has a valid state by passing an entrance exam
tools.entrance_exam()

# Create a common key pair used by the secure device and user application
tools.create_keys()

# Create a JWT packet that contains the policy and keys to be provisioned to a device
tools.create_provisioning_packet()

# Execute device provisioning
tools.provision_device()

# Sign the user application with the keys
tools.sign_image('example-blinky.hex')
```

# Interface description

## **Common options**

The CLI (command line interface) provides common options - the options that are common for all commands and must precede them:

| Option         | Description              |
| -------------  | ------------------------ |
| -t, --target   | Device name or family    |
| -p, --policy   | Provisioning policy file |
| -v, --verbose  | Provides debug-level log |
| --logfile-off  | Avoids logging into file |
| --help         | Shows the tool help      |

#### Usage example:
```bash
cysecuretools -t <TARGET> -p <POLICY> <COMMAND> --<COMMAND_OPTION>
```
For the detailed help of particular command use:
```bash
cysecuretools <COMMAND> --help
```

## **Create keys**
Creates keys specified in the policy file for the image signing.
#### CLI implementation
### create-keys
#### Parameters
| Name                             | Optional/Required  | Description   |
| -------------------------------- |:------------------:| ------------- |
| --overwrite / --no-overwrite     | optional           | Indicates whether overwrite the keys in the output directory if they already exist. If omitted, a prompt will ask whether to overwrite the existing keys. |
| -o, --out                        | optional           | The output directory for generated keys. By default, the keys location will be as specified in the policy file. |
| --kid                            | optional           | The ID of the key to create. If not specified, all the keys found in the policy file will be generated. |

#### Usage example
```bash
cysecuretools -t CY8CKIT-064B0S2-4343W create-keys --overwrite
```
or
```bash
cysecuretools -t CY8CKIT-064B0S2-4343W -p MyPolicy.json create-keys --overwrite
```

#### API implementation
### create_keys()
#### Parameters
| Name          | Optional/Required  | Description   |
| ------------- |:------------------:| ------------- |
| overwrite     | optional           | Indicates whether overwrite the keys in the output directory if they already exist. The available values: True, False, None. If None, a prompt will ask whether to overwrite the existing keys. |
| out           | optional           | The output directory for generated keys. By default, the keys location will be as specified in the policy file. |

#### Usage example
```python
from cysecuretools import CySecureTools
tools = CySecureTools('CY8CKIT-064B0S2-4343W')
tools.create_keys()
```
or
```python
from cysecuretools import CySecureTools
tools = CySecureTools('CY8CKIT-064B0S2-4343W', 'MyPolicy.json')
tools.create_keys()
```

## Create provisioning packet
Creates a JWT packet (a file to be programmed into the device during the provisioning procedure). In general, this is a policy, keys, and certificates in the JWT format. Returns True if the packet is created successfully, otherwise - False.
#### CLI implementation
### create-provisioning-packet
#### Parameters
No parameters required.
#### Usage example
```bash
cysecuretools -t CY8CKIT-064B0S2-4343W create-provisioning-packet
```
or
```bash
cysecuretools -t CY8CKIT-064B0S2-4343W -p MyPolicy.json create-provisioning-packet
```

#### API implementation
### create_provisioning_packet()
#### Parameters
No parameters required.
#### Usage example
```python
from cysecuretools import CySecureTools
tools = CySecureTools('CY8CKIT-064B0S2-4343W')
tools.create_provisioning_packet()
```
or
```python
from cysecuretools import CySecureTools
tools = CySecureTools('CY8CKIT-064B0S2-4343W', 'MyPolicy.json')
tools.create_provisioning_packet()
```

## Provision device
Starts a device provisioning process. Returns True if provisioning was success, otherwise - False.

__WARNING:__ This operation can be done with the SECURE UNCLAIMED device only. SECURE UNCLAIMED means it was not provisioned before, so does not have an identity assigned. Once device was provisioned it is considered as a SECURE CLAIMED and further identity assigning is not possible. It can be re-provisioned with the `re-provision-device` command.

#### CLI implementation
### provision-device
#### Parameters
| Name              | Optional/Required  | Description   |
| ----------------- |:------------------:| ------------- |
| --probe_id        | optional           | The probe serial number. Can be used to specify a probe if more than one device is connected to a computer. |
| --existing-packet | optional           | Skip the provisioning packet creation and use the existing packet. |

#### Usage example
```bash
cysecuretools -t CY8CKIT-064B0S2-4343W provision-device
```
or
```bash
cysecuretools -t CY8CKIT-064B0S2-4343W -p MyPolicy.json provision-device
```

#### API implementation
### provision_device()
#### Parameters
| Name          | Optional/Required  | Description   |
| ------------- |:------------------:| ------------- |
| probe_id      | optional           | The probe serial number. Can be used to specify a probe if more than one device is connected to a computer. |

#### Usage example
```python
from cysecuretools import CySecureTools
tools = CySecureTools('CY8CKIT-064B0S2-4343W')
tools.provision_device()
```
or
```python
from cysecuretools import CySecureTools
tools = CySecureTools('CY8CKIT-064B0S2-4343W', 'MyPolicy.json')
tools.provision_device()
```

## Re-provision device
Starts a device re-provisioning process. Returns True if re-provisioning was success, otherwise - False.
#### CLI implementation
### re-provision-device
#### Parameters
| Name               | Optional/Required  | Description   |
| ------------------ |:------------------:| ------------- |
| --probe_id         | optional           | The probe serial number. Can be used to specify a probe if more than one device is connected to a computer. |
| --existing-packet  | optional           | Skip the provisioning packet creation and use the existing packet. |
| --control-dap-cert | optional           | The certificate that provides the access to control DAP. For more information refer to [Open CM0 Access Port](#open-cm0-access-port).|

#### Usage example
```bash
cysecuretools -t CY8CKIT-064B0S2-4343W re-provision-device
```
or
```bash
cysecuretools -t CY8CKIT-064B0S2-4343W -p MyPolicy.json re-provision-device
```

#### API implementation
### re_provision_device()
#### Parameters
| Name             | Optional/Required  | Description   |
| ---------------- |:------------------:| ------------- |
| probe_id         | optional           | The probe serial number. Can be used to specify a probe if more than one device is connected to a computer. |
| erase_boot       | optional           | Indicates whether erase BOOT slot. |
| control_dap_cert | optional           | The certificate that provides the access to control DAP. For more information refer to [Open CM0 Access Port](#open-cm0-access-port).|

#### Usage example
```python
from cysecuretools import CySecureTools
tools = CySecureTools('CY8CKIT-064B0S2-4343W')
tools.re_provision_device()
```
or
```python
from cysecuretools import CySecureTools
tools = CySecureTools('CY8CKIT-064B0S2-4343W', 'MyPolicy.json')
tools.re_provision_device()
```

## Sign image
Signs the user application with the keys created by the [create keys](#create-keys).
#### CLI implementation
### sign-image
#### Parameters
| Name             | Optional/Required  | Description   |
| ---------------- |:------------------:| ------------- |
| -h, --hex        | required           | The hex file with the user application. |
| -i, --image-id   | optional           | The ID of the firmware image in the device. The default value is 4. |
| --image-type     | optional           | Indicates which type of an image is signed - boot or upgrade. If omitted, both types will be generated. Accepted only **BOOT** or **UPGRADE** values. |
| -e, --encrypt    | optional           | Public key PEM-file for the image encryption. |
| -R, --erased-val | optional           | The value that is read back from erased flash. |
| --boot-record    | optional           | Create CBOR encoded boot record TLV. Represents the role of the software component (e.g. CoFM for coprocessor firmware) [max. 12 characters] |

#### Usage example
```bash
cysecuretools -t CY8CKIT-064B0S2-4343W sign-image --hex example-blinky.hex --image-type BOOT
```
or
```bash
cysecuretools -t CY8CKIT-064B0S2-4343W -p MyPolicy.json sign-image --hex example-blinky.hex --image-type BOOT
```

#### API implementation
### sign_image()
#### Parameters
| Name          | Optional/Required  | Description   |
| ------------- |:------------------:| ------------- |
| hex_file      | required           | The hex file with the user application. |
| image_id      | optional           | The ID of the firmware image in the device. The default value is 4. |
| image_type    | optional           | Indicates which type of an image is signed - boot or upgrade. If omitted, both types will be generated. Accepted only **BOOT** or **UPGRADE** values. |
| encrypt_key   | optional           | Path to public key file for the image encryption. |
| erased_val    | optional           | The value that is read back from erased flash. |
| boot_record   | optional           | Create CBOR encoded boot record TLV. Represents the role of the software component (e.g. CoFM for coprocessor firmware) [max. 12 characters] |

#### Usage example
```python
from cysecuretools import CySecureTools
tools = CySecureTools('CY8CKIT-064B0S2-4343W')
tools.sign_image('example-blinky.hex')
```
or
```python
from cysecuretools import CySecureTools
tools = CySecureTools('CY8CKIT-064B0S2-4343W', 'MyPolicy.json')
tools.sign_image('example-blinky.hex')
```

## Entrance exam
Checks the device life-cycle, Flashboot firmware, and Flash memory state. Returns True if the device is ready for provisioning, otherwise - False.
#### CLI implementation
### entrance-exam
#### Parameters
No parameters needed.
#### Usage example
```bash
cysecuretools -t CY8CKIT-064B0S2-4343W entrance-exam
```
or
```bash
cysecuretools -t CY8CKIT-064B0S2-4343W -p MyPolicy.json entrance-exam
```

#### API implementation
### entrance_exam()
#### Parameters
No parameters needed.
#### Usage example
```python
from cysecuretools import CySecureTools
tools = CySecureTools('CY8CKIT-064B0S2-4343W')
tools.entrance_exam()
```
or
```python
from cysecuretools import CySecureTools
tools = CySecureTools('CY8CKIT-064B0S2-4343W', 'MyPolicy.json')
tools.entrance_exam()
```

## Create a certificate
Creates a certificate in the X.509 format based on the device public key.
#### CLI implementation
### create-certificate
#### Parameters
| Name            | Optional/Required  | Description   |
| --------------- |:------------------:| ------------- |
| -n, --name      | optional           | The certificate filename. By default 'psoc_cert.pem' |
| -e , --encoding | optional           | The certificate encoding (PEM, DER). By default 'PEM' |
| --probe-id      | optional           | The probe serial number. |
| --subject-name  | optional           | The certificate subject name. By default 'Example Certificate' |
| --country       | optional           | The certificate country code. By default 'US' |
| --state         | optional           | The certificate issuer state. By default 'San Jose' |
| --organization  | optional           | The certificate issuer organization. By default 'Cypress Semiconductor' |
| --issuer-name   | optional           | The certificate issuer name. By default 'Example Issuer Name' |
| --private-key   | optional           | The private key to sign the certificate. By default HSM private key |

#### Usage example
```bash
cysecuretools -t CY8CKIT-064B0S2-4343W create-certificate -e DER --private-key some_key.json
```
or
```bash
cysecuretools -t CY8CKIT-064B0S2-4343W -p MyPolicy.json create-certificate -e DER --private-key some_key.json
```

#### API implementation
### create_x509_certificate()
#### Parameters
| Name          | Optional/Required  | Description   |
| ------------- |:------------------:| ------------- |
| cert_name     | optional           | The certificate filename. |
| cert_encoding | optional           | The certificate encoding (PEM or DER). By default 'PEM' |
| probe_id      | optional           | The probe ID. Used to read a public key and die ID from a device. Can be used to specify a probe if more than one device is connected to a computer. |
| kwargs        | optional           | The dictionary with the certificate fields. |

#### Usage example
```python
from cysecuretools import CySecureTools
tool = CySecureTools('CY8CKIT-064B0S2-4343W')
cert_fields = {
    'subject_name': 'Example Certificate',
    'country': 'US',
    'state': 'San Jose',
    'organization': 'Cypress Semiconductor',
    'issuer_name': 'Example Issuer Name',
    'private_key': 'keys/hsm_state.json'
}
tool.create_x509_certificate(cert_name='example_cert.pem', **cert_fields)
```
or
```python
from cysecuretools import CySecureTools
tools = CySecureTools('CY8CKIT-064B0S2-4343W', 'MyPolicy.json')
cert_fields = {
    'subject_name': 'Example Certificate',
    'country': 'US',
    'state': 'San Jose',
    'organization': 'Cypress Semiconductor',
    'issuer_name': 'Example Issuer Name',
    'private_key': 'keys/hsm_state.json'
}
tool.create_x509_certificate(cert_name='example_cert.pem', **cert_fields)
```

## Create image certificate
Creates Bootloader image certificate.
#### CLI implementation
### image-certificate
#### Parameters
| Name           | Optional/Required  | Description   |
| -------------- |:------------------:| ------------- |
| -i, --image    | required           | The bootloader image path. |
| -k, --key      | required           | The private key for certificate signing. |
| -o, --cert     | optional           | The output certificate file path. |
| -v, --version  | optional           | The image version. |
| --image-id     | optional           | The image ID. |
| -d, --exp-date | optional           | The certificate expiration date. |

#### Usage example
```bash
cysecuretools -t CY8CKIT-064B0S2-4343W image-certificate -i CypressBootloader_CM0p.hex --key ../keys/key.json -o CypressBootloader_CM0p.jwt --version "1.0.0.200" --image-id 0 --exp-date "Jan 1 2031"
```
or
```bash
cysecuretools -t CY8CKIT-064B0S2-4343W -p MyPolicy.json image-certificate -i CypressBootloader_CM0p.hex --key ../keys/key.json -o CypressBootloader_CM0p.jwt --version "1.0.0.200" --image-id 0 --exp-date "Jan 1 2031"
```

#### API implementation
### create_image_certificate()
#### Parameters
| Name          | Optional/Required  | Description   |
| ------------- |:------------------:| ------------- |
| image         | required           | The bootloader image path. |
| key           | required           | The private key for certificate signing. |
| output        | required           | The output certificate file path. |
| version       | required           | The image version. |
| image_id      | optional           | The image ID. |
| exp_date_str  | optional           | The certificate expiration date. |

#### Usage example
```python
from cysecuretools import CySecureTools
tool = CySecureTools('CY8CKIT-064B0S2-4343W')
tool.create_image_certificate('CypressBootloader_CM0p.hex', '../keys/key.json', 'CypressBootloader_CM0p.jwt', "1.0.0.200", 0, 'Jan 1 2031')
```
or
```python
from cysecuretools import CySecureTools
tools = CySecureTools('CY8CKIT-064B0S2-4343W', 'MyPolicy.json')
tools.create_image_certificate('CypressBootloader_CM0p.hex', '../keys/key.json', 'CypressBootloader_CM0p.jwt', "1.0.0.200", 0, 'Jan 1 2031')
```

## Flash map methods
These methods provides an image address and size from the policy file.
#### CLI implementation
The CLI only methods.
### slot-address
Returns slot address from given policy
#### Parameters
| Name             | Optional/Required  | Description   |
| ---------------- |:------------------:| ------------- |
| -i, --image-id   | required           | The image ID. |
| -t, --image-type | required           | The image type - **BOOT** or **UPGRADE**. |
| -h               | optional           | If present, output value will be in HEX format. |
#### Usage example
```bash
cysecuretools -t CY8CKIT-064B0S2-4343W slot-address --image-id 1 --image-type BOOT -h
```
or
```bash
cysecuretools -t CY8CKIT-064B0S2-4343W -p MyPolicy.json slot-address --image-id 1 --image-type UPGRADE
```
### slot-size
Returns slot size from given policy
#### Parameters
| Name             | Optional/Required  | Description   |
| ---------------- |:------------------:| ------------- |
| -i, --image-id   | required           | The image ID. |
| -t, --image-type | required           | The image type - **BOOT** or **UPGRADE**. |
| -h               | optional           | If present, output value will be in HEX format. |
#### Usage example
```bash
cysecuretools -t CY8CKIT-064B0S2-4343W slot-size --image-id 4 --image-type BOOT -h
```
or
```bash
cysecuretools -t CY8CKIT-064B0S2-4343W -p MyPolicy.json slot-size --image-id 4 --image-type UPGRADE
```
#### API implementation
The API only method. Returns a tuple with the address and size for a specified image.
### flash_map()
#### Parameters
| Name          | Optional/Required  | Description   |
| ------------- |:------------------:| ------------- |
| image_id      | optional           | The ID of the firmware image in the device. The default value is 4. |

#### Usage example
```python
from cysecuretools import CySecureTools
tools = CySecureTools('CY8CKIT-064B0S2-4343W')
tools.flash_map()
```
or
```python
from cysecuretools import CySecureTools
tools = CySecureTools('CY8CKIT-064B0S2-4343W', 'MyPolicy.json')
tools.flash_map()
```

## List of supported devices
Outlists the supported devices to the console
#### CLI implementation
### device-list
#### Parameters
No parameters needed.
#### Usage example
```bash
cysecuretools device-list
```

#### API implementation
### device_list()
#### Parameters
No parameters needed.
#### Usage example
```python
from cysecuretools import CySecureTools
tools = CySecureTools('CY8CKIT-064B0S2-4343W')
tools.device_list()
```
or
```python
from cysecuretools import CySecureTools
tools = CySecureTools()
```

## Encrypted programming
The encrypted programming consists of two steps:
- Create encrypted image
- Program encrypted image

### Create encrypted image
Creates encrypted image for encrypted programming.
#### CLI implementation
### encrypt-image
#### Parameters
| Name                  | Optional/Required  | Description   |
| --------------------- |:------------------:| ------------- |
| -i, --image           | required           | The image to encrypt. |
| -h, --host-key-id     | required           | Host private key ID (4 - HSM, 5 - OEM). |
| -d, --device-key-id   | required           | Device public key ID (1 - device, 12 - group). |
| -a, --algorithm       | optional           | Asymmetric algorithm for key derivation function.   |
| --key-length          | optional           | Derived key length. |
| --raw-image           | optional           | Output file of raw image for encrypted programming. |
| -o, --encrypted-image | required           | Output file of encrypted image for encrypted programming. |
| --padding-value       | optional           | Value for image padding. |
| --probe_id            | optional           | Probe serial number. Used to read device public key from device. |
#### Usage example
```bash
cysecuretools -t CY8CKIT-064B0S2-4343W encrypt-image -i BlinkyApp.hex -h 4 -d 1 -o encrypted_image.txt
```

#### API implementation
### encrypt_image()
#### Parameters
| Name          | Optional/Required  | Description   |
| ------------- |:------------------:| ------------- |
| image           | required           | The image to encrypt. |
| host_key_id     | required           | Host private key ID (4 - HSM, 5 - OEM). |
| dev_key_id      | required           | Device public key ID (1 - device, 12 - group). |
| algorithm       | optional           | Asymmetric algorithm for key derivation function. |
| key_length      | optional           | Derived key length. |
| raw_image       | optional           | Output file of raw image for encrypted programming. |
| encrypted_image | optional           | Output file of encrypted image for encrypted programming. |
| padding_value   | optional           | Value for image padding. |
| probe_id        | optional           | Probe serial number. Used to read device public key from device. |

#### Usage example
```python
from cysecuretools import CySecureTools
tools = CySecureTools('CY8CKIT-064B0S2-4343W')
tools.encrypt_image('BlinkyApp.hex', 4, 1, encrypted_image='encrypted_image.txt')
```

### Program encrypted image
Programs encrypted image.
#### CLI implementation
### encrypted-programming
#### Parameters
| Name                  | Optional/Required  | Description   |
| --------------------- |:------------------:| ------------- |
| -i, --encrypted-image | required           | The encrypted image to program. |
| --probe-id            | optional           | Probe serial number. |
#### Usage example
```bash
cysecuretools -t CY8CKIT-064B0S2-4343W encrypted-programming -i encrypted_image.txt
```

#### API implementation
### encrypted_programming()
#### Parameters
| Name          | Optional/Required  | Description   |
| --------------- |:------------------:| ------------- |
| encrypted_image | required           | The encrypted image to program. |
| probe_id        | optional           | Probe serial number. |

#### Usage example
```python
from cysecuretools import CySecureTools
tools = CySecureTools('CY8CKIT-064B0S2-4343W')
tools.encrypted_programming('encrypted_image.txt')
```

### Programming encrypted bootloader
During device provisioning, the bootloader can be programmed in encrypted format.
This requires following steps:

1. Create image certificate for your custom bootloader application (refer [Create image certificate](#create-image-certificate)).
2. Encrypt bootloader application (refer [Create encrypted image](#create-encrypted-image)).
3. Update policy with the encrypted bootloader file:

   In the policy file, set the bootloader mode to _custom_ and provide bootloader program file (_hex_path_) and image certificate (_jwt_path_). To indicate that the image is encrypted, set _encrypted_ field to _true_. If custom bootloader is not encrypted, set _encrypted_ field to _false_ or do not specify it. Absolute or relative path can be used. Relative path is related to the policy file location.
   ```json
   "cy_bootloader":
    {
        "mode": "custom",
        "hex_path": "encrypted_image.txt",
        "jwt_path": "CypressBootloader_CM0p.jwt",
        "encrypted": true
    },
   ```

### Programming encrypted user application
This requires following steps:

1. Encrypt application (refer [Create encrypted image](#create-encrypted-image)).
3. Update policy with the encrypted bootloader file:

   In the policy file _pre_build_ field add _user_apps_ field as shown below. To indicate that the image is encrypted, set _encrypted__ field to _true_. If the application is not encrypted, set encrypted field to _false_. Absolute or relative path can be used. Relative path is related to the policy file location.
   ```json
   "pre_build": {
        ...
        "user_apps": [
            { "encrypted": true, "app": "encrypted_image.txt" },
            { "encrypted": true, "app": "encrypted_image.txt" }
   }
   ```

### CyBootloader and Secure Flash Boot version
Outputs CyBootloader version bundled with the package. Outputs CyBootloader and Secure Flash Boot version programmed into device.

#### CLI implementation
### version
#### Parameters
| Name                | Optional/Required  | Description   |
| ------------------- |:------------------:| ------------- |
| --probe-id          | optional           | Probe serial number. |
| --ap                | optional           | The access port used for to read CyBootloader and Secure Flash Boot version from device. |
#### Usage example
Using the command without _--target_ argument outputs CyBootloader version bundled with the package.
```bash
cysecuretools version
```
Using the command with _--target_ argument outputs CyBootloader and Secure Flash Boot version programmed into the connected device.
```bash
cysecuretools -t CY8CKIT-064B0S2-4343W version
```

#### API implementation
### print_version()
#### Parameters
| Name              | Optional/Required  | Description   |
| ----------------- |:------------------:| ------------- |
| probe_id          | optional           | Probe serial number. |
| ap                | optional           | The access port used for to read CyBootloader and Secure Flash Boot version from device. |

#### Usage example
```python
from cysecuretools import CySecureTools
tools = CySecureTools('CY8CKIT-064B0S2-4343W')
tools.print_version()
```

### Sign certificate
Signs JSON certificate with the private key.

#### CLI implementation
### sign-cert
#### Parameters
| Name                | Optional/Required  | Description   |
| ------------------- |:------------------:| ------------- |
| -j, --json-file     | required           | JSON file to be signed. |
| -k, --key-id        | required           | Private Key ID to sign the certificate with (1 - DEVICE, 4 - HSM, 5 - OEM, 12 - GROUP). |
| -o, --out-file      | optional           | Filename where to save the JWT. If not specified, the input file name with "jwt" extension will be used. |
#### Usage example
```bash
cysecuretools -t CY8CKIT-064B0S2-4343W sign-cert --json-file packets/control_dap_cert.json --key-id 5
```
or
```bash
cysecuretools -t CY8CKIT-064B0S2-4343W -p MyPolicy.json sign-cert --json-file packets/control_dap_cert.json --key-id 5
```

#### API implementation
### sign_json()
#### Parameters
| Name              | Optional/Required  | Description   |
| ----------------- |:------------------:| ------------- |
| json_file         | required           | JSON file to be signed. |
| priv_key_id       | required           | Private Key ID to sign the certificate with (1 - DEVICE, 4 - HSM, 5 - OEM, 12 - GROUP). |
| output_file       | optional           | Filename where to save the JWT. If not specified, the input file name with "jwt" extension will be used. |

#### Usage example
```python
from cysecuretools import CySecureTools
tools = CySecureTools('CY8CKIT-064B0S2-4343W')
jwt = tools.sign_json('dap_cert.json', 5)
```
or
```python
from cysecuretools import CySecureTools
tools = CySecureTools('CY8CKIT-064B0S2-4343W', 'MyPolicy.json')
jwt = tools.sign_json('dap_cert.json', 5)
```

### Read public key from device
Reads public key from device.

#### CLI implementation
### read-public-key
#### Parameters
| Name                | Optional/Required  | Description   |
| ------------------- |:------------------:| ------------- |
| -k, --key-id        | required           | Key ID to read (1 - DEVICE, 4 - HSM, 5 - OEM, 12 - GROUP). |
| -f, --key-format    | optional           | Key format (jwk or pem). Default is 'jwk'. |
| -o, --out-file      | optional           | Filename where to save the key. If not specified, the log file is used for output. |
| --probe-id          | optional           | Probe serial number. |
#### Usage example
```bash
cysecuretools -t CY8CKIT-064B0S2-4343W read-public-key --key-id 5 --out-file oem_pub.jwk
```
or
```bash
cysecuretools -t CY8CKIT-064B0S2-4343W read-public-key --key-id 5 --key-format pem --out-file oem_pub.pem
```

#### API implementation
### read_public_key()
#### Parameters
| Name       | Optional/Required  | Description   |
| ---------- |:------------------:| ------------- |
| key_id     | required           | Key ID to read (1 - DEVICE, 4 - HSM, 5 - OEM, 12 - GROUP). |
| key_fmt    | required           | Key format (jwk or pem). |
| out_file   | optional           | Filename where to save the key. |
| probe_id   | optional           | Probe serial number. |

#### Usage example
```python
from cysecuretools import CySecureTools
tools = CySecureTools('CY8CKIT-064B0S2-4343W')
jwk = tools.read_public_key(5, 'jwk')
```
or
```python
from cysecuretools import CySecureTools
tools = CySecureTools('CY8CKIT-064B0S2-4343W', 'MyPolicy.json')
pem = tools.read_public_key(5, 'pem', 'pub_oem.pem')
```


### Read die ID from device
Reads die ID from device.

#### CLI implementation
### read-die-id
#### Parameters
| Name            | Optional/Required  | Description   |
| --------------- |:------------------:| ------------- |
| -o, --out-file  | optional           | Filename where to save die ID. If not specified, the log file is used for output. |
| --probe-id      | optional           | Probe serial number. |

#### Usage example
```bash
cysecuretools -t CY8CKIT-064B0S2-4343W read-die-id -o die_id.json
```

#### API implementation
### read_die_id()
#### Parameters
| Name          | Optional/Required  | Description   |
| ------------- |:------------------:| ------------- |
| probe_id      | optional           | Probe serial number. |

#### Usage example
```python
from cysecuretools import CySecureTools
tools = CySecureTools('CY8CKIT-064B0S2-4343W')
jwk = tools.read_die_id()
```


## Closing All Access Ports
Often it is necessary to close all access ports during provisioning. After closing the access ports, there will be no way to program application.
In this case, the application can be programmed during the provisioning process, when the access ports are open. Refer [Programming encrypted user application](#programming-encrypted-user-application).


## Open CM0 Access Port
_System AP must be enabled since it is used to open CM0 AP._

There is a way to close CM0 access port and allow to open it using a certificate. To close CM0 port with the ability of further opening, provision the device with the following configuration of _m0p_ in the policy file:
```json
"m0p" : {
    "permission" : "allowed",
    "control" : "certificate",
    "key" : 5
}
```
The above configuration means that the CM0 AP can be opened with certificate. The certificate must be signed with the key with ID 5.
The certificate can be found in the packets directory (look for control_dap_cert.json).

### Sign certificate
Once device was provisioned with the above _m0p_ configuration, the AP can be opened with the certificate.

To sign the certificate refer to [Sign certificate](#sign-certificate) section. The key ID used to sign the certificate must match the key ID specified in the policy file _m0p_ properties.

### Re-provision and open CM0 access port
Re-provision device using the certificate to open CM0 access port for programming bootloader program file.
```bash
cysecuretools -t CY8CKIT-064B0S2-4343W re-provision-device --control-dap-cert packets/control_dap_cert.jwt
```
_NOTE_: The access port opens for a short time to program bootloader during re-provisioning.

# Policy and Keys

## Provisioning Policies
Change the policy by specifying the _policy_ argument. All available policy files are located in the _policy_ directory inside the folder with the target name in the package installation directory.

## Policy Location
By default, the keys and policy files location is the package installation directory.
To use a policy file from a different location, provide the policy file location while creating a CySecureTools object.

#### CLI example:
```bash
cysecuretools -t CY8CKIT-064B0S2-4343W -p /Users/example/policy_multi_CM0_CM4.json
```

#### API example:
```python
from cysecuretools import CySecureTools
tools = CySecureTools('CY8CKIT-064B0S2-4343W', '/Users/example/policy_multi_CM0_CM4.json')
```

## Custom Data Sections
Policy file used for provisioning or reprovisioning can contain optional list of sections, e.g.:
```json
{
    "custom_data_sections": ["abc", "xyz"],
    "abc":
    {
        ...
    },
    "xyz":
    {
        ...
    }
}
```
All listed sections content will be added to the provisioning JWT packet. These data sections are simply copied raw without validation or filtering.

## Keys Location
By default, the keys location is the  _keys_ directory inside the package installation directory. The keys location can be changed in the policy file. Either an absolute or relative path can be used. A relative path is related to the policy file location.

Example:
```json
{
    "boot_auth": [
        8
    ],
    "boot_keys": [
        { "kid": 8, "key": "../keys/USERAPP_CM4_KEY.json" }
    ],
    "id": 4,
    "monotonic": 0,
    "smif_id": 0,
    "upgrade": true,
    "version": "0.1",
    "rollback_counter": 0,
    "encrypt": true,
    "encrypt_key_id": 1,
    "encrypt_peer": "../keys/dev_pub_key.pem",
    "resources": [
        {
            "type": "BOOT",
            "address": 268435456,
            "size": 327680
        },
        {
            "type": "UPGRADE",
            "address": 268763136,
            "size": 327680
        }
    ]
}
```

The policy file properties which represent the keys:

| Property      | Description      |
| ------------- |------------------|
| boot_keys     | The keys for signing a BOOT image. |
| encrypt_peer  | The public key read from the device during the provisioning procedure. The key is used for the image encryption. |


# CyBootloader
By default, the tools use _release_ mode of CyBootloader. This does not output CyBootloader logs to the serial port, but it has a smaller size. The _debug_ mode of CyBootloader allows seeing its logs using the serial port with the baud rate 115200. To change CyBootloader mode, change the cy_bootloader field in the policy file:

for _debug_ mode
```json
"cy_bootloader":
{
    "mode": "debug"
}
```
for _release_ mode
```json
"cy_bootloader":
{
    "mode": "release"
}
```

## Custom Bootloader
To use a custom bootloader, specify value _custom_ in the _cy_bootloader_ _mode_ field. Also, it requires the specifying bootloader image (_hex_path_) and its certificate (_jwt_path_). A bootloader image certificate is a JWT file that confirms the image's validity. To create an image certificate, use the [image certificate creation](#create-image-certificate) command.
```json
"cy_bootloader":
{
    "mode": "custom",
    "hex_path": "../prebuilt/CyBootloader_WithLogs/CypressBootloader_CM0p.hex",
    "jwt_path": "../prebuilt/CyBootloader_WithLogs/CypressBootloader_CM0p.jwt"
}
```

## Encrypted Bootloader
Refer [Programming encrypted bootloader](#programming-encrypted-bootloader).

# Using Different On-Chip Debugger
The package supports the following on-chip debuggers - `pyocd` and `Cypress OpenOCD`. To use a different debugger, run command `set-ocd`.

### Command Parameters
| Name          | Optional/Required  | Description   |
| ------------- |:------------------:| ------------- |
| --name        | required           | The tool name (pyocd \| openocd). |
| --path        | optional           | The path to the tool root directory. Not applicable for pyocd. |

### Usage example
```bash
cysecuretools set-ocd --name openocd --path /Users/example/tools/openocd-4.0
```

## pyocd
`pyocd` is the default debugger and is installed together with cysecuretools. The project is hosted on PyPI (https://pypi.org/project/pyocd/).

## OpenOCD
`Cypress OpenOCD` is downloaded and installed separately. The supported version is 4.0.0. The project is hosted on GitHub (https://github.com/cypresssemiconductorco/openocd).


# Package Installation Directory
Use the `pip` command to get the package location:
```bash
pip show cysecuretools
```

# License and Contributions
The software is provided under the Apache-2.0 license. Contributions to this project are accepted under the same license.
This project contains code from other projects. The original license text is included in those source files.