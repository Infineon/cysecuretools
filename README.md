This package contains security tools for creating keys, creating certificates, signing user application, and provisioning Cypress MCUs.

# Features

* Create keys - A key is a file used to authorize access to device data. There must be a common key pair between the secure device and user application. A device must be provisioned with a public key and user application must be signed with corresponding private key from same pair.

* Provisioning a device - Provisioning is the act of configuring a device with an authorized set of keys, certificates, and policies.

* Entrance exam - Before provisioning a device, there is an option to ensure that the device has a valid state by passing an entrance exam.

* Sign a user application - To run a user application on a secure device, the application must be signed with the same keys that the device has been provisioned with.

* Create a certificate - Create a certificate in the X.509 format with the device public key inside and signed with the private key. The certificate can be used when connecting to a cloud service.

# Prerequisites

* Python 3.6 or later

* Installed the libusb driver

   **Windows**
   - Download and unzip libusb-1.0.21.7z from https://github.com/libusb/libusb/releases/tag/v1.0.21
   - Run following command to determine if a Python shell is executing in 32-bit or 64-bit mode on OS: `python -c "import struct; print(struct.calcsize('P') * 8)"`
   - Copy *libusb-1.0.dll* file into Python folder (use the 64-bit version of DLL for the 64-bit Python and the 32-bit version of DLL for the 32-bit Python)
   - Make sure Python path is located at the beginning of the Path environment variable.
   
   **Linux/Mac OS**
   - Use [homebrew] to install the driver from the terminal: `homebrew install libusb`

# Installing Package

Invoke `pip install` from the command line:

```bash
pip install cysecuretools
```

# Quick Start
```python
from cysecuretools import CySecureTools

tools = CySecureTools('CY8CPROTO-064B0S1-BLE')

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

To run the above code from the command line, use the `python -c` command:
```bash
python -c "from cysecuretools import CySecureTools; tools = CySecureTools('CY8CPROTO-064B0S1-BLE'); tools.entrance_exam(); tools.create_keys(); tools.create_provisioning_packet(); tools.provision_device(); tools.sign_image('example-blinky.hex')"
```

# API

## **create_keys()**
Creates keys specified in the policy file for the image signing and encryption.
#### Parameters
| Name          | Optional/Required  | Description   |
| ------------- |:------------------:| ------------- |
| overwrite     | optional           | Indicates whether overwrite the keys in the output directory if they already exist. The available values: True, False, None. If None, a prompt will ask whether to overwrite the existing keys. |
| out           | optional           | The output directory for generated keys. By default, the keys location will be as specified in the policy file. |

#### Usage example
```python
from cysecuretools import CySecureTools
tools = CySecureTools('CY8CPROTO-064B0S1-BLE')
tools.create_keys()
```

## **create_provisioning_packet()**
Creates a JWT packet (a file to be programmed into the device during the provisioning procedure). In general, this is a policy, keys, and certificates in the JWT format. Returns True if the packet is created successfully, otherwise - False.

#### Usage example
```python
from cysecuretools import CySecureTools
tools = CySecureTools('CY8CPROTO-064B0S1-BLE')
tools.create_provisioning_packet()
```

## **provision_device()**
Starts device provisioning process. Returns true if provisioning was success, otherwise False.

#### Parameters
| Name          | Optional/Required  | Description   |
| ------------- |:------------------:| ------------- |
| probe_id      | optional           | Probe serial number. Can be used to specify probe if more than one device is connected to a computer. |

#### Usage example
```python
from cysecuretools import CySecureTools
tools = CySecureTools('CY8CPROTO-064B0S1-BLE')
tools.provision_device()
```

## **sign_image()**
Signs the user application with the keys created by the _create_keys()_ API.

#### Parameters
| Name          | Optional/Required  | Description   |
| ------------- |:------------------:| ------------- |
| hex_file      | required           | The hex file with the user application. |
| image_id      | optional           | The ID of the firmware image in the device. The default value is 4. |

#### Usage example
```python
from cysecuretools import CySecureTools
tools = CySecureTools('CY8CPROTO-064B0S1-BLE')
tools.sign_image('example-blinky.hex')
```

## **entrance_exam()**
Checks the device life-cycle, Flashboot firmware, and Flash memory state. Returns True if the device is ready for provisioning, otherwise - False.

#### Usage example
```python
from cysecuretools import CySecureTools
tools = CySecureTools('CY8CPROTO-064B0S1-BLE')
tools.entrance_exam()
```

## **create_x509_certificate()**
Creates a certificate in the X.509 format based on the device public key.

#### Parameters
| Name          | Optional/Required  | Description   |
| ------------- |:------------------:| ------------- |
| cert_name     | optional           | The certificate filename. |
| cert_encoding | optional           | The certificate encoding. |
| probe_id      | optional           | The probe ID. Used to read a public key and die ID from a device. Can be used to specify a probe if more than one device is connected to a computer. |
| kwargs        | optional           | The dictionary with the certificate fields. |

#### Usage example
```python
from cysecuretools import CySecureTools
tools = CySecureTools('CY8CPROTO-064B0S1-BLE')
tools.create_x509_certificate()
```

## **flash_map()**
The API provides an image address and size from the policy file. Returns a tuple with the address and size for a specified image.

#### Parameters
| Name          | Optional/Required  | Description   |
| ------------- |:------------------:| ------------- |
| image_id      | optional           | The ID of the firmware image in the device. The default value is 4. |

#### Usage example
```python
from cysecuretools import CySecureTools
tools = CySecureTools('CY8CPROTO-064B0S1-BLE')
tools.flash_map()
```

# Policy and Keys

## Provisioning Policies
Change the policy by specifying _policy_ argument. All available policy files are located in _policy_ directory inside the folder with the target name in the package installation directory.

## Policy Location
By default, the keys and policy files location is the package installation directory.
To use a policy file from a different location, provide the policy file location while creating a CySecureTools object.

Example:
```python
from cysecuretools import CySecureTools
tools = CySecureTools('CY8CPROTO-064B0S1-BLE', '/Users/example/policy_single_stage_CM4.json')
```

## Keys Location
By default, the keys location is the  _keys_ directory inside the package installation directory. The keys location can be changed in the policy file. Either an absolute or relative path can be used. If a relative path is used, it is related to the policy file location.

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
    "encrypt_key": "../keys/image-aes-128.key",
    "encrypt_key_id": 1,
    "encrypt_peer": "../keys/dev_pub_key.pem",
    "upgrade_auth": [
        8
    ],
    "upgrade_keys": [
        { "kid": 8, "key": "../keys/USERAPP_CM4_KEY.json" }
    ],
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

| Property      | Description  |
| ------------- |------------------|
| boot_keys     | The keys for signing a BOOT image. |
| upgrade_keys  | The keys for signing an UPGRADE image. |
| encrypt_key   | The key used for the image encryption. |
| encrypt_peer  | The public key read from the device during the provisioning procedure. The key is used for the image encryption. |


# CyBootloader
By default, the tools use _debug_ mode of CyBootloader. This allows seeing CyBootloader logs using the serial port with the baud rate 115200. The _release_ mode of CyBootloader does not have this feature, but it has a smaller size. To change CyBootloader mode, change the  cy_bootloader field in the policy file:
```json
"cy_bootloader":
{
    "mode": "debug"
}
```

# Package Installation Directory
Use the `pip` command to get the package location:
```bash
pip show cysecuretools
```

# License and Contributions
The software is provided under Apache-2.0 license. Contributions to this project are accepted under the same license.
This project contains code from other projects. The original license text is included in those source files.