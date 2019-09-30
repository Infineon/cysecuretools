This package contains security tools for creating keys, signing user application and device provisioning.

# Prerequisites

* Python 3.7

* Installed pyocd

  From command line: `pip install --upgrade --force-reinstall git+http://git-ore.aus.cypress.com/repo/pyocd.git`

* Installed libusb driver

   **Windows**
   - Download and unzip libusb-1.0.21.7z from https://github.com/libusb/libusb/releases/tag/v1.0.21
   - Copy *libusb-1.0.dll* file into Python 3.7 folder (use 64-bit version of the DLL for 64-bit Python and 32-bit version of the DLL for 32-bit Python)
   - Make sure Python path located at the begginning of Path environment variable
   
   **Linux/Mac OS**
   - Use [homebrew] to install the driver from terminal: `homebrew install libusb`

# Installing Package

From command line invoke `pip install`:

```
pip install --upgrade --force-reinstall git+http://git-ore.aus.cypress.com/repo/cysecuretools.git
```
# Installing libusb

# Preparing Secure Application

The package has an APIs that should be sequentially called to make a device and a user application protected.

## Basic Guide

The basic guide provides several steps that allow to create key, provision device with a default policy and sign user application with the key.

### 1. Create keys
The key is a certificate file used to authorize access to a device data. There must be common key pair between secure device and user application. A device must be provisioned with a public key and user application must be signed with corresponding private key from same pair.

**create_keys()** - creates keys specified in policy file for image signing and encryption.
#### Arguments
* _overwrite_ (optional) - Indicates whether overwrite keys in the output directory if they already exist. Available values: True, False, None. If the value is None, a prompt will ask whether to overwrite existing keys.
* _out_ (optional) - Output directory for generated keys. By default, keys location will be as specified in the policy file.
#### Usage example
```
from cysecuretools import CySecureTools
tools = CySecureTools('cy8cproto-064s1-sb', 'targets/cy8cproto_064s1_sb/policy/policy_single_stage_CM4.json')
tools.create_keys()
```

### 2. Create provisioning packet
The provisioning packet is a JWT file to program into device during provisioning procedure. In general, this is policy and keys in JWT format. Returns True if packet created successfully, otherwise False.

**create_provisioning_packet()** - creates JWT packet for provisioning device.
#### Usage example
```
from cysecuretools import CySecureTools
tools = CySecureTools('cy8cproto-064s1-sb', 'targets/cy8cproto_064s1_sb/policy/policy_single_stage_CM4.json')
tools.create_provisioning_packet()
```

### 3. Provision device
Provisioning is the act of configuring a device with an authorized set of keys (certificates), credentials and firmware images.

**provision_device()** - executes device provisioning that is the process of attaching a certificate to the device identity. Returns true if provisioning was success, otherwise False.
#### Arguments
* _probe_id_ (optional) - Probe serial number. Can be used to specify probe if more than one device is connected to a computer.
#### Usage example
```
from cysecuretools import CySecureTools
tools = CySecureTools('cy8cproto-064s1-sb', 'targets/cy8cproto_064s1_sb/policy/policy_single_stage_CM4.json')
tools.provision_device()
```

### 4. Sign user application
To run user application on a secure device, the application must be signed with the same keys that the device has been provisioned with.

**sign_image()** - signs user application with the certificates.
#### Arguments
* hex_file - Hex file with user application.
* _image_id_ (optional) - The ID of the firmware image in the device. Default value is 4.
#### Usage example
```
from cysecuretools import CySecureTools
tools = CySecureTools('cy8cproto-064s1-sb', 'targets/cy8cproto_064s1_sb/policy/policy_single_stage_CM4.json')
tools.sign_image('mbed-os-example-blinky.hex')
```

# Additional APIs

### 1. Entrance exam
Before provisioning a device user can ensure that the device has valid state by passing an entrance exam.

**entrance_exam()** - checks device life-cycle, Flashboot firmware and Flash memory state. Returns True if the device is ready for provisioning, otherwise False.
#### Usage example
```
from cysecuretools import CySecureTools
tools = CySecureTools('cy8cproto-064s1-sb', 'targets/cy8cproto_064s1_sb/policy/policy_single_stage_CM4.json')
tools.entrance_exam()
```

### 2. Flash map
The API provides an image address and size from the policy file.

**flash_map()** - extracts information about slots from given policy. Returns tuple with address and size for the specified image. If arguments not specified, the default will be used.
#### Arguments
* _image_id_ (optional) - The ID of the firmware image in the device. Default value is 4.
#### Usage example
```
from cysecuretools import CySecureTools
tools = CySecureTools('cy8cproto-064s1-sb', 'targets/cy8cproto_064s1_sb/policy/policy_single_stage_CM4.json')
tools.flash_map()
```

# Running Tools From Command Line
To execute the tools APIs from command line use `python -c` command.

Example:
```
python -c "from cysecuretools import CySecureTools;tools = CySecureTools('cy8cproto-064s1-sb', 'targets/cy8cproto_064s1_sb/policy/policy_single_stage_CM4.json');tools.create_keys();tools.create_provisioning_packet();tools.provision_device();tools.sign_image('mbed-os-example-blinky.hex')"
```

# Package Installation Directory
Use `pip` command to get the package location:
```
pip show cysecuretools
```

# Advanced Guide
## Provisioning Policies
Change the policy by specifying _policy_ argument. All available policy files are located in _policy_ directory inside the folder with target name in the package installation directory.

## Policy Location
By default, keys and policy files location is the package installation directory.
To use policy file from different location, provide policy file location while creation CySecureTools object.

Example:
```
from cysecuretools import CySecureTools
tools = CySecureTools('cy8cproto-064s1-sb', '/Users/example/policy_single_stage_CM4.json')
```

## Keys Location
By default, keys location is _keys_ directory inside the package installation directory. Keys location can be changed in the policy file. Either absolute or relative path can be used. If use relative path it is related to the policy file location.

Example:

```
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
    "encrypt": true,
    "encrypt_key": "../keys/aes128.key",
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

_boot_keys_ - keys for signing BOOT image.

_upgrade_keys_ - keys for signing UPGRADE image.

_encrypt_key_ - key used for image encryption.

_encrypt_peer_ - public key read from device during provisioning procedure. The key is used for image encryption.

# CyBootloader
By default, the tools use debug mode of CyBootloader. It allows to see CyBootloader logs using serial port with baud rate 115200. The release mode of CyBootloader does not have this feature, but it has smaller size. To change CyBootloader mode, change cy_bootloader field in the policy file:
```
"cy_bootloader":
{
    "mode": "debug"
}
```

# License and Contributions
The software is provided under Apache-2.0 license. Contributions to this project are accepted under the same license.
This project contains code from other projects. The original license text is included in those source files.