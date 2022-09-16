This package contains security tools for creating keys, creating certificates, signing user applications, and provisioning Cypress MCUs.

# Table of Contents
- [Prerequisites](#prerequisites)
- [Documentation](#documentation)
- [Installing package](#installing-package)
- [Supported devices](#supported-devices)
- [Interface and Usage](#interface-and-usage)
    - [PSoC 64](#psoc-64)
    - [CYW20829](#cyw20829)
- [Logging](#logging)
- [Installing libusb driver](#installing-libusb-driver)
- [Known issues](#known-issues)
- [License and Contributions](#license-and-contributions)

# Prerequisites
* General
  * Python 3.6 or later
* For PSoC 64 devices
  * In case of use PyOCD:
    * [Installed the libusb driver](#installing-libusb-driver) 
    * Ensure the KitProg3 programming mode is **DAPLink**
  * In case of use OpenOCD:
    * [Installed Cypress OpenOCD](https://github.com/cypresssemiconductorco/openocd/releases)
    * Ensure the KitProg3 programming mode is **CMSIS-DAP Bulk**
  * Ensure the power selection jumper is set to provide 2.5 V to the power supply pin related to eFuse power. This voltage level is required to blow eFuses
* For CYW20829 devices
  * [Installed Cypress OpenOCD](https://github.com/cypresssemiconductorco/openocd/releases)
  * Ensure the KitProg3 programming mode is **CMSIS-DAP Bulk**
  * Ensure the power selection jumper is set to provide 2.5 V to the power supply pin related to eFuse power. This voltage level is required to blow eFuses


# Documentation
* [PSoC64 Secure MCU Secure Boot SDK User Guide](https://www.cypress.com/documentation/software-and-drivers/psoc-64-secure-mcu-secure-boot-sdk-user-guide)
* [Changelog](CHANGELOG.md)

# Installing Package
Invoke `pip install` from the command line:
```bash
$ pip install cysecuretools
```


# Supported devices
Use `device-list` command for output of the supported devices list.
```bash
$ cysecuretools device-list
```


# Interface and Usage
## PSoC 64
See [README_PSOC64.md](docs/README_PSOC64.md)
## CYW20829
See [README_CYW20829.md](docs/README_CYW20829.md)


# Logging
Every time the tool is invoked, a new log file is created in the _logs_ directory of the project. By default, the console output has INFO logging severity. The log file contains the DEBUG logging severity.

When using _pyOCD_ as a debugger, the log files contain messages sent by both tools - _CySecureTools_ and _pyOCD_. When using _OpenOCD_, the log files contain messages from the package only. For the _OpenOCD_ messages, the additional files are created (e.g. _openocd_1.log_).


# Installing libusb driver

**Windows**
  - Download and unzip libusb-1.0.25.7z from https://github.com/libusb/libusb/releases/tag/v1.0.25.
  - Run the following command to determine if a Python shell is executing in 32-bit or 64-bit mode on the OS: `python -c "import struct; print(struct.calcsize('P') * 8)"`
  - Copy *libusb-1.0.dll* file into the Python root folder (in same folder with *python.exe*). Use the 64-bit version of DLL for the 64-bit Python (MinGW64 directory) and the 32-bit version of DLL for the 32-bit Python (MinGW32 directory).
  - Ensure the Python path is located at the beginning of the Path environment variable.

**Mac OS**
  - Use [homebrew](https://brew.sh/) to install the driver from the terminal: `homebrew install libusb`.

**Linux**
  - Bundled with the system, no need for additional installation.


# Known issues
- Using the policy from version 4.0.0 in projects created by version 4.1.0 causes the CY_FB_INVALID_IMG_JWT_SIGNATURE error during re-provisioning on PSoC64-2M devices:
```
  ...
  ERROR : SFB status: CY_FB_INVALID_IMG_JWT_SIGNATURE: Invalid image certificate signature. Check the log for details
```
_Workaround_:
1. Open the policy file. 
2. Navigate to section 1 of the `boot_upgrade/firmware`. 
3. Set `boot_auth` and `bootloader_keys` as follows:
```
"boot_auth": [
    3
],
"bootloader_keys": [
    {
        "kid": 3,
        "key": "../keys/cy_pub_key.json"
    }
]
```
- During the installation of the package via _pip_ on Mac OS Big Sur, the following exception is raised:
```
  ...
  distutils.errors.DistutilsError: Setup script exited with error: SandboxViolation:
  mkdir('/private/var/root/Library/Caches/com.apple.python/private/tmp/easy_install-y8c1npmz', 511) {}

  The package setup script has attempted to modify files on your system
  that are not within the EasyInstall build area, and has been aborted.

  This package cannot be safely installed by EasyInstall, and may not
  support alternate installation locations even if you run its setup
  script by hand.  Please inform the package's author and the EasyInstall
  maintainers to find out if a fix or workaround is available.
```
_Solution:_ Upgrade the `pip` package running the following command from the terminal: `python3 -m pip install --upgrade pip`.

# License and Contributions
The software is provided under the Apache-2.0 license. Contributions to this project are accepted under the same license.
This project contains code from other projects. The original license text is included in those source files.
