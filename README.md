This package contains security tools for creating keys, creating certificates, signing user applications, and provisioning Cypress MCUs.

# Table of Contents
- [Prerequisites](#prerequisites)
- [Documentation](#documentation)
- [Installing package](#installing-package)
- [Supported devices](#supported-devices)
- [Interface and Usage](#interface-and-usage)
    - [PSoC 64](#psoc-64)
    - [CYW20829/CYW89829](#cyw20829cyw89829)
    - [XMC7100/7200](#xmc71007200)
- [Logging](#logging)
- [Installing libusb driver](#installing-libusb-driver)
- [Known issues](#known-issues)
- [License and Contributions](#license-and-contributions)

# HW/SW compatibility
## PSoC 64
<table>
  <thead>
    <tr>
      <td>Target/Kit</td>
      <td>Silicon Revision<sup>1</sup></td>
      <td>Silicon ID, Silicon Rev., Family ID</td>
      <td>Secure FlashBoot Version</td>
      <td>CyBootloader Version</td>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td colspan="6" style="text-align: center;">512K</td>
    </tr>
    <tr>
      <td>
        cyb06xx5<br>
        cy8cproto&#8209;064b0s3
      </td>
      <td>A1</td>
      <td>0xE70D, 0x12, 0x105</td>
      <td>4.0.2.1842</td>
      <td>2.0.1.6441</td>
    </tr>
    <tr>
      <td colspan="6" style="text-align: center;">2M</td>
    </tr>
    <tr>
      <td>
        cyb06xxa<br>
        cy8ckit&#8209;064b0s2&#8209;4343w
      </td>
      <td>A1</td>
      <td>0xE470, 0x12, 0x102</td>
      <td>4.0.3.2319</td>
      <td>2.0.2.8102</td>
    </tr>
    <tr>
      <td>
        cys06xxa<br>
        cy8ckit&#8209;064s0s2&#8209;4343w
      </td>
      <td>A1</td>
      <td>0xE4A0, 0x12, 0x02</td>
      <td>4.0.3.2319</td>
      <td>2.0.2.8102</td>
    </tr>
    <tr>
      <td colspan="6" style="text-align: center;">1M</td>
    </tr>
    <tr>
      <td>
        cyb06xx7<br>
        cy8cproto&#8209;064s1&#8209;sb<br>
        cy8cproto&#8209;064b0s1&#8209;ble<br>
        cy8cproto&#8209;064b0s1&#8209;ssa
      </td>
      <td>B3</td>
      <td>
        0xE262, 0x24, 0x100
        0xE261, 0x24, 0x100
      </td>
      <td>4.0.2.1842</td>
      <td>2.0.0.4041</td>
    </tr>
  </tbody>
</table>

## CYW20829
<table>
  <thead>
    <tr>
      <td>Target/Kit</td>
      <td>Silicon Revision<sup>1</sup></td>
      <td>Silicon ID, Silicon Rev., Family ID</td>
      <td>ROM Boot Version</td>
      <td>RAM Applications Version</td>
    </tr>
  </thead>
  <tbody>
  <tr>
    <td>cyw20829</td>
    <td>A0</td>
    <td>0xEB40, 0x11, 0x110</td>
    <td>1.0.0.7120</td>
    <td>1.0.0.2857</td>
  </tr>
  <tr>
    <td>cyw20829</td>
    <td>B0</td>
    <td>0xEB43, 0x21, 0x110</td>
    <td>1.2.0.8334</td>
    <td>1.2.0.3073</td>
  </tr>
  </tbody>
</table>

<sup>1</sup> Specify `--rev` option for older revision of the silicon (e.g. `$ cysecuretools -t cyw20829 --rev a0 <COMMAND>`). Using the latest revision does not require specifying the option.

## CYW89829
<table>
  <thead>
    <tr>
      <td>Target/Kit</td>
      <td>Silicon Revision</td>
      <td>Silicon ID, Silicon Rev., Family ID</td>
      <td>ROM Boot Version</td>
      <td>RAM Applications Version</td>
    </tr>
  </thead>
  <tbody>
  <tr>
    <td>cyw89829</td>
    <td>B0</td>
    <td>0xEB47, 0x21, 0x110</td>
    <td>1.2.0.8334</td>
    <td>1.2.0.3073</td>
  </tr>
  </tbody>
</table>

# Prerequisites
* General
  * Python 3.6 or later
  * [Installed Cypress OpenOCD](https://github.com/Infineon/openocd/releases)
* For PSoC 64 devices
  * Ensure the KitProg3 programming mode is **CMSIS-DAP Bulk**
  * Ensure the power selection jumper is set to provide 2.5 V to the power supply pin related to eFuse power. This voltage level is required to blow eFuses
* For CYW20829/CYW89829 devices
  * Ensure the KitProg3 programming mode is **CMSIS-DAP Bulk**
  * Ensure the power selection jumper is set to provide 2.5 V to the power supply pin related to eFuse power. This voltage level is required to blow eFuses


# Documentation
* [PSoC64 Secure MCU Secure Boot SDK User Guide](https://www.cypress.com/documentation/software-and-drivers/psoc-64-secure-mcu-secure-boot-sdk-user-guide)
* [Changelog](https://github.com/Infineon/cysecuretools/blob/master/CHANGELOG.md)

# Installing Package
Invoke `pip install` from the command line:
```bash
$ pip install cysecuretools
```
To update the already installed package:
```bash
$ pip install --upgrade --force-reinstall cysecuretools
```


# Supported devices
Use `device-list` command for output of the supported devices list.
```bash
$ cysecuretools device-list
```


# Interface and Usage
## PSoC 64
See [README_PSOC64.md](https://github.com/Infineon/cysecuretools/blob/master/docs/README_PSOC64.md)
## CYW20829/CYW89829
See [README_CYW20829.md](https://github.com/Infineon/cysecuretools/blob/master/docs/README_CYW20829.md)
## XMC7100/7200
See [README_XMC7XXX.md](https://github.com/Infineon/cysecuretools/blob/master/docs/README_XMC7XXX.md)


# Logging
Every time the tool is invoked, a new log file is created in the _logs_ directory of the project. By default, the console output has INFO logging severity. The log file contains the DEBUG logging severity.


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
