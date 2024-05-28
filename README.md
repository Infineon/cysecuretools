This package contains security tools for creating keys, creating certificates, signing user applications, and provisioning Cypress/Infineon MCUs.

# Table of Contents
- [HW/SW compatibility](#hwsw-compatibility)
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
      <td>0xE470, 0x12, 0x102</td>
      <td>4.0.3.2319</td>
      <td>2.0.2.8102</td>
    </tr>
    <tr>
      <td>
        cys06xxa<br>
        cy8ckit&#8209;064s0s2&#8209;4343w
      </td>
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
      <td>
        0xE262, 0x24, 0x100
        0xE261, 0x24, 0x100
      </td>
      <td>4.0.2.1842</td>
      <td>2.0.0.4041</td>
    </tr>
  </tbody>
</table>

## CYW20829 / CYW89829
<table>
  <thead>
    <tr>
      <td>Target/Kit</td>
      <td>Silicon ID, Silicon Rev., Family ID</td>
      <td>ROM Boot Version</td>
      <td>RAM Applications Version</td>
    </tr>
  </thead>
  <tbody>
  <tr>
    <td>cyw20829</td>
    <td>0xEB43, 0x21, 0x110</td>
    <td>1.2.0.8334</td>
    <td>1.2.0.3073</td>
  </tr>
  <tr>
    <td>cyw89829</td>
    <td>0xEB47, 0x21, 0x110</td>
    <td>1.2.0.8334</td>
    <td>1.2.0.3073</td>
  </tr>
  </tbody>
</table>

# Prerequisites
* General
  * Python 3.8 - 3.12
  * [Installed Infineon OpenOCD](https://github.com/Infineon/openocd/releases)
* For PSoC 64 / CYW20829 / CYW89829 devices
  * Ensure the KitProg3 programming mode is **CMSIS-DAP Bulk**
  * Ensure the power selection jumper is set to provide 2.5 V to the power supply pin related to eFuse power. This voltage level is required to blow eFuses


# Documentation
* [PSoC64 Secure MCU Secure Boot SDK User Guide](https://www.cypress.com/documentation/software-and-drivers/psoc-64-secure-mcu-secure-boot-sdk-user-guide)
* [Changelog](https://github.com/Infineon/cysecuretools/blob/master/CHANGELOG.md)

# Installing Package
## Windows
The installation of ModusToolbox™ Software 3.1 includes the correct version of Python and CySecureTools 5.0.0. The latest version of CySecureTools is 6.0.0.
To update the package from the ModusToolbox™ shell (for Windows users):
* In the ModusToolbox™ GUI open the terminal by clicking the **Terminal** tab in the bottom pane.
* Then, select a project in the **Project Explorer** to open a shell in the project directory.
* Enter the following command: `$ pip install --upgrade --force-reinstall edgeprotecttools`

## Linux / macOS
Install Python 3.12 on your computer. You can download it from https://www.python.org/downloads/.

Set up the appropriate environment variable(s) for your operating system.

If Python 2.7 is also installed, make sure that Python312 and Python312\Scripts have higher priority in the
PATH than CPython27.

### Linux Configuration
Most distributions of Linux should already have python2 and python3 installed. To verify that python by
default points to python3 run:
```bash
$ python --version
```
If python3 is not set as default, run the following commands. The number at the end of each command
denotes a priority:
```bash
$ update-alternatives --install /usr/bin/python python /usr/bin/python2.7 1
$ update-alternatives --install /usr/bin/python python /usr/bin/python3.12 2
```

### macOS Configuration
By default, `python` points to `/usr/bin/python`, which is python2. To make `python` and `pip` resolve to
python3 versions, execute the following from command line:
```bash
$ echo 'alias python=python3' >> ~/.bash_profile
$ echo 'alias pip=pip3' >> ~/.bash_profile
$ source ~/.bash_profile
$ python --version
Python 3.12.3
$ pip --version
pip 24.0 from
/Library/Frameworks/Python.framework/Versions/3.12/lib/python3.12/site-packages/pip (python 3.12)
```
Note: If you use a shell other than bash, update its profile file accordingly. For example `~/.zshrc` if you use zsh instead of `~/.bash_profile`.

### Installing CySecureTools Package
Make sure that you have the latest version of pip installed, use
the following command.
```bash
$ python -m pip install --upgrade pip
```
Run the following command in your terminal window.
```bash
$ python -m pip install cysecuretools
```

### Updating CySecureTools Package
To update the already installed package:
```bash
$ pip install --upgrade --force-reinstall cysecuretools
```

Note 1: During installation, you may see errors saying that cysecuretools requires package version X, but you have package version Y which is incompatible. In most cases, these can be safely ignored.

Note 2: You can use the following command to show the path to the installed package
`python -m pip show cysecuretools`.


# Supported devices
Use `device-list` command for output of the supported devices list.
```bash
$ cysecuretools device-list
```


# Interface and Usage
## PSoC 64 CLI
See [README_PSOC64.md](https://github.com/Infineon/cysecuretools/blob/master/docs/README_PSOC64.md)
## CYW20829/CYW89829 CLI
See [README_CYW20829.md](https://github.com/Infineon/cysecuretools/blob/master/docs/README_CYW20829.md)
## XMC7100/7200 CLI
See [README_XMC7XXX.md](https://github.com/Infineon/cysecuretools/blob/master/docs/README_XMC7XXX.md)


# Logging
Every time the tool is invoked, a new log file is created in the _logs_ directory of the project. By default, the console output has INFO logging severity. The log file has the DEBUG logging severity.


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
