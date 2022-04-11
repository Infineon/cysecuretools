# Changelog
All notable changes to this project will be documented in this file.

## 4.0.0
### Added
- Support of CYW20829 devices
- Support Python 3.10
- Signing images with HSM

### Changed
- Separated PSoC 64 and CYW20829 devices CLI
- Updated PSoC 64 CyBootloader for 512k and 2M:
  - added "reset_after_failure" feature
  - decreased boot time
- Protect PSA API from NSPE in PSoC 64 2M-S0 policy
- Prevent signing of already signed images
- Change MCUboot image header padding to erase value
- Use CyBootloader from the project directory if the project exists
- Updated dependencies packages to the latest versions
- Use pyocd 0.32.3

## 3.1.1
### Changed
- Fixed installation failure on macOS Big Sur and Apple M1 chip
- Fixed installation failure in Python 3.9

## 3.1.0
### Added
- SCRATCH with Status Partition swap mode
- Small image slots support in the external memory

## 3.0.0
### Added
- Image SWAP using Status Partition

### Changed
- CyBootloader 2.0
- Secure Flash Boot 4.0.2 support

## 2.1.0
### Added
- Support PSoC64 1M
- New command to read device die ID
- Optionally add boot record to the signed image
- New policy validators (address overlaps between images and bootloader, slots address alignment with the SMPU address limits, DAP closure, monotonic counter)
- Log the device response JWT during the provisioning process

### Changed
- Fixed issue with using group private key
- Use pyocd 0.27.3


## 2.0.0
### Added
- Support PSoC64 2M, PSoC64 512K
- Command line interface
- Encrypted programming
- Single-image and multi-image policy

### Changed
- Update provisioning according to new Secure Flash Boot functionality (update system calls, reprovisioning, encrypted image support)
- New CyBootloaders (CY8CKIT-064B0S2-4343W, CY8CKIT-064S0S2-4343W, CY8CPROTO-064B0S3)
- Use pyocd 0.27.0