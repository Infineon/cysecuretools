# Changelog
All notable changes to this project will be documented in this file.

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