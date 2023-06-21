"""
Copyright (c) 2022 Cypress Semiconductor Corporation

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
ram_app_codes = {
    0xF2A00001: {
        "status": "CYAPP_SUCCESS",
        "descr": "The provisioning application completed successfully"
    },
    0x45000002: {
        "status": "CYAPP_BAD_PARAM",
        "descr": "One or more invalid parameters"
    },
    0x45000003: {
        "status": "CYAPP_LOCKED",
        "descr": "Resource lock failure"
    },
    0x45000004: {
        "status": "CYAPP_STARTED",
        "descr": "Operation started but not necessarily completed yet"
    },
    0x45000005: {
        "status": "CYAPP_FINISHED",
        "descr": "Operation finished"
    },
    0x45000006: {
        "status": "CYAPP_CANCELED",
        "descr": "Operation canceled"
    },
    0x45000007: {
        "status": "CYAPP_TIMEOUT",
        "descr": "Operation timed out"
    },
    0x45000008: {
        "status": "CYAPP_FAILED",
        "descr": "RAM Application failed"
    },
    0xF2A00010: {
        "status": "CYAPP_APP_RUNNING",
        "descr": "The provisioning application is in-progress"
    },
    0x45000020: {
        "status": "CYAPP_OTP_INIT_FAILED",
        "descr": "Fail to initialize OTP"
    },
    0x45000021: {
        "status": "CYAPP_OTP_BOOTROW_WRITE_FAILED",
        "descr": "Fail to update LCS"
    },
    0x45000022: {
        "status": "CYAPP_OTP_BOOTROW_READ_FAILED",
        "descr": "Fail to read LCS"
    },
    0x45000023: {
        "status": "CYAPP_OTP_WRITE_FAILED",
        "descr": "Fail to program object into OTP"
    },
    0x45000024: {
        "status": "CYAPP_OTP_READ_FAILED",
        "descr": "Fail to read object from OTP"
    },
    0x45000030: {
        "status": "CYAPP_LCS_INVALID",
        "descr": "Current device LCS is illegal to perform provisioning or re-provisioning"
    },
    0x45000031: {
        "status": "CYAPP_CBOR_INVALID",
        "descr": "Object in CBOR has illegal value"
    },
    0x45000032: {
        "status": "CYAPP_RESPONSE_GEN_FAILED",
        "descr": "Object does not exists in CBOR package"
    },
    0x45000033: {
        "status": "CYAPP_DEVICEID_CERT_GEN_FAILED",
        "descr": "Object does not exists in CBOR package"
    },
    0x45000034: {
        "status": "CYAPP_DEVICE_ID_KEYPAIR_FAILED",
        "descr": "Fail to retrieve DeviceID keypair"
    },
    0x45000035: {
        "status": "CYAPP_ALIAS_CERT_GEN_FAILED",
        "descr": "Alias certificate generation failed"
    },
    0x45000036: {
        "status": "CYAPP_DEVICE_ID_GENERATION_FAILED",
        "descr": "Fail to generate device identity"
    },
    0x45000037: {
        "status": "CYAPP_CDI_COMPUTE_FAILED",
        "descr": "Fail to compute CDI hash"
    },
    0x45000038: {
        "status": "CYAPP_HL0_COMPUTE_FAILED",
        "descr": "Fail to compute HL0 hash"
    },
    0x45000039: {
        "status": "CYAPP_DEVICE_ID_PROGRAM_FAILED",
        "descr": "Fail to program device identity data, not recoverable error"
    },
    0x4500003A: {
        "status": "CYAPP_SIGN_VERIFY_FAILED",
        "descr": "Signature validation failed"
    },
    0x4500003B: {
        "status": "CYAPP_ASSET_VERIFY_FAILED",
        "descr": "RRAM asset validation failed"
    },
    0x4500003C: {
        "status": "CYAPP_NVM_WRITE_FAILED",
        "descr": "Fail to program object into NVM"
    },
    0x4500003D: {
        "status": "CYAPP_NVM_READ_FAILED",
        "descr": "Fail to read object from NVM"
    },
    0x4500003E: {
        "status": "CYAPP_HASH_CALCULATION_FAILED",
        "descr": "Fail to calculate hash"
    },
    0x4500003F: {
        "status": "CYAPP_PROVISIONING_LIMITS_FAILED",
        "descr": "Exceed provisioning limits"
    },
    0x45000040: {
        "status": "CYAPP_ALIAS_KEYPAIR_GEN_FAILED",
        "descr": "Fail to generate Alias keypair"
    },
    0x45000041: {
        "status": "CYAPP_HASH_VALIDATION_FAILED",
        "descr": "Fail to validate hash"
    },
    0x45000042: {
        "status": "CYAPP_SE_RT_SERVICES_FAILED",
        "descr": "Call of SE RT Services API failed"
    }
}


def get_status_by_code(code):
    """Get status by the code"""
    return ram_app_codes[code]['status'], ram_app_codes[code]['desc']


def get_code_by_name(name):
    """Get status code by the name"""
    return next(k for k, v in ram_app_codes.items() if v['status'] == name)
