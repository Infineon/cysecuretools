from .pre_build_keys_exist_validator import PreBuildKeysExistValidator
from .encryption_key_validator import EncryptionAndProgramOemKey1Validator
from .hci_mode_validator import HciModeValidator
from .revoke_oem_encryption_validator import RevocationAndEncryptionValidator
from .access_restrictions_validator import AccessRestrictionsValidator

validators = {
    'pre_build': [PreBuildKeysExistValidator,
                  HciModeValidator,
                  EncryptionAndProgramOemKey1Validator,
                  RevocationAndEncryptionValidator,
                  AccessRestrictionsValidator
                  ]
}


def validate(policy_parser, skip_list):
    """ Validates dependencies and returns list of messages """
    is_valid = True
    messages = list()
    for k, v in validators.items():
        if skip_list is not None and k in skip_list:
            continue
        for item in v:
            validator = item(policy_parser)
            validator.validate()
            if not validator.is_valid:
                is_valid = False
            if validator.messages:
                messages.extend(validator.messages)
    return is_valid, messages
