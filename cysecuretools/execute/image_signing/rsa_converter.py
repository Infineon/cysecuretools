"""
Copyright (c) 2020 Cypress Semiconductor Corporation

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
from cysecuretools.core import strops
from cysecuretools.core.key_handlers import RSAHandler


class RSAConverter:

    @staticmethod
    def convert_to_mbedtls(key_path, big_endian=True):
        """
        Extracts modulus and additional coefficients from RSA public key
        and converts to mbedtls format
        :param key_path: RSA key path (public or private)
        :param big_endian: Indicates whether to use big endian
        :return: RSA key in mbedtls format
        """
        public_numbers = RSAHandler.public_numbers(key_path)

        key_len = public_numbers.length
        modulus = hex(public_numbers.modulus).replace('0x', '')
        modulus_list = strops.split_by_n(modulus, 2)

        if not key_len:
            ValueError('Key length was not gotten by parsing')

        if len(modulus_list) != (key_len // 8):
            ValueError(f'The length of modulus ({key_len}) is not equal '
                       f'to the key length ({len(modulus_list) * 8})')

        coef = RSAConverter._calculate_additional_rsa_key_coefs(modulus)
        coef_list = RSAConverter._convert_hexstr_to_list(coef, not big_endian)
        coef_list = RSAConverter._align_byte_list(coef_list, 4, big_endian)
        lst = [('%02X' % x) for x in coef_list]
        result = '00000000' + modulus + ''.join(lst)

        return result

    @staticmethod
    def _align_byte_list(lst, alignment, is_be):
        list_len = len(lst)
        if list_len % alignment != 0:
            padding = [0] * (alignment - (list_len % alignment))
            if is_be:
                lst = padding + lst
            else:
                lst = lst + padding

        return lst

    @staticmethod
    def _calculate_additional_rsa_key_coefs(modulo):
        """
        Calculates Barrett coefficient for modulo value of RSA key:
           Equation is: barretCoef = floor((2 << (2 * k)) / n);
           Main article: https://en.wikipedia.org/wiki/Barrett_reduction
        :param modulo: Part of RSA key
        :return: Barrett coefficient
        """
        if isinstance(modulo, str):
            modulo = int(modulo, 16)
        if modulo <= 0:
            raise ValueError('Modulus must be positive')
        if modulo & (modulo - 1) == 0:
            raise ValueError('Modulus must not be a power of 2')

        modulo_len = modulo.bit_length()
        barret_coef2 = (1 << (modulo_len * 2)) % modulo

        return barret_coef2

    @staticmethod
    def _convert_hexstr_to_list(s, reverse=False):
        """
        Converts a string likes '0001aaff...' to list [0, 1, 170, 255].
        Also an input parameter can be an integer, in this case it will be
        converted to a hex string
        :param s: String to convert
        :param reverse: A returned list have to be reversed
        :return: A list of an integer values
        """
        if isinstance(s, (int,)):
            s = hex(s)
        s = s[2 if s.lower().startswith('0x') else 0: -1 if s.upper().endswith('L') else len(s)]
        if len(s) % 2 != 0:
            s = '0' + s
        lst = [int('0x%s' % s[i:i+2], 16) for i in range(0, len(s), 2)]
        if reverse:
            lst.reverse()

        return lst
