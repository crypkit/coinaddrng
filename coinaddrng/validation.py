# pylint: disable=no-member

"""
:mod:`coinaddr.validation`
~~~~~~~~~~~~~~~~~~~~~~~~

Various validation machinery for validating cryptocurrency addresses.
"""

import re
from hashlib import sha256
import functools
import operator

from zope.interface import implementer, provider
import attr
import sha3
import base58check
import math
from binascii import unhexlify
import base64
import crc16

from .interfaces import (
    INamedSubclassContainer, IValidator, IValidationRequest,
    IValidationResult, ICurrency
    )
from .base import NamedSubclassContainerBase
from . import currency


@provider(INamedSubclassContainer)
class Validators(metaclass=NamedSubclassContainerBase):
    """Container for all validators."""


class ValidatorMeta(type):
    """Register validator classes on Validators.validators."""

    def __new__(mcs, cls, bases, attrs):
        new = type.__new__(mcs, cls, bases, attrs)
        if new.name:
            Validators[new.name] = new
        return new


@attr.s(cmp=False, slots=True)
class ValidatorBase(metaclass=ValidatorMeta):
    """Validator Interface."""

    name = None

    request = attr.ib(
        type='ValidationRequest',
        validator=[
            lambda i, a, v: type(v).__name__ == 'ValidationRequest',
            attr.validators.provides(IValidationRequest)
            ]
    )

    def validate(self):
        """Validate the address type, return True if valid, else False."""

    def validate_extended(self):
        """Validate the extended keys, return True if valid, else False."""

    @property
    def network(self):
        """Return the network derived from the network version bytes."""


@attr.s(frozen=True, slots=True, cmp=False)
@implementer(IValidator)
class Base58CheckValidator(ValidatorBase):
    """Validates Base58Check based cryptocurrency addresses."""

    name = 'Base58Check'
    # base58 alphabet representation
    dec_digit_to_base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    base58_digit_to_dec = { b58:dec for dec,b58 in enumerate(dec_digit_to_base58) }


    def validate(self):
        """extended keys have their own validation"""
        if len(self.request.address) == 111:
            return self.validate_extended()

        """Validate the address."""
        if 25 > len(self.request.address) > 35:
            return False

        abytes = base58check.b58decode(
            self.request.address, **self.request.extras)

        if self.network == "":
            return False

        checksum = sha256(sha256(abytes[:-4]).digest()).digest()[:4]
        if abytes[-4:] != checksum:
            return False

        return self.request.address == base58check.b58encode(
            abytes, **self.request.extras)

    def validate_extended(self):
        if len(self.request.address) != 111:
            return False

        if self.network == "":
            return False

        # strip leading "zeros" (the "1" digit with base58)
        base58_stripped = self.request.address.decode('utf-8').lstrip("1")
        # convert base58 to decimal
        int_rep = 0
        for base58_digit in base58_stripped:
            int_rep *= 58
            try:
                int_rep += self.base58_digit_to_dec[base58_digit]
            except KeyError:
                # not a valid base58 digit -> invalid address
                return False

        # encode it to base64
        hex_rep = "{:X}".format(int_rep)
        # if the length is odd, add leading zero (needed for b16decode)
        if len(hex_rep) % 2 == 1:
            hex_rep = "0" + hex_rep
        # decode it into a binary string, padded with zeros
        # 72 bytes (extended key size) + 4 bytes (prefix version bytes)
        all_bytes =  base64.b16decode(hex_rep).rjust(82, b"\0")

        # count leading zeros
        zero_count = next(zeros for zeros,byte in enumerate(all_bytes) if byte != 0)
        # compare it with the number of leading zeros lstripped at the beginning
        if len(self.request.address.decode('utf-8')) - len(base58_stripped) != zero_count:
            return False

        # checking if the checksum is valid
        if sha256(sha256(all_bytes[:-4]).digest()).digest()[:4] != all_bytes[-4:]:
            return False

        return True


    @property
    def network(self):
        """Return network derived from network version bytes."""
        try:
            abytes = base58check.b58decode(
                self.request.address, **self.request.extras)
        except ValueError:
            return ""

        for name, networks in self.request.currency.networks.items():
            for netw in networks:
                if netw != 0:
                    # count the prefix length in bytes
                    prefixlen = math.ceil(math.floor((math.log(netw) / math.log(2)) + 1) / 8)
                else:
                    prefixlen = 1
                address_prefix = [x for x in bytearray(abytes[:prefixlen])]
                if prefixtodec(address_prefix) == netw:
                    return name
        return ""

@attr.s(frozen=True, slots=True, cmp=False)
@implementer(IValidator)
class EosValidator(ValidatorBase):
    """Validates EOS cryptocurrency addresses."""

    name = 'EOS'

    def validate(self):
        if len(self.request.address) != 12:
            return False
        eos_pattern = re.compile('^[a-z]{1}[a-z1-5.]{10}[a-z1-5]{1}$')
        if eos_pattern.match(self.request.address.decode('utf-8')) == None:
            return False
        return True

    def validate_extended(self):
        return False

    @property
    def network(self):
        return ''


@attr.s(frozen=True, slots=True, cmp=False)
@implementer(IValidator)
class StellarValidator(ValidatorBase):
    """Validates Stellar cryptocurrency addresses."""

    name = 'Stellar'

    def validate(self):
        try:
            decoded_address = base64.b32decode(self.request.address)
        except:
            return False

        version_byte = decoded_address[0]
        payload = decoded_address[0:-2]
        expected_checksum = int.from_bytes(decoded_address[-2:], byteorder='little')

        if version_byte != 6 << 3:  # ed25519PublicKey
            return False

        checksum = crc16.crc16xmodem(payload)

        if checksum != expected_checksum:
            return False

        return True

    def validate_extended(self):
        return False

    @property
    def network(self):
        return ''


@attr.s(frozen=True, slots=True, cmp=False)
@implementer(IValidator)
class EthereumValidator(ValidatorBase):
    """Validates ethereum based crytocurrency addresses."""

    name = 'Ethereum'
    non_checksummed_patterns = (
        re.compile("^(0x)?[0-9a-f]{40}$"), re.compile("^(0x)?[0-9A-F]{40}$")
        )


    def validate(self):
        """Validate the address."""
        address = self.request.address.decode()
        if any(bool(pat.match(address))
               for pat in self.non_checksummed_patterns):
            return True
        addr = address[2:] if address.startswith('0x') else address
        addr_hash = sha3.keccak_256(addr.lower().encode('ascii')).hexdigest()
        for i, letter in enumerate(addr):
            if any([
                    int(addr_hash[i], 16) >= 8 and letter.upper() != letter,
                    int(addr_hash[i], 16) < 8 and letter.lower() != letter
            ]):
                return False
        return True

    def validate_extended(self):
        return False

    #def validate(self):
    #    """Validate the address."""
    #    address = self.request.address.decode()
    #    if any(bool(pat.match(address))
    #           for pat in self.non_checksummed_patterns):
    #        return True
    #    addr = address.lstrip('0x')
    #    addr_hash = sha3.keccak_256(addr.lower().encode('ascii')).hexdigest()
    #    for i in range(0, len(addr)):
    #        if any([
    #                int(addr_hash[i], 16) > 7 and addr[i].upper() != addr[i],
    #                int(addr_hash[i], 16) <= 7 and addr[i].lower() != addr[i]
    #        ]):
    #            return False
    #    return True

    @property
    def network(self):
        """Return network derived from network version bytes."""
        return 'both'


@attr.s(frozen=True, slots=True, cmp=False)
@implementer(IValidationRequest)
class ValidationRequest:
    """Contain the data and helpers as an immutable request object."""

    currency = attr.ib(
        type=currency.Currency,
        converter=currency.Currencies.get,
        validator=[
            attr.validators.instance_of(currency.Currency),
            attr.validators.provides(ICurrency)
            ])
    address = attr.ib(
        type=bytes,
        converter=lambda a: a if isinstance(a, bytes) else a.encode('ascii'),
        validator=attr.validators.instance_of(bytes))

    @property
    def extras(self):
        """Extra arguments for passing to decoder, etc."""
        extras = dict()
        if self.currency.charset:
            extras.setdefault('charset', self.currency.charset)
        return extras

    @property
    def networks(self):
        """Concatenated list of all version bytes for currency."""
        networks = tuple(self.currency.networks.values())
        return functools.reduce(operator.concat, networks)

    def execute(self):
        """Execute this request and return the result."""
        validator = Validators.get(self.currency.validator)(self)
        return ValidationResult(
            name=self.currency.name,
            ticker=self.currency.ticker,
            address=self.address,
            valid=validator.validate(),
            network=validator.network,
            is_extended=validator.validate_extended()
            )


@attr.s(frozen=True, slots=True, cmp=False)
@implementer(IValidationResult)
class ValidationResult:
    """Contains an immutable representation of the validation result."""

    name = attr.ib(
        type=str,
        validator=attr.validators.instance_of(str))
    ticker = attr.ib(
        type=str,
        validator=attr.validators.instance_of(str))
    address = attr.ib(
        type=bytes,
        validator=attr.validators.instance_of(bytes))
    valid = attr.ib(
        type=bool,
        validator=attr.validators.instance_of(bool))
    network = attr.ib(
        type=str,
        validator=attr.validators.instance_of(str))
    is_extended = attr.ib(
        type=bool,
        validator=attr.validators.instance_of(bool))

    def __bool__(self):
        return self.valid


def validate(currency, address):
    """Validate the given address according to currency type.

    This is the main entrypoint for using this library.

    :param currency str: The name or ticker code of the cryptocurrency.
    :param address (bytes, str): The crytocurrency address to validate.
    :return: a populated ValidationResult object
    :rtype: :inst:`ValidationResult`

    Usage::

      >>> import coinaddr
      >>> coinaddr.validate('btc', b'1BoatSLRHtKNngkdXEeobR76b53LETtpyT')
      ValidationResult(name='bitcoin', ticker='btc',
      ...              address=b'1BoatSLRHtKNngkdXEeobR76b53LETtpyT',
      ...              valid=True, network='main')

    """
    request = ValidationRequest(currency, address)
    return request.execute()


def prefixtodec(prefix):
    total = 0
    multiplier = 256
    for i in range(2,len(prefix)+1):
        total += prefix[-i]*multiplier
        multiplier *= 256
    return total+prefix[-1]
