"""
:mod:`coinaddr.currency`
~~~~~~~~~~~~~~~~~~~~~~~~

Containers for holding all the necessary data for validating cryptocurrencies.
"""

import attr
from zope.interface import implementer, provider

from .interfaces import ICurrency, INamedInstanceContainer
from .base import NamedInstanceContainerBase


@provider(INamedInstanceContainer)
class Currencies(metaclass=NamedInstanceContainerBase):
    """Container for all currencies."""

    @classmethod
    def get(cls, name, default=None):
        """Return currency object with matching name or ticker."""
        for inst in cls.instances.values():
            if name in (inst.name, inst.ticker):
                return inst
        else:
            return default


class CurrencyMeta(type):
    """Register currency classes on Currencies.currencies."""

    def __call__(cls, *args, **kwargs):
        inst = super(CurrencyMeta, cls).__call__(*args, **kwargs)
        Currencies[inst.name] = inst
        return inst


@implementer(ICurrency)
@attr.s(frozen=True, slots=True, cmp=False)
class Currency(metaclass=CurrencyMeta):
    """An immutable representation of a cryptocurrency specification."""

    name = attr.ib(
        type=str,
        validator=attr.validators.instance_of(str))
    ticker = attr.ib(
        type=str,
        validator=attr.validators.instance_of(str))
    validator = attr.ib(
        type='str',
        validator=attr.validators.instance_of(str))
    networks = attr.ib(
        type=dict,
        validator=attr.validators.optional(attr.validators.instance_of(dict)),
        default=attr.Factory(dict))
    charset = attr.ib(
        type=bytes,
        validator=attr.validators.optional(attr.validators.instance_of(bytes)),
        default=None)


Currency('bitcoin', ticker='btc', validator='Base58Check',
         networks=dict(
             main=(0x00, 0x05, 0x0488b21e, 0x049d7cb2, 0x04b24746, 0x0295b43f, 0x02aa7ed3), 
             test=(0x6f, 0xc4, 0x043587cf, 0x044a5262, 0x045f1cf6, 0x024289ef, 0x02575483)))
Currency('bitcoin-cash', ticker='bch', validator='Base58Check',
         networks=dict(
             main=(0x00, 0x05), test=(0x6f, 0xc4)))
Currency('litecoin', ticker='ltc', validator='Base58Check',
         networks=dict(
             main=(0x30, 0x05, 0x32, 0x019da462, 0x01b26ef6), 
             test=(0x6f, 0xc4, 0x0436f6e1)))
Currency('dogecoin', ticker='doge', validator='Base58Check',
         networks=dict(
             main=(0x1e, 0x16), test=(0x71, 0xc4)))
Currency('dashcoin', ticker='dash', validator='Base58Check',
         networks=dict(
             main=(0x4c, 0x10), test=(0x8c, 0x13)))
Currency('neocoin', ticker='neo', validator='Base58Check',
         networks=dict(both=(0x17,)))
Currency('ripple', ticker='xrp', validator='Base58Check',
         networks=dict(both=(0x00, 0x05)),
         charset=(b'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcd'
                  b'eCg65jkm8oFqi1tuvAxyz'))
Currency('ethereum', ticker='eth', validator='Ethereum')
Currency('ether-zero', ticker='etz', validator='Ethereum')
Currency('ethereum-classic', ticker='etc', validator='Ethereum')

Currency('zcash', ticker='zec', validator='Base58Check', 
         networks=dict(
             main=(0x1cb8, 0x1cbd), test=(0x1d25, 0x1cba)))
Currency('tezos', ticker='xtz', validator='Base58Check', 
         networks=dict(
             both=(0x06a19f, 0x06a1a1, 0x06a1a4, )))
Currency('horizen', ticker='zen', validator='Base58Check',
         networks=dict(
             both=(0x2089, 0x1cb8)))
Currency('eos', ticker='eos', validator='EOS')
Currency('stellar', ticker='xlm', validator='Stellar')
Currency('ravencoin', ticker='rvn', validator='Base58Check',
        networks=dict(
             main=(0x3c,0x0488B21E), test=(0x6f,0x043587CF)))
