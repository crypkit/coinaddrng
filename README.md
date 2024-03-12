# CoinAddrNG
[![Github Repo](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/crypkit/coinaddrng) [![Pypi Version](https://img.shields.io/pypi/v/coinaddrng.svg)](https://pypi.python.org/pypi/coinaddrng) [![Pypi License](https://img.shields.io/pypi/l/coinaddrng.svg)](https://pypi.python.org/pypi/coinaddrng) [![Pypi Wheel](https://img.shields.io/pypi/wheel/coinaddrng.svg)](https://pypi.python.org/pypi/coinaddrng) [![Pypi Versions](https://img.shields.io/pypi/pyversions/coinaddrng.svg)](https://pypi.python.org/pypi/coinaddrng)


## Maintainer
Devmons s.r.o. - *Maintainer of this fork* - [coinaddrng](https://github.com/crypkit/coinaddrng)

See also the list of [contributors](https://github.com/crypkit/coinaddrng/contributors) who participated in this project.

## Original Maintainer
Joe Black | <me@joeblack.nyc> | [github](https://github.com/joeblackwaslike)


## Introduction
A cryptocurrency address inspection/validation library for python.

### Supported currencies
* binancecoin
* bitcoin
* bitcoin-sv
* bitcoin-cash
* boscoin
* cardano
* cosmos
* dashcoin
* decred
* dogecoin
* eos
* ethereum
* ethereum-classic
* ether-zero
* groestlcoin
* horizen
* kusama
* litecoin
* neocoin
* ontology
* polkadot
* ravencoin
* ripple
* stellar
* tezos
* tronix
* vechain
* zcash

## Installation
From `setup.py`:
```commandline
python setup.py install
```
Pip:
```shell
pip3 install coinaddrng
```

## Usage
```python
>>> import coinaddrng
>>> coinaddrng.validate('btc', b'1BoatSLRHtKNngkdXEeobR76b53LETtpyT')
ValidationResult(name='bitcoin', ticker='btc', address=b'1BoatSLRHtKNngkdXEeobR76b53LETtpyT', valid=True, network='main', is_extended=False, address_type='address')
```

ValidationResult returns coin name and ticker, address, if the address is valid or not. In case network prefix bytes are defined for the checked currency, then the network
is returned, too. If the coin supports that and the address is an extended key, it returns if it is valid or not.  For some coins the address type can be guessed based on its
format, which is returned as address_type. If there's none, 'address' is being returned as a default.

### Extending
#### Currencies
To add a new currency, simply instantiate a new `coinaddr.currency.Currency` class.  It will be automatically registered.
```python
from coinaddrng import Currency
Currency('decred', ticker='dcr', validator='DecredCheck',
        networks=dict(
            main=(0x073f,0x071a,0x02fda926), test=(0x0f21,0x0efc,0x043587d1)),
        address_types=dict(
            address=(0x073f,0x0f21), ticket=(0x071a,0x0efc),
            xpubkey=(0x02fda926,0x043587d1)))
```

To override a default currency, simply instantiate a new currency with that name.


#### Validators
To add a new validator, simply create a subclass of `coinaddr.validation.ValidatorBase` with your own implementation that implements the `coinaddr.interfaces.IValidator` interface.  It will be automatically registered.
```python
from zope.interface import implementer
from coinaddr.interfaces import IValidator
from coinaddr import ValidatorBase


@implementer(IValidator)
class NewValidator(ValidatorBase):
    name = 'New'

    @property
    def networks(self):
        return 'testing'

    def validate(self):
        return True
```

To override a default validator, simply create a new validator with that name.


## Changes
* [CHANGELOG](CHANGELOG.md)
