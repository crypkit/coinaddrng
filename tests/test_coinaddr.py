import unittest

import coinaddrng

from coinaddrng.interfaces import (
    INamedSubclassContainer, INamedInstanceContainer, ICurrency, IValidator,
    IValidationRequest, IValidationResult
    )
from coinaddrng.currency import Currencies, Currency
from coinaddrng.validation import (
    Validators, ValidatorBase, ValidationRequest, ValidationResult,
    Base58CheckValidator, EthereumValidator
    )


TEST_DATA = [
    ('bitcoin', 'btc', b'1BoatSLRHtKNngkdXEeobR76b53LETtpyT', 'main'),
    ('bitcoin', 'btc', b'n2nzi7xDTrMVK9stGpbK3BtrpBCJfH7LRQ', 'test'),
    ('bitcoin', 'btc', b'3QJmV3qfvL9SuYo34YihAf3sRCW3qSinyC', 'main'),
    ('bitcoin', 'btc', b'bc1qxneu85dnhx33asv8da45x55qyeu44ek9h3vngx', 'main'),
    ('bitcoin-cash', 'bch', b'1BoatSLRHtKNngkdXEeobR76b53LETtpyT', 'main'),
    ('bitcoin-cash', 'bch', b'n2nzi7xDTrMVK9stGpbK3BtrpBCJfH7LRQ', 'test'),
    ('bitcoin-cash', 'bch', b'3QJmV3qfvL9SuYo34YihAf3sRCW3qSinyC', 'main'),
    ('litecoin', 'ltc', b'LeF6vC9k1qfFDEj6UGjM5e4fwHtiKsakTd', 'main'),
    ('litecoin', 'ltc', b'mkwV3DZkgYwKaXkphBtcXAjsYQEqZ8aB3x', 'test'),
    ('neocoin', 'neo', b'AL9fzczwjV6ynoFAJVz4fBDu4NYLG6MBwm', 'both'),
    ('dogecoin', 'doge', b'DAnBU2rLkUgQb1ZLBJd6Bm5pZ45RN4TQC4', 'main'),
    ('dogecoin', 'doge', b'njscgXBB3HUUTXH7njim1Uw82PF9da4R8k', 'test'),
    ('dashcoin', 'dash', b'XsVkhTxLjzdXP1xZWtEFRj1mDhWcU6d8tE', 'main'),
    ('dashcoin', 'dash', b'yPv7h2i8v3dJjfSH4L3x91JSJszjdbsJJA', 'test'),
    ('ether-zero', 'etz', b'900ff070d37657cdf8016bca0d60cb493ebf7f83', 'both'),
    ('ethereum-classic', 'etc',
     b'0x900ff070d37657cdf8016bca0d60cb493ebf7f83', 'both'),
    ('ethereum', 'eth', b'900Ff070D37657cdF8016BcA0D60CB493EBf7f83', 'both'),
    ('ethereum-classic', 'etc',
     b'0x900Ff070D37657cdF8016BcA0D60CB493EBf7f83', 'both'),
    ('terramoney', 'luna', b'terra1v5hrqlv8dqgzvy0pwzqzg0gxy899rm4kdn0jp4', ''),
    ('polkadot', 'dot', b'12gX42C4Fj1wgtfgoP624zeHrcPBqzhb4yAENyvFdGX6EUnN', ''),
    ('kusama', 'ksm', b'GLdQ4D4wkeEJUX8DBT9HkpycFVYQZ3fmJyQ5ZgBRxZ4LD3S', ''),
]

WRONG_DATA = [
    ('ethereum', 'eth', b'0000001', 'both'),
]

WRONG_ADDRESSES = [
    '0', 'A', 'Z', '0x', '0123', 'ABCD', '0xaBaB', '987654321aBcD'
]


class TestCoinaddr(unittest.TestCase):
    def test_validation_by_name(self):
        for name, ticker, addr, net in TEST_DATA:
            with self.subTest(name=name, address=addr, net=net):
                res = coinaddrng.validate(name, addr)
                self.assertEqual(name, res.name)
                self.assertEqual(ticker, res.ticker)
                self.assertEqual(addr, res.address)
                self.assertEqual(True, res.valid)
                self.assertEqual(net, res.network)

        for name, ticker, addr, net in WRONG_DATA:
            with self.subTest(name=name, address=addr, net=net):
                res = coinaddrng.validate(name, addr)
                self.assertNotEqual(True, res.valid)

    def test_validation_by_ticker(self):
        for name, ticker, addr, net in TEST_DATA:
            with self.subTest(name=name, ticker=ticker, address=addr, net=net):
                res = coinaddrng.validate(ticker, addr)
                self.assertEqual(name, res.name)
                self.assertEqual(ticker, res.ticker)
                self.assertEqual(addr, res.address)
                self.assertEqual(True, res.valid)
                self.assertEqual(net, res.network)
                del res

    def test_validation_from_text(self):
        for name, ticker, addr, net in TEST_DATA:
            with self.subTest(name=name, address=addr, net=net):
                res = coinaddrng.validate(name, addr.decode())
                self.assertEqual(name, res.name)
                self.assertEqual(ticker, res.ticker)
                self.assertEqual(addr, res.address)
                self.assertEqual(True, res.valid)
                self.assertEqual(net, res.network)

    def test_validation_wrong_data(self):
        for currency in Currencies.instances.values():
            for addr in WRONG_ADDRESSES:
                with self.subTest(name=currency.name, address=addr):
                    res = coinaddrng.validate(currency.name, addr)
                    self.assertEqual(res.valid, False)


class TestExtendingCoinaddr(unittest.TestCase):
    def test_extending_currency(self):
        new_currency = Currency(
            'testcoin', ticker='ttc', validator='Base58Check',
            networks=dict(
                main=(0x00, 0x05), test=(0x6f, 0xc4)))

        self.assertEqual(new_currency, Currencies.get(new_currency.name))
        self.assertEqual(new_currency, Currencies.get(new_currency.ticker))

        test_data = [
            (new_currency.name, new_currency.ticker,
             b'1BoatSLRHtKNngkdXEeobR76b53LETtpyT', 'main')
            ]
        for name, ticker, addr, net in test_data:
            with self.subTest(name=name, ticker=ticker, address=addr, net=net):
                res = coinaddrng.validate(name, addr)
                self.assertEqual(name, res.name)
                self.assertEqual(ticker, res.ticker)
                self.assertEqual(addr, res.address)
                self.assertEqual(True, res.valid)
                self.assertEqual(net, res.network)

            with self.subTest(name=name, ticker=ticker, address=addr, net=net):
                res = coinaddrng.validate(ticker, addr)
                self.assertEqual(name, res.name)
                self.assertEqual(ticker, res.ticker)
                self.assertEqual(addr, res.address)
                self.assertEqual(True, res.valid)
                self.assertEqual(net, res.network)

    def test_extending_validator(self):
        class NewValidator(ValidatorBase):
            name = 'new'
            networks = 'testing'

            def validate(self):
                return True

        validator = Validators.get('new')
        self.assertEqual(NewValidator, validator)


if __name__ == '__main__':
    unittest.main()
