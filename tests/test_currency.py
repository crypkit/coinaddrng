import unittest

from coinaddrvalid.interfaces import INamedInstanceContainer, ICurrency
from coinaddrvalid.currency import Currencies, Currency


class TestCurrency(unittest.TestCase):
    def test_interfaces(self):
        self.assertTrue(INamedInstanceContainer.providedBy(Currencies))
        self.assertTrue(ICurrency.implementedBy(Currency))

        for currency in Currencies.instances.values():
            with self.subTest(currency=currency):
                self.assertTrue(ICurrency.providedBy(currency))


if __name__ == '__main__':
    unittest.main()
