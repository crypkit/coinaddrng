import re
from setuptools import setup, find_packages
import sys


with open('coinaddrng/__init__.py', 'rt') as fd:
    version = re.search(r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]',
                        fd.read(), re.MULTILINE).group(1)

if not version:
    raise RuntimeError('Cannot find version information')

try:
    from m2r import parse_from_file
    long_description = parse_from_file('README.md')
except ImportError:
    with open('README.md') as fd:
        long_description = fd.read()


install_requires = [
    'attrs>=17.4.0',
    'base58check>=1.0.1',
    'zope.interface>=4.4.3',
    'crc16>=0.1.1',
    'blake256>=0.1.1',
    'cbor>=1.0.0',
    'bech32>=1.1.0',
    'groestlcoin-hash2>=1.1.1'
]

if sys.version_info < (3, 6):
    install_requires.append('pysha3>=1.0.2')


setup(
    name='coinaddrng',
    version=version,
    description='A crypto-currency address inspection/validation library.',
    #long_description=long_description,
    keywords=[
        'bitcoin',
        'litecoin',
        'altcoin',
        'ethereum',
        'address',
        'validation',
        'inspection',
    ],
    author='Joe Black',
    author_email='me@joeblack.nyc',
    maintainer='Joe Black',
    maintainer_email='me@joeblack.nyc',
    url='https://github.com/joeblackwaslike/coinaddr',
    download_url=(
        'https://github.com/joeblackwaslike/coinaddr/tarball/v%s' % version),
    license='MIT',
    install_requires=install_requires,
    zip_safe=False,
    packages=find_packages(),
    package_data={'': ['LICENSE']},
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Natural Language :: English',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Software Development',
        'Topic :: Security :: Cryptography',
        'Topic :: Text Processing',
        'Topic :: Utilities',
        "Topic :: Software Development :: Libraries :: Python Modules",
    ]
)
