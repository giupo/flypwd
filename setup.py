#!/usr/bin/env python

from distutils.core import setup
from setuptools import find_packages
from flypwd import __version__

setup(
    name = 'flypwd',
    version = __version__,
    author = 'Giuseppe Acito',
    author_email = 'giuseppe.acito@bancaditalia.it',
    packages = find_packages(exclude=['test']),  
    url = 'http://pypi.python.org/pypi/flypwd/',
    license = 'LICENSE.txt',
    description = 'flypwd password mgt for Python',
    long_description = open('README.md').read(),
    install_requires = [
        "pycrypto",
        "pam"
    ],
)
