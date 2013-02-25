#!/usr/bin/env python

from distutils.core import setup
from setuptools import find_packages
from flypwd import __version__
<<<<<<< HEAD
import flypwd.__doc__ as doc
=======
from flypwd import __doc__ as doc 
>>>>>>> f53a9bfdb7e5329dcc5f3b033ca3bca0be269a6f

setup(
    name = 'flypwd',
    version = __version__,
    author = 'Giuseppe Acito',
    author_email = 'giuseppe.acito@bancaditalia.it',
    packages = find_packages(exclude=['test']),  
    url = 'http://pypi.python.org/pypi/flypwd/',
    license = 'LICENSE.txt',
    description = doc,
    long_description = open('README.md').read(),
    install_requires = [
        "pycrypto",
        "pam"
    ],
    entry_points = {
        'console_scripts' : [
            'flypwd = flypwd:main'
            ]
        }
    )
