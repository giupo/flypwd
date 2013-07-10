#!/usr/bin/env python

from distutils.core import setup
from setuptools import find_packages
from flypwd import __version__
from flypwd import __doc__ as doc

setup(
    name = 'flypwd',
    version = __version__,
    author = 'Giuseppe Acito',
    author_email = 'giuseppe.acito@gmail.it',
    packages = find_packages(exclude=['test']),
    url = 'http://pypi.python.org/pypi/flypwd/',
    license = open('LICENSE.txt').read(),
    description = doc,
    long_description = open('README.md').read(),
    install_requires = [
        "pycrypto",
        "pam"
    ],

    dependency_links=['http://atlee.ca/software/pam/dist/0.1.3/pam-0.1.3.tar.gz#egg=pam'],
    
    entry_points = {
        'console_scripts' : [
            'flypwd = flypwd:main'
            ]
        }
    )
