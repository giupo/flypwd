#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys

from setuptools import setup
from setuptools.command.test import test as TestCommand

class PyTest(TestCommand):
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        import pytest
        errcode = pytest.main(self.test_args)
        sys.exit(errcode)


readme = open('README.rst').read()
history = open('HISTORY.rst').read().replace('.. :changelog:', '')

requirements = [
    "pycrypto",
]

test_requirements = [
    'pytest',
    'lettuce'
]

setup(
    name='flypwd',
    version='0.2.2',
    description='Library to store and retrieve passwords',
    long_description=readme + '\n\n' + history,
    author='Giuseppe Acito',
    author_email='giuseppe.acito@gmail.com',
    url='https://github.com/giupo/flypwd',
    packages=[
        'flypwd',
    ],
    package_dir={'flypwd':
                 'flypwd'},
    include_package_data=True,
    install_requires=requirements,
    license="BSD",
    zip_safe=False,
    keywords='flypwd',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        "Programming Language :: Python :: 2",
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
    ],
    cmdclass={'test': PyTest},
    test_suite='tests',
    tests_require=test_requirements,
    entry_points={
        'console_scripts':['flypwd=flypwd:main']
    }
)
