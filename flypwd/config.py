# -*- coding:utf-8 -*-
import os
import errno

import os.path
import logging

try:
    from configparser import ConfigParser
except ImportError:
    from ConfigParser import ConfigParser

log = logging.getLogger(__name__)


def mkdir_p(path):
    """Helper function mimic the mkdir -p option"""
    try:
        os.makedirs(path)
    except OSError as exc:  # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise


def build_config(config=ConfigParser()):
    """
    build the config assets for Flypwd

    - checks if the $HOME/.flypwd exists
    - 
    """

    basedir = ".flypwd"
    workdir = os.path.join(os.path.expanduser("~"), basedir)
    pwdfile_pattern = "%(service)s"
    prvfile_pattern = "flypwd-%(service)s.key"
    pubfile_pattern = prvfile_pattern + ".pub"
    
    config.add_section('path')
    config.set("path", "workdir", workdir)

    config.add_section("service")
    config.set("service", "default", "default")

    config.add_section('keys')
    config.set('keys', 'dimension', str(2048))
    mkdir_p(workdir)
    return config


config = build_config()
