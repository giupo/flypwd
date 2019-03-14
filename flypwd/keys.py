# -*- coding:utf-8 -*-

import logging
import warnings

from flypwd.config import config

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_v1_5

log = logging.getLogger(__name__)

def check_key(keyfile):
    """
    checks the RSA key file
    raises ValueError if not valid
    """
    with open(keyfile, 'r') as f:
        return RSA.importKey(f.read(), passphrase="")


def gen_key():
    return RSA.generate(config.getint('keys', 'dimension'))
    

def encrypt_with_pub(pwd, pub):
    cipher = PKCS1_v1_5.new(pub)
    return cipher.encrypt(pwd.encode('utf-8'))
