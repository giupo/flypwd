#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = 'Giuseppe Acito'
__email__ = 'giuseppe.acito@gmail.com'
__version__ = '1.1.0'

#
# flypwd -- gestione sicura delle password utente
#

"""Library for flypwd password management"""
import os
import os.path
import sys
import logging

import coloredlogs
import getpass
import warnings
import stat

from argparse import ArgumentParser
from flypwd.config import config
from flypwd.keys import check_key, gen_key, encrypt_with_pub
from flypwd.auth import authenticate, AuthenticationException

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_v1_5


log = logging.getLogger("flypwd")


__all__ = ['flypwd', 'Flypwd', 'main']


def flypwd(service=config.get('service', 'default'),
           user=getpass.getuser()):
    """ Main entry point """
    f = Flypwd(service, user)
    try:
        return f.password
    except Exception as e:
        log.error(e)
        f.clean()
        f = Flypwd(service, user)
        return f.prompt()


def main():
    """console entry-point"""
    parser = ArgumentParser(description=__doc__)
    parser.add_argument('--clean', '-c',
                        action='store_true',
                        help="Removes the priv/pub key and pwd file")

    parser.add_argument('--printout', '-p',
                        action='store_true',
                        help="Shows the password: WARNING ;) ")

    parser.add_argument('--verify', '-v', action='store_true',
                        help="verify password with authentication system")
    
    parser.add_argument('service', nargs='?',
                        default=config.get('service', 'default'),
                        help="filename to store encrypted password")

    parser.add_argument('--debug', action='store_true')
    
    parser.add_argument('user', nargs='?', default=getpass.getuser())

    args = parser.parse_args()
    
    if args.debug:
        coloredlogs.install(level=logging.DEBUG)
    else:
        coloredlogs.install(level=logging.INFO)

    log.debug(args)
    service = args.service
    user = args.user if args.user else getpass.getuser()
    f = Flypwd(service, user, shouldVerify=args.verify)

    if(args.clean):
        log.debug("cleaning...")
        f.clean()
        sys.exit(0)

    try:
        pwd = f.password
        if(args.printout or not sys.stdout.isatty()):
            # o mi dai il printout o non sto su una shell interattiva
            # ed io ti scrivo la pwd su standard output...
            sys.stdout.write(str(pwd))
        else:
            log.info("Your password is stored")

    except AuthenticationException:
        log.error("Authentication Error: your password was not stored")
        sys.exit(-1)


class Flypwd(object):
    """Represent the password stored"""
    def __init__(self, service, user=getpass.getuser(), shouldVerify=False):
        self.service = service
        WDIR = config.get('path', 'workdir')
        self._service_pwd_file = os.path.join(WDIR, service)
        self._private_key_file = os.path.join(
            WDIR, service + ".key")
        
        self._public_key_file = os.path.join(
            WDIR, self._private_key_file + ".pub")
        
        self.user = user
        self.shouldVerify = shouldVerify

        key, pub = self.check_keys()

        log.debug(self.service)
        log.debug(self._service_pwd_file)
        log.debug(self._private_key_file)
        log.debug(self._public_key_file)
        log.debug(self.user)

    def clean(self):
        """ Removes the files under the work dir """
        try:
            if os.path.isfile(self._private_key_file):
                os.remove(self._private_key_file)
        except Exception as e:
            log.warning(e)

        try:
            if os.path.isfile(self._public_key_file):
                os.remove(self._public_key_file)
        except Exception as e:
            log.warning(e)

        try:
            if os.path.isfile(self._service_pwd_file):
                os.remove(self._service_pwd_file)
        except Exception as e:
            log.warning(e)

    def check_keys(self):
        try:
            key = check_key(self._private_key_file)
            pub = check_key(self._public_key_file)
            return key, pub
        except Exception as e:
            log.debug(e)
            log.warn("Keys are invalid, regenerating...")
            return self.genkeys()

    def genkeys(self):
        self.clean()
        key = gen_key()
        with open(self._private_key_file, 'wb') as f:
            f.write(key.exportKey('PEM'))
            
        with open(self._public_key_file, 'wb') as f:
            f.write(key.publickey().exportKey())

        perm = stat.S_IRUSR | stat.S_IWUSR

        os.chmod(self._private_key_file, perm)
        os.chmod(self._public_key_file, perm)

        return self.check_keys()

    def prompt(self, prompt='Password :'):
        # I love Python!
        if sys.stdin.isatty():
            return getpass.getpass(prompt)
        else:
            raise Exception("flypwd can't work without an interactive shell")

    def remove_pwd_file(self):
        if os.path.isfile(self._service_pwd_file):
            os.remove(self._service_pwd_file)
    
    @property
    def password(self):
        """Emits the password for the given filename"""
        key, pub = self.check_keys()
        if os.path.isfile(self._service_pwd_file):
            with open(self._service_pwd_file, 'rb') as pwdfile:
                pwd_encrypted = pwdfile.read()

            cipher = PKCS1_v1_5.new(key)

            try:
                pwd = cipher.decrypt(pwd_encrypted, None).decode('utf-8')
            except Exception as e:
                log.debug(e)
                self.remove_pwd_file()
                return self.password

            if not pwd:
                self.remove_pwd_file()
                return self.password

            if pwd.endswith('\n'):
                pwd = pwd[:-1]

            if self.shouldVerify and not authenticate(self.user, pwd):
                log.warning(
                    "User %s not authenticated with the supplied password",
                    self.user)
                self.remove_pwd_file()
                return self.password
                
            return pwd

        else:
            key, pub = self.check_keys()
            log.debug("No PWD file")
            
            pwd = self.prompt()
            pwdEncrypted = encrypt_with_pub(pwd, pub)
            log.debug("saving %s", self._service_pwd_file)
            with open(self._service_pwd_file, 'wb') as f:
                f.write(pwdEncrypted)

            perm = stat.S_IRUSR | stat.S_IWUSR
            try:
                os.chmod(self._service_pwd_file, perm)
                os.chmod(self._service_pwd_file, perm)
            except Exception as e:
                log.warn(e)

            return self.password


if __name__ == '__main__':
    main()
