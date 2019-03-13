#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = 'Giuseppe Acito'
__email__ = 'giuseppe.acito@gmail.com'
__version__ = '1.0.0'

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
import errno

from argparse import ArgumentParser
from subprocess import PIPE, Popen

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_v1_5

# The following 'pam' package can be found here:
# http://atlee.ca/software/pam/index.html
#
# DON'T please DON'T "pip install pam", because
# you'll find yourself struggling with PAM (installed by the mentioned
# "pip" invocation  which is totally different from the one at the URL
# http://atlee.ca/software/pam/index.html
#
# My best wishes to who has created this mess.
#

try:
    from pam import authenticate as pamauthenticate
except Exception as e:
    def pamauthenticate(user, pwd):
        return False


def mkdir_p(path):
    """Helper function mimic the mkdir -p option"""
    try:
        os.makedirs(path)
    except OSError as exc:  # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise

        
log = logging.getLogger("flypwd")


__PROG_DIR__ = ".flypwd"
HOME = os.path.expanduser("~")
WDIR = os.path.join(HOME, __PROG_DIR__)
_DEFAULT_SERVICE_ = 'default'
# Assert you have the working dir ;)
mkdir_p(WDIR)

# Constants, constants everywhere...
KEY_SIZE = 2048

__all__ = ['flypwd', 'Flypwd', 'main']


class AuthenticationException(Exception):
    """ notifies the error upon authentication """
    pass


def flypwd(service=_DEFAULT_SERVICE_, user=getpass.getuser()):
    """ Main entry point """
    f = Flypwd(service, user)
    try:
        return f.password
    except:
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
    
    parser.add_argument('service', nargs='?', default=_DEFAULT_SERVICE_,
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


def authenticate(user, pwd):
    """Authenticates the current user"""
    # auth = (authenticateKerberos(pwd) or authenticatePam(pwd))
    kerb = authenticateKerberos
    pama = authenticatePam
    auth = True if pama(user, pwd) else kerb(user, pwd)
    log.debug("is authenticated? %s" % str(auth))
    return auth


def authenticateKerberos(user, pwd):
    """Macheronic authentication via Kerberos, returns `True`
    if success, `False` if failed"""
    try:
        from sys import platform
        cmd = ["kinit", user]
        if platform == 'darwin':
            cmd = ["kinit", "--password-file=STDIN", user]

        procKinit = Popen(cmd, stdin=PIPE, stdout=PIPE)
        procKinit.stdin.write("%s\n" % pwd)
        rcKinit = procKinit.wait()
        log.debug("kinit rc: %d" % rcKinit)
        return (rcKinit == 0)
    except OSError as exp:
        log.debug("could not find kinit...")
        log.debug(exp)
        return False


def authenticatePam(user, pwd):
    """Authentication through PAM"""
    return pamauthenticate(user, pwd)


def check_key(keyfile):
    """
    checks the RSA key file
    raises ValueError if not valid
    """
    with open(keyfile, 'r') as f:
        return RSA.importKey(f.read(), passphrase="")


class Flypwd(object):
    """Represent the password stored"""
    def __init__(self, service, user=getpass.getuser(), shouldVerify=False):
        self.service = service
        self._service_pwd_file = os.path.join(WDIR, service)
        self._private_key_file = os.path.join(WDIR, "flypwd-" +
                                              service + ".key")
        self._public_key_file = os.path.join(WDIR, "flypwd-" +
                                             service + ".key.pub")
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
            os.remove(self._private_key_file)
        except Exception as e:
            log.warning(e)

        try:
            os.remove(self._public_key_file)
        except Exception as e:
            log.warning(e)

        try:
            self.remove_pwd_file()
        except Exception as e:
            log.warning(e)

    def check_keys(self):
        try:
            key = check_key(self._private_key_file)
            pub = check_key(self._public_key_file)
            return key, pub
        except:
            log.warn("Keys are invalid, regenerating...")
            return self.genkeys()

    def genkeys(self):
        self.clean()
        key = RSA.generate(KEY_SIZE)
        with open(self._private_key_file, 'w') as f:
            f.write(key.exportKey('PEM'))
            
        with open(self._public_key_file, 'w') as f:
            f.write(key.publickey().exportKey())

        perm = stat.S_IRUSR | stat.S_IWUSR
        os.chmod(self._private_key_file, perm)
        os.chmod(self._public_key_file, perm)

        return self.privatekey, self.publickey

    @property
    def publickey(self):
        return check_key(self._public_key_file)

    @property
    def privatekey(self):
        return check_key(self._private_key_file)

    def prompt(self, prompt='Password :'):
        # I love Python!
        if sys.stdin.isatty():
            return getpass.getpass(prompt)
        else:
            raise Exception(
                "no interactive shell: impossible to retrieve password")

    def remove_pwd_file(self):
        if os.path.isfile(self._service_pwd_file):
            os.remove(self._service_pwd_file)
        else:
            log.warning("%s doesn't exists", self._service_pwd_file)

           
    @property
    def password(self):
        """Emits the password for the given filename"""
        key, pub = self.check_keys()
        if os.path.isfile(self._service_pwd_file):
            with open(self._service_pwd_file, 'r') as pwdfile:
                pwd_encrypted = pwdfile.read()

            cipher = PKCS1_v1_5.new(key)

            try:
                pwd = cipher.decrypt(pwd_encrypted, None)
            except Exception as e:
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
            cipher = PKCS1_v1_5.new(pub)
            pwdEncrypted = cipher.encrypt(pwd)
            log.debug("saving")
            with open(self._service_pwd_file, 'w') as f:
                f.write(pwdEncrypted)

            perm = stat.S_IRUSR | stat.S_IWUSR
            os.chmod(self._service_pwd_file, perm)
            os.chmod(self._service_pwd_file, perm)

            return self.password


if __name__ == '__main__':
    main()
