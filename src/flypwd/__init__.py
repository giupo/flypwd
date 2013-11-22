#!/usr/bin/env python
# -*- coding:utf-8 -*-

#
# flypwd -- gestione sicura delle password utente
#

"""Library for flypwd password management"""

import getpass
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import os.path
import os
from subprocess import PIPE, Popen
import sys

# The following 'pam' package can be found here:
# http://atlee.ca/software/pam/index.html
#
# DON'T please DON'T "pip install pam", because
# you'll find yourself struggling with PAM (installed by the mentioned
# "pip" invocation  which is totally different from the one at the URL
# http://atlee.ca/software/pam/index.html
#
# My best wishes to who has created this mess.

import pam

import errno
from argparse import ArgumentParser

import logging
logging.basicConfig()
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

def mkdir_p(path):
    """Helper function mimic the mkdir -p option"""
    try:
        os.makedirs(path)
    except OSError as exc: # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else: raise

__PROG_DIR__ = ".flypwd"
HOME = os.path.expanduser("~")
WDIR = os.path.join(HOME, __PROG_DIR__)

# Assert you have the working dir ;)
mkdir_p(WDIR)

# Constants, constants everywhere...
RSAKEY = "pwd.pem"
PUBKEY = "pwd.pub"
RSAFILE = os.path.join(WDIR, RSAKEY)
PUBFILE = os.path.join(WDIR, PUBKEY)
PWDNAM="pwd"

PWD_FILE = os.path.join(WDIR, PWDNAM)

#That's quite important, it's the size of the RSA key
KEY_SIZE = 2048

__all__ = ['flypwd', 'clean', 'main']


class AuthenticationException(Exception):
    """ notifies the error upon authentication """
    pass

def get_the_damn_password(prompt = 'Password :'):
    # I love Python!
    if sys.stdin.isatty():
        return getpass.getpass(prompt)
    else:
        raise Exception("no interactive shell: impossible to retrieve password")

def check_key(rsafile):
    """
    checks the RSA key file
    raises ValueError if not valid
    """
    with open(rsafile, 'r') as f:
        return RSA.importKey(f.read(), passphrase="")


def exrsagen():
    """Generates the private key"""
    try:
        key = check_key(RSAFILE)
        log.debug(str(key))
        assert key.has_private()
    except:
        key = RSA.generate(KEY_SIZE)
        with open(RSAFILE, 'w') as f:
            f.write(key.exportKey('PEM'))
        with open(PUBFILE, 'w') as f:
            f.write(key.publickey().exportKey())

    return key

def expubgen():
    """generates the public key"""
    try:
        pub = check_key(PUBFILE)
        log.debug(str(pub))
        assert pub.has_private() is not True
    except:
        key = check_key(RSAFILE)
        with open(PUBFILE, 'w') as f:
            pub = key.publickey().exportKey()
            f.write(pub)

    return pub

def authenticateKerberos(pwd, krb5user):
    """Macheronic authentication via Kerberos"""
    try:
        from sys import platform
        cmd = ["kinit", krb5user] if krb5user else "kinit"
        if platform == 'darwin':
            cmd = ["kinit", "--password-file=STDIN", krb5user] if krb5user else ["kinit", "--password-file=STDIN"]

        procKinit = Popen(cmd, stdin = PIPE, stdout = PIPE)
        procKinit.stdin.write("%s\n" % pwd)
        rcKinit = procKinit.wait()
        log.debug("kinit rc: %d" % rcKinit)
        authenticated = (rcKinit == 0)
    except OSError, exp:
        log.debug("could not find kinit...")
        log.debug(exp)
        authenticated = False

    return authenticated

def authenticatePam(pwd):
    """Authentication through PAM"""
    return pam.authenticate(getpass.getuser(), pwd)

def authenticate(pwd, krb5user=None):
    """Authenticates the current user with the standard pwd-file password"""
    # auth = (authenticateKerberos(pwd) or authenticatePam(pwd))
    auth = (authenticatePam(pwd) or authenticateKerberos(pwd, krb5user))
    log.debug("is authenticated? %s" % str(auth))
    return auth


def emit_pwd(nome_file = PWD_FILE, auth=True, krb5user=None):
    """Emits the password for the given filename"""
    if os.path.isfile(RSAFILE) and os.path.isfile(nome_file):
        key = check_key(RSAFILE)
        with open(nome_file,'r') as pwdfile:
            pwd_encrypted = pwdfile.read()

        cipher = PKCS1_v1_5.new(key)
        pwd = cipher.decrypt(pwd_encrypted, None)
        if pwd is None:
            raise Exception("No password found")

        if auth:
            if not authenticate(pwd, krb5user=krb5user):
                os.remove(nome_file)
                raise AuthenticationException()

        if pwd.endswith('\n'):
            return pwd[:-1]

        return pwd

    else:
        log.debug("No RSA or PWD file")
        raise Exception("No files RSA or PWD file")

def flypwd(nome_file=None, prompt='Password: ', auth=True, krb5user=None):
    """ Main entry point    
    """
    try:
        pwd = emit_pwd(nome_file, auth=auth), 
    except Exception as e:
        log.warn(e)
        key = exrsagen()
        pub = expubgen()
        pwd = get_the_damn_password(prompt)

        cipher = PKCS1_v1_5.new(pub)

        pwdEncrypted = cipher.encrypt(pwd)
        log.debug("saving")
        with open(nome_file, 'w') as f:
            f.write(pwdEncrypted)

        pwd = emit_pwd(nome_file, auth=auth, krb5user=krb5user)

    return pwd

def clean(nome_file=None):
    """ Removes the files under the work dir """
    try:
        os.remove(RSAFILE)
    except Exception as e:
        log.warning(e)

    try:
        os.remove(PUBFILE)
    except Exception as e:
        log.warning(e)

    try:
        if nome_file is None:
            nome_file = PWD_FILE
        os.remove(nome_file)
    except Exception as e:
        log.warning(e)

def main():
    """console entry-point"""
    parser = ArgumentParser(description=__doc__)
    parser.add_argument('--clean', '-c',
                        action = 'store_true',
                        help="Removes the priv/pub key and pwd file")

    parser.add_argument('--printout', '-p',
                        action = 'store_true',
                        help="Shows the password: WARNING ;) ")

    parser.add_argument('--auth', '-a',
                        action = 'store_true',
                        help="Verify authentication on PAM or Kerberos")

    parser.add_argument('nomefile', nargs='?', default=PWD_FILE,
                        help="filename to store encrypted password")

    parser.add_argument('--krb5user', '-k', help="Kerberos User Principal")

    args = parser.parse_args()
    nomefile = os.path.join(WDIR,args.nomefile)
    log.debug(args)
    should_auth = args.auth or nomefile == PWD_FILE
    if(args.clean):
        log.debug("cleaning..")
        clean(nomefile)
        sys.exit(0)
    try:
        log.debug("Should we authenticate? %s" % str(should_auth))
        pwd = flypwd(nomefile, auth=should_auth, krb5user=args.krb5user)
        if isinstance(pwd, tuple):
            pwd = pwd[0]
        if(args.printout or not sys.stdout.isatty()):
            # o mi dai il printout o non sto su una shell interattiva
            # ed io ti scrivo la pwd su standard output...
            sys.stdout.write(str(pwd))
        else:
            log.info("Your password is stored")
    except AuthenticationException as ae:
        log.error("Authentication Error: your password was not stored")


if __name__ == '__main__':
    main()
