#
# flypwd -- gestione sicura delle password utente
# 
#
# Questa versione NON funziona con i file trattati con flypwd/bash


import getpass
from Crypto.PublicKey import RSA
import os.path
import os
from subprocess import PIPE, Popen
import sys
import pam
import errno

import logging
logging.basicConfig()
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc: # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else: raise

HOME = os.path.expanduser("~")
WDIR = os.path.join(HOME, ".ssh")

mkdir_p(WDIR)

RSAKEY = "pwd.pem"
PUBKEY = "pwd.pub"
RSAFILE = os.path.join(WDIR, RSAKEY)
PUBFILE = os.path.join(WDIR, PUBKEY)

PWDNAM="pwd"
PWD_FILE = os.path.join(WDIR, PWDNAM)
KEY_SIZE = 2048

__all__ = ['flypwd']
__version__ = '0.0.1'


def get_the_damn_password():
    if sys.stdout.isatty():
        return getpass.getpass()
    else:
        # gestire lo stato senza shell interattiva (Exception? UI?)
        pass

def check_key(rsafile):
    """
    checks the RSA key file
    raises ValueError if not valid
    """
    with open(rsafile, 'r') as f:
        return RSA.importKey(f.read(), passphrase="")


def exrsagen():
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

def authenticateKerberos(pwd):
    try:
        procKinit = Popen("kinit", stdin = PIPE, stdout = PIPE)
        procKinit.stdin.write("%s\n" % pwd)
        rcKinit = procKinit.wait()
        log.debug("kinit rc: %d" % rcKinit)
        authenticated = (rcKinit == 0)        
    except OSError:
        log.debug("could not find kinit...")
        authenticated = False

    return authenticated

def authenticatePam(pwd):
    return pam.authenticate(getpass.getuser(), pwd)

def authenticate(pwd):
    auth = (authenticateKerberos(pwd) or authenticatePam(pwd))    
    log.debug("is authenticated? %s" % str(auth))
    return auth
        

def emit_pwd():
    if os.path.isfile(RSAFILE) and os.path.isfile(PWD_FILE):
        key = check_key(RSAFILE)
        with open(PWD_FILE,'r') as pwdfile:
            pwd_encrypted = pwdfile.read()

        pwd = key.decrypt(pwd_encrypted)
        # print pwd
        if not authenticate(pwd):
            os.remove(PWD_FILE)
            raise Exception("Authentication Not Valid")

        return pwd

    else:
        log.debug("No RSA and PWD file")
        raise Exception("No files RSA and PWD file")

def flypwd():
    try:
        pwd = emit_pwd()
    except:
        key = exrsagen()
        pub = expubgen()    
        pwd = get_the_damn_password()
    
        pwdEncrypted = pub.encrypt(pwd, None)[0]
        with open(PWD_FILE, 'w') as f:
            f.write(pwdEncrypted)
            
        pwd = emit_pwd()
                    
    return pwd
        
    
    
