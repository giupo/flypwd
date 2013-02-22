#
# flypwd -- gestione sicura delle password utente
# 
#
# Questa versione NON funziona con i file trattati con flypwd/bash


import getpass
from Crypto.PublicKey import RSA
import os.path
import os
import subprocess
from subprocess import PIPE, Popen
import sys

import errno

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
        assert pub.has_private() is not True
    except:
        key = check_key(RSAFILE)        
        with open(PUBFILE, 'w') as f:
            pub = key.publickey().exportKey()
            f.write(pub)

    return pub

def emit_pwd():
    if os.path.isfile(RSAFILE) and os.path.isfile(PWD_FILE):
        key = check_key(RSAFILE)
        with open(PWD_FILE,'r') as pwdfile:
            pwd_encrypted = pwdfile.read()

        pwd = key.decrypt(pwd_encrypted)
        # print pwd
        procKinit = Popen("kinit", stdin = PIPE, stdout = PIPE)
        procKinit.stdin.write("%s\n" % pwd)
        rcKinit = procKinit.wait()
        if(rcKinit == 0):
            return pwd
        else:
            os.remove(PWD_FILE)
            raise Exception("No pwd file")
    else:
        raise Exception("no files")

def flypwd():
    try:
        pwd = emit_pwd()
    except:
        key = exrsagen()
        expubgen()    
        pwd = get_the_damn_password()
        pwdEncrypted = key.publickey().encrypt(pwd, None)[0]
        with open(PWD_FILE, 'w') as f:
            f.write(pwdEncrypted)
                    
    return pwd
        
    
    
