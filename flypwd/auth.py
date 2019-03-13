# -*- coding:utf-8 -*-

import logging
from subprocess import Popen

log = logging.getLogger(__name__)

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


class AuthenticationException(Exception):
    """ notifies the error upon authentication """
    pass
    

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
