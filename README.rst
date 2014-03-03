======
Flypwd
======

Command line utility to store (under *$HOME/.ssh*) passwords (one per file).

A single password (the one stored in the *$HOME/.ssh/pwd* file) can be checked 
against PAM or Kerberos. If you specify a different password file, authentication
won't be executed (Why this? Because I hate myself...)

Basically this is useful if you need to store a password for later retrieval and
you don't want to do it in clear text (beside this, having under your hand 
private and public keys won't be diffcult for the malicous to decrypt it...)

HowTo
=====

Install
-------

Download the package from `here`_ and then unzip it somewhere on your 
filesystem, then chdir into that dir

then the usual::

    [sudo] python setup.py install

Dependencies
~~~~~~~~~~~~
- `pycrypto`_ (to encrypt/decrypt)
- `pam`_ (to authenticate: **Watch It**! Don't `pip install pam` : pip will install another module PAM, which will give you just headache). That's why I've removed the *install_requires* entry: please download `pam`_ from the link, gunzip it, and then execute the usual "python setup.py install" for `pam`_
                                    
How does it works
-----------------

Run it::

    $ flypwd               
    WARNING:flypwd:No files RSA or PWD file # no RSA or pwd file, let's do it
    Password:                               # gimmie the password
    INFO:flypwd:Your password is stored     # ok
    
The first executin finds out you don't have an RSA key (flypwd creates one custom for itself, your identity is left alone)

Then it asks for the password (since you haven't specified a different password file, it will try to authenticate over PAM/Kerberos (it's a requirement of my employer, please use --auth option to force auth over different passwords files)

**NB**: if you look into $HOME/.ssh, you'll find a bunch of new files added (pwd.pem, pwd.pub, pwd = private, public, password file)

Now with a different file::
 
     $ flypwd another
     WARNING:flypwd:No files RSA or PWD file # another wasn't there
     Password:                               # gimmie the password
     INFO:flypwd:Your password is stored     # ok!

**NB** as before: now you'll have *$HOME/.ssh/another* with the encrypted password

From the code, it's just the same as command line::

     from flypwd import flypwd
     flypwd() # same as command line, returns a string containing the password
     flypwd("anotherfileName") # retrieves a password for another system
  
TODO
----

Add a callback to retrieve the password in different environments (UI, tty, etc...)

Credits
-------

- `Distribute`_
- `Buildout`_
- `modern-package-template`_

.. _here: http://github.com/giupo/flypwd
.. _pycrypto: https://pypi.python.org/pypi/pycrypto
.. _pam: https://pypi.python.org/pypi/pam
.. _Buildout: http://www.buildout.org/
.. _Distribute: http://pypi.python.org/pypi/distribute
.. _`modern-package-template`: http://pypi.python.org/pypi/modern-package-template
