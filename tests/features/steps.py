# -*- coding: utf-8 -*-
from lettuce import *

@step(u'I have the password (\w+)')
def have_the_password(step, password):
    world.password = password

@step(u'I use flypwd')
def use_flypwd(step):
    from flypwd import flypwd
    world.flypwd = flypwd(getattr(world, 'service', 'test'))
    
@step(u'I have the service (\w+)')
def have_the_service(step, service):
    world.service = service

@step(u'have a file named (\w+)')
def have_a_file_named(step, name):
    from os.path import expanduser, isfile, join
    home = expanduser("~")
    assert isfile(join(home, ".ssh", name))

@step(u'retrieve the password (\w+)')
def have_the_password_from_service(step, password):
    assert world.flypwd == password
