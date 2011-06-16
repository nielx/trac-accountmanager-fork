# -*- coding: utf8 -*-
#
# Copyright (C) 2005 Matthew Good <trac@matt-good.net>
#
# "THE BEER-WARE LICENSE" (Revision 42):
# <trac@matt-good.net> wrote this file.  As long as you retain this notice you
# can do whatever you want with this stuff. If we meet some day, and you think
# this stuff is worth it, you can buy me a beer in return.   Matthew Good
#
# Author: Matthew Good <trac@matt-good.net>

import os

from trac.config import Option

class EnvRelativePathOption(Option):
 
    def __get__(self, instance, owner):
        if instance is None:
            return self
        path = super(EnvRelativePathOption, self).__get__(instance, owner)
        if not path:
            return path
        return os.path.normpath(os.path.join(instance.env.path, path))

# taken from a comment of Horst Hansen
# at http://code.activestate.com/recipes/65441
def containsAny(str, set):
    for c in set:
        if c in str:
            return True
    return False

# Compatibility code for `ComponentManager.is_enabled`
# (available since Trac 0.12)
def is_enabled(env, cls):
    """Return whether the given component class is enabled.

    For Trac 0.11 the missing algorithm is included as fallback.
    """
    try:
        return env.is_enabled(cls)
    except AttributeError:
        if cls not in env.enabled:
            env.enabled[cls] = env.is_component_enabled(cls)
        return env.enabled[cls]

