# -*- coding: utf8 -*-
#
# Copyright (C) 2005 Matthew Good <trac@matt-good.net>
# Copyright (C) 2010-2012 Steffen Hoffmann <hoff.st@web.de>
#
# "THE BEER-WARE LICENSE" (Revision 42):
# <trac@matt-good.net> wrote this file.  As long as you retain this notice you
# can do whatever you want with this stuff. If we meet some day, and you think
# this stuff is worth it, you can buy me a beer in return.   Matthew Good
#
# Author: Matthew Good <trac@matt-good.net>

import os

from genshi.builder import tag

from trac.config import Option
from trac.util.datefmt import format_datetime, pretty_timedelta
from trac.web.chrome import Chrome

from acct_mgr.api import _


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

# Compatibility code for `pretty_dateinfo` from template data dict
# (available since Trac 0.13)
def get_pretty_dateinfo(env, req):
    """Return the function defined in trac.web.chrome.Chrome.populate_data .

    For Trac 0.11 and 0.12 it still provides a slightly simplified version.
    """
    # Function is not a class attribute, must be extracted from data dict.
    fn = Chrome(env).populate_data(req, {}).get('pretty_dateinfo')
    if not fn:
        def _pretty_dateinfo(date, format=None, dateonly=False):
            absolute = user_time(req, format_datetime, date)
            relative = pretty_timedelta(date)
            if format == 'absolute':
                label = absolute
                # TRANSLATOR: Sync with same msgid in Trac 0.13, please.
                title = _("%(relativetime)s ago", relativetime=relative)
            else:
                label = _("%(relativetime)s ago", relativetime=relative) \
                        if not dateonly else relative
                title = absolute
            return tag.span(label, title=title)
    return fn and fn or _pretty_dateinfo

