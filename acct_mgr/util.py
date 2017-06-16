# -*- coding: utf-8 -*-
#
# Copyright (C) 2005 Matthew Good <trac@matt-good.net>
# Copyright (C) 2010-2013 Steffen Hoffmann <hoff.st@web.de>
# Copyright (C) 2011 Edgewall Software
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
#
# Author: Matthew Good <trac@matt-good.net>

import os
import re
import sys
import urllib2

from acct_mgr.api import _, ngettext
from trac.config import Option
from trac.util.datefmt import format_datetime, to_datetime, utc


class EnvRelativePathOption(Option):
    def __get__(self, instance, owner):
        if instance is None:
            return self
        path = super(EnvRelativePathOption, self).__get__(instance, owner)
        if not path:
            return path
        return os.path.normpath(os.path.join(instance.env.path, path))


# Fix for issue http://bugs.python.org/issue8797 in Python 2.6
# following Bitten changeset 974.
if sys.version_info[:2] == (2, 6):
    import base64


    class HTTPBasicAuthHandler(urllib2.HTTPBasicAuthHandler):
        """Patched version of Python 2.6's HTTPBasicAuthHandler.

        The fix for [1]_ introduced an infinite recursion bug [2]_ into
        Python 2.6.x that is triggered by attempting to connect using
        Basic authentication with a bad username and/or password. This
        class fixes the problem using the simple solution outlined in [3]_.

        .. [1] http://bugs.python.org/issue3819
        .. [2] http://bugs.python.org/issue8797
        .. [3] http://bugs.python.org/issue8797#msg126657
        """

        def retry_http_basic_auth(self, host, req, realm):
            user, pw = self.passwd.find_user_password(realm, host)
            if pw is not None:
                raw = "%s:%s" % (user, pw)
                auth = 'Basic %s' % base64.b64encode(raw).strip()
                if req.get_header(self.auth_header, None) == auth:
                    return None
                req.add_unredirected_header(self.auth_header, auth)
                return self.parent.open(req, timeout=req.timeout)
            else:
                return None

else:
    HTTPBasicAuthHandler = urllib2.HTTPBasicAuthHandler


# taken from a comment of Horst Hansen
# at http://code.activestate.com/recipes/65441
def contains_any(str, set):
    for c in set:
        if c in str:
            return True
    return False


def if_enabled(func):
    def wrap(self, *args, **kwds):
        if not self.enabled:
            return None
        return func(self, *args, **kwds)

    return wrap


def pretty_precise_timedelta(time1, time2=None, resolution=None, diff=0):
    """Calculate time delta between two `datetime` objects and format
    for pretty-printing.

    If either `time1` or `time2` is None, the current time will be used
    instead.  Extending the signature of trac.util.datefmt.pretty_timedelta
    pre-calculated timedeltas may be specified by the alternative `diff`
    keyword argument that takes precedence if used.
    """
    if diff:
        age_s = diff
    else:
        time1 = to_datetime(time1)
        time2 = to_datetime(time2)
        if time1 > time2:
            time2, time1 = time1, time2
        diff = time2 - time1
        age_s = int(diff.days * 86400 + diff.seconds)
    age_d = age_s // 86400

    # DEVEL: Always reduce resolution as required by `resolution` argument.
    if resolution:
        if age_s < resolution:
            return _("less than %s"
                     % pretty_precise_timedelta(None, diff=resolution))
    # Get a compact string by stripping non-significant parts.
    if age_s == 0:
        return ''
    # Show seconds for small time values, even in timedeltas > 1 day.
    t = age_s - age_d * 86400
    if 0 < t < 120:
        t = ngettext('%(num)i second', '%(num)i seconds', t)
        if age_d == 0:
            return t
    elif age_d != age_s / 86400.0:
        t = format_datetime(age_s - age_d * 86400, format='%X', tzinfo=utc)
        if age_d == 0:
            return t
    # TRANSLATOR: Pretty datetime representation, time part provided by
    # string substitution.
    return (ngettext("%(num)i day %%s", "%(num)i days %%s", age_d)
            % (str(t) != '0' and t or '')).rstrip()


def _create_zwsp_re():
    ucs2_range = u'\\s\u200b-\u200f\u061c\u202a-\u202e\u2066-\u2069\u00ad' \
                 u'\u2060\ufeff\u2061-\u2064\u115f\u1160\u180b-\u180d' \
                 u'\ufe00-\ufe0f'
    try:
        pattern = re.compile(u'[%s\U000e0100-\U000e01ef]+' % ucs2_range,
                             re.UNICODE)
    except re.error:
        # Narrow build, `re` cannot use characters >= 0x10000
        pattern = re.compile(u'[%s]+|(?:\udb40[\udd00-\uddef])+' % ucs2_range,
                             re.UNICODE)
    return pattern


_zwsp_re = _create_zwsp_re()


def remove_zwsp(text):
    """Strips unicode zero-width and whitespace characters.
    """
    return _zwsp_re.sub('', text)
