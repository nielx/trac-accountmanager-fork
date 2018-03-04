# -*- coding: utf-8 -*-
#
# Copyright (C) 2005 Matthew Good <trac@matt-good.net>
# Copyright (C) 2010-2014 Steffen Hoffmann <hoff.st@web.de>
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.

from trac.web.chrome import Chrome


def genshi_template_args(env, filename, data):
    """Compatibility function for IAdminPanelProviders."""
    if hasattr(Chrome(env), 'jenv'):
        return filename, data, None
    else:
        return filename, data
