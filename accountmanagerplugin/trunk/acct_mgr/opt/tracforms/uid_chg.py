# -*- coding: utf-8 -*-
#
# Copyright (C) 2013 Steffen Hoffmann <hoff.st@web.de>
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
#
# Author: Steffen Hoffmann <hoff.st@web.de>

from tracforms.tracdb import DBComponent

from acct_mgr.api import _
from acct_mgr.model import PrimitiveUserIdChanger


class TracFormsUserIdChanger(PrimitiveUserIdChanger):
    """Change user IDs for TracForms tables, schema version > 12."""

    enabled = False

    def __init__(self):
        try:
            schema_ver = int(
                DBComponent(self.env).get_installed_version(None))
            if schema_ver > 12:
                # Support only current db schema versions.
                self.enabled = True
        except ValueError:
            # Some older plugin version found.
            pass

    # IUserIdChanger method
    def replace(self, old_uid, new_uid):
        if not self.enabled:
            plugin = 'TracForms'
            result = _("Unsupported db schema version, please update "
                       "%(plugin)s to a recent version.", plugin=plugin)
            return dict(error={('forms', 'author', None): result})
        results = dict()

        self.table = 'forms'
        result = super(TracFormsUserIdChanger, self).replace(old_uid, new_uid)

        if 'error' in result:
            return result
        results.update(result)

        self.table = 'forms_fields'
        result = super(TracFormsUserIdChanger, self).replace(old_uid, new_uid)

        if 'error' in result:
            return result
        results.update(result)

        self.table = 'forms_history'
        result = super(TracFormsUserIdChanger, self).replace(old_uid, new_uid)

        if 'error' in result:
            return result
        results.update(result)

        return results
