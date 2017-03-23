# -*- coding: utf-8 -*-
#
# Copyright (C) 2013 Steffen Hoffmann <hoff.st@web.de>
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
#
# Author: Steffen Hoffmann <hoff.st@web.de>

from announcer.api import AnnouncementSystem

from acct_mgr.api import _
from acct_mgr.model import PrimitiveUserIdChanger


class TracAnnouncerUserIdChanger(PrimitiveUserIdChanger):
    """Change user IDs for TracAnnouncer tables, schema version > 2."""

    enabled = False

    def __init__(self):
        try:
            schema_ver = AnnouncementSystem(self.env).get_schema_version()
            if schema_ver > 2:
                # Support only current db schema versions.
                #   For older ones at least information stored in
                #   'session_attribute' is already handled by the
                #   respective user ID changer component for Trac core.
                self.enabled = True
        except AttributeError:
            # Some older plugin version found.
            pass

    # IUserIdChanger method
    def replace(self, old_uid, new_uid):
        if not self.enabled:
            plugin = 'TracAnnouncer'
            result = _("Unsupported db schema version, please update "
                       "%(plugin)s to a recent version.", plugin=plugin)
            return dict(error={('subscriptions', 'sid', None): result})
        results = {}

        self.column = 'sid'
        self.table = 'subscription'
        result = super(TracAnnouncerUserIdChanger, self).\
                 replace(old_uid, new_uid)

        if 'error' in result:
            return result
        results.update(result)

        self.table = 'subscription_attribute'
        result = super(TracAnnouncerUserIdChanger, self).\
                 replace(old_uid, new_uid)

        if 'error' in result:
            return result
        results.update(result)

        return results
