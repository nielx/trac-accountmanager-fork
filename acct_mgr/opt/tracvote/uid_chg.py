# -*- coding: utf-8 -*-
#
# Copyright (C) 2013 Steffen Hoffmann <hoff.st@web.de>
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
#
# Author: Steffen Hoffmann <hoff.st@web.de>

from acct_mgr.model import PrimitiveUserIdChanger


class TracVoteUserIdChanger(PrimitiveUserIdChanger):
    """Change user IDs for TracVote table."""

    column = 'username'
    table = 'votes'
