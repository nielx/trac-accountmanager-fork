# -*- coding: utf-8 -*-
#
# Copyright (c) 2013-2015 Steffen Hoffmann
# 
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
#

import unittest


def suite():
    msg_fail = 'Issue with %s (%s): skipping acct_mgr.opt.tests.%s'

    suite = unittest.TestSuite()

    try:
        import acct_mgr.opt.tests.announcer
    except ImportError, e:
        print(msg_fail % ('UID changer for TracAnnouncer', e, 'announcer'))
    else:
        suite.addTest(acct_mgr.opt.tests.announcer.suite())

    try:
        import acct_mgr.opt.tests.tracforms
    except ImportError, e:
        print(msg_fail % ('UID changer for TracForms', e, 'tracforms'))
    else:
        suite.addTest(acct_mgr.opt.tests.tracforms.suite())

    try:
        import acct_mgr.opt.tests.tracscreenshots
    except ImportError, e:
        print(msg_fail % ('UID changer for TracScreenshots', e,
                          'tracscreenshots'))
    else:
        suite.addTest(acct_mgr.opt.tests.tracscreenshots.suite())

    try:
        import acct_mgr.opt.tests.tracvote
    except ImportError, e:
        print(msg_fail % ('UID changer for TracVote', e, 'tracvote'))
    else:
        suite.addTest(acct_mgr.opt.tests.tracvote.suite())

    try:
        import acct_mgr.opt.tests.radius
    except ImportError, e:
        print(msg_fail % ('RADIUS auth', e, 'radius'))
    else:
        suite.addTest(acct_mgr.opt.tests.radius.suite())
    return suite


# Start test suite directly from command line like so:
#   $> PYTHONPATH=$PWD python announcer/opt/tests/__init__.py
if __name__ == '__main__':
    unittest.main(defaultTest="suite")
