# -*- coding: utf-8 -*-
#
# Copyright (c) 2013, Steffen Hoffmann
# 
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
#

import unittest

from acct_mgr.opt.tests import announcer, tracforms, tracscreenshots, tracvote


def suite():
    suite = unittest.TestSuite()
    suite.addTest(announcer.suite())
    suite.addTest(tracforms.suite())
    suite.addTest(tracscreenshots.suite())
    suite.addTest(tracvote.suite())
    return suite


# Start test suite directly from command line like so:
#   $> PYTHONPATH=$PWD python announcer/opt/tests/__init__.py
if __name__ == '__main__':
    unittest.main(defaultTest="suite")
