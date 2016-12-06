# -*- coding: utf-8 -*-
#
# Copyright (C) 2005 Matthew Good <trac@matt-good.net>
# Copyright (C) 2015 Steffen Hoffmann <hoff.st@web.de>
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
#
# Author: Matthew Good <trac@matt-good.net>

import unittest
try:
    import twill, subprocess
    INCLUDE_FUNCTIONAL_TESTS = True
except ImportError:
    INCLUDE_FUNCTIONAL_TESTS = False


def test_suite():
    from acct_mgr.tests import admin, api, db, guard, htfile, model, register
    from acct_mgr.tests import util
    from acct_mgr.opt.tests import test_suite as opt_test_suite

    suite = unittest.TestSuite()
    suite.addTest(admin.test_suite())
    suite.addTest(api.test_suite())
    suite.addTest(db.test_suite())
    suite.addTest(guard.test_suite())
    suite.addTest(htfile.test_suite())
    suite.addTest(model.test_suite())
    suite.addTest(register.test_suite())
    suite.addTest(util.test_suite())
    suite.addTest(opt_test_suite())

    # if INCLUDE_FUNCTIONAL_TESTS:
    #     from acct_mgr.tests.functional import suite as functional_suite
    #     suite.addTest(functional_suite())
    return suite

if __name__ == '__main__':
    import sys
    if '--skip-functional-tests' in sys.argv:
        sys.argv.remove('--skip-functional-tests')
        INCLUDE_FUNCTIONAL_TESTS = False
    unittest.main(defaultTest='test_suite')
