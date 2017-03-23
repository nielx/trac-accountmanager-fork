# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Steffen Hoffmann <hoff.st@web.de>
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
#
# Author: Steffen Hoffmann <hoff.st@web.de>

import os.path
import shutil
import tempfile
import unittest

from acct_mgr.opt.radius import RadiusAuthStore
from trac.test import EnvironmentStub


class _BaseTestCase(unittest.TestCase):
    def setUp(self):
        self.basedir = os.path.realpath(tempfile.mkdtemp())
        self.env = EnvironmentStub(default_data=True, enable=
            ['trac.*', 'acct_mgr.api.*',
             'acct_mgr.opt.radius.RadiusAuthStore'])
        self.env.path = os.path.join(self.basedir, 'trac-tempenv')
        os.mkdir(self.env.path)

    def tearDown(self):
        shutil.rmtree(self.basedir)


class RadiusAuthTestCase(_BaseTestCase):
    def setUp(self):
        _BaseTestCase.setUp(self)
        self.env.config.set('account-manager', 'password_store',
                            'RadiusAuthStore')
        self.env.config.set('account-manager', 'radius_secret',
                            'shared_secret')
        self.store = RadiusAuthStore(self.env)

    def test_obfuscate_shared_secret(self):
        self.assertEqual(set(['*']), set([c for c in
                                          repr(self.store.radius_secret)]))

    def test_get_users(self):
        self.assertEqual([], self.store.get_users())

    def test_has_user(self):
        self.assertFalse(self.store.has_user('user'))

    def test_check_password(self):
        self.assertEqual(None, self.store.check_password('user', 'password'))

    def test_update_password(self):
        self.assertFalse(hasattr(self.store, 'set_password'))


def test_suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(RadiusAuthTestCase))
    return suite


if __name__ == '__main__':
    unittest.main(defaultTest='test_suite')
