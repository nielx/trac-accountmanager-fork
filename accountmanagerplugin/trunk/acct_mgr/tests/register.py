# -*- coding: utf-8 -*-
#
# Copyright (C) 2012 Steffen Hoffmann <hoff.st@web.de>
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
#
# Author: Steffen Hoffmann <hoff.st@web.de>

import shutil
import tempfile
import unittest

from genshi.core  import Markup

from trac.perm  import PermissionCache, PermissionSystem
from trac.test  import EnvironmentStub, Mock

from acct_mgr.admin  import AccountManagerAdminPanels
from acct_mgr.api  import AccountManager, IAccountRegistrationInspector
from acct_mgr.register  import GenericRegistrationInspector, \
                               RegistrationError, RegistrationModule


class _BaseTestCase(unittest.TestCase):
    def setUp(self):
        self.env = EnvironmentStub(
                enable=['trac.*', 'acct_mgr.*'])
        self.env.path = tempfile.mkdtemp()
        self.perm = PermissionSystem(self.env)

        # Register AccountManager actions.
        self.ap = AccountManagerAdminPanels(self.env)
        self.perm.grant_permission('admin', 'ACCTMGR_USER_ADMIN')
        self.rmod = RegistrationModule(self.env)

    def tearDown(self):
        shutil.rmtree(self.env.path)


class DummyRegInspectorTestCase(_BaseTestCase):
    """Check GenericRegistrationInspector properties via child classes."""
    def setUp(self):
        _BaseTestCase.setUp(self)

        class DummyRegistrationInspector(GenericRegistrationInspector):
            def validate_registration(self, req):
                if req.args.get('username') == 'dummy':
                    raise RegistrationError('Dummy check error')
                return

        self.check = DummyRegistrationInspector(self.env)

    def test_bad_check(self):
        class BadRegistrationInspector(GenericRegistrationInspector):
            """Bad example of a check without check method implementation."""

        check = BadRegistrationInspector(self.env)
        args = dict(username='', name='', email='')
        req = Mock(authname='anonymous', args=args)
        field_res = check.render_registration_fields(req)
        self.assertEqual(len(field_res), 2)
        self.assertEqual((Markup(field_res[0]), field_res[1]),
                         (Markup(''), {}))
        self.assertRaises(NotImplementedError, check.validate_registration,
                          req)

    def test_dummy_check(self):
        args = dict(username='', name='', email='')
        req = Mock(authname='anonymous', args=args)
        self.assertEqual(self.check.validate_registration(req), None)

    def test_check_error(self):
        args = dict(username='dummy', name='', email='')
        req = Mock(authname='anonymous', args=args)
        self.assertRaises(RegistrationError, self.check.validate_registration,
                          req)
        try:
            self.check.validate_registration(req)
            # Shouldn't reach that point.
            self.assertTrue(False)
        except RegistrationError, e:
            # Check error properties in detail.
            self.assertEqual(e.message, 'Dummy check error')
            self.assertEqual(e.title, 'Registration Error')


def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(DummyRegInspectorTestCase, 'test'))
    return suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
