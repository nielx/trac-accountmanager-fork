# -*- coding: utf-8 -*-
#
# Copyright (C) 2013 Steffen Hoffmann <hoff.st@web.de>
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
#
# Author: Steffen Hoffmann <hoff.st@web.de>

import shutil
import tempfile
import unittest

from trac.core import Component, implements
from trac.perm import PermissionCache, PermissionSystem
from trac.test import EnvironmentStub, Mock

from acct_mgr.admin import ExtensionOrder, ConfigurationAdminPanel, \
                           UserAdminPanel
from acct_mgr.api import AccountManager, IAccountRegistrationInspector
from acct_mgr.db import SessionStore
from acct_mgr.register import BasicCheck, RegistrationError


class BadCheck(Component):
    """Attributes/methods left out intentionally for testing."""
    implements(IAccountRegistrationInspector)


class DisabledCheck(BadCheck):
    """Won't even enable this one."""


class DummyCheck(Component):

    implements(IAccountRegistrationInspector)

    _domain = ''
    _description = \
        """A dummy check for unit-testing the interface."""

    def render_registration_fields(self, req, data):
        return None, None

    def validate_registration(self, req):
        if req.args.get('username') == 'dummy':
            raise RegistrationError('Dummy check error')
        return


class _BaseTestCase(unittest.TestCase):
    def setUp(self):
        self.env = EnvironmentStub(enable=[
            'trac.*', 'acct_mgr.api.*', 'acct_mgr.admin.*',
            'acct_mgr.db.*', 'acct_mgr.register.*',
            'acct_mgr.pwhash.HtDigestHashMethod',
            'acct_mgr.tests.admin.BadCheck',
            'acct_mgr.tests.admin.DummyCheck'
        ])
        self.env.path = tempfile.mkdtemp()
        self.perm = PermissionSystem(self.env)

        # Create a user reference in the permission system.
        self.perm.grant_permission('admin', 'ACCTMGR_ADMIN')
        # Prepare a generic request object for admin actions.
        self.req = Mock(authname='admin', method='GET',
                        args=dict(), abs_href=self.env.abs_href,
                        chrome=dict(notices=[], warnings=[]),
                        href=self.env.abs_href, locale='',
                        redirect=lambda x: None, session=dict(), tz=''
                        )
        self.req.perm = PermissionCache(self.env, 'admin')

        self.acctmgr = AccountManager(self.env)

    def tearDown(self):
        shutil.rmtree(self.env.path)


class ExtensionOrderTestCase(_BaseTestCase):
    def setUp(self):
        _BaseTestCase.setUp(self)

        self.checks = ExtensionOrder(components=self.acctmgr.checks,
                                     list=self.acctmgr.register_checks)
        self.check_list = ['BasicCheck', 'EmailCheck', 'BotTrapCheck',
                           'RegExpCheck', 'UsernamePermCheck']
        # Mock _setorder function call.
        for c in self.checks.get_all_components():
            c_name = c.__class__.__name__
            self.checks[c] = c_name in self.check_list and \
                             self.check_list.index(c_name) + 1 or 0
            continue

    def test_component_count(self):
        self.assertEqual(self.checks.component_count(), 7)

    def test_get_enabled_components(self):
        enabled_components_count = 0
        for c in self.checks.get_enabled_components():
            c_name = c.__class__.__name__
            self.assertTrue(c_name in self.check_list +
                            ['BadCheck', 'DummyCheck'])
            self.assertFalse(c_name in ['DisabledCheck'])
            enabled_components_count += 1
        self.assertEqual(enabled_components_count, 5)

    def test_get_enabled_component_names(self):
        self.assertEqual(self.checks.get_enabled_component_names(),
                         self.check_list)

    def test_get_all_components(self):
        all_components_count = 0
        for c in self.checks.get_all_components():
            c_name = c.__class__.__name__
            self.assertTrue(c_name in self.check_list +
                            ['BadCheck', 'DummyCheck'])
            self.assertFalse(c_name in ['DisabledCheck'])
            all_components_count += 1
        self.assertEqual(all_components_count, 7)


class AccountManagerAdminPanelTestCase(_BaseTestCase):
    def setUp(self):
        _BaseTestCase.setUp(self)
        self.cfg_panel_template = 'admin_accountsconfig.html'
        self.env.config.set('account-manager', 'password_store',
                            'SessionStore')
        self.admin = ConfigurationAdminPanel(self.env)
        self.bad_check = BadCheck(self.env)
        self.basic_check = BasicCheck(self.env)
        self.dummy_check = DummyCheck(self.env)
        self.store = SessionStore(self.env)

    def test_render_cfg_admin_panel(self):
        # Default configuration - all registration checks enabled.
        self.req.args['active'] = '3'
        response = self.admin.render_admin_panel(self.req, 'accounts',
                                                 'config', '')
        # Panel must use the appropriate template.
        self.assertEqual(response[0], self.cfg_panel_template)
        self._assert_no_msg(self.req)

        # Doc-string extraction must work.
        self.env.config.set('account-manager', 'register_check', 'DummyCheck')
        response = self.admin.render_admin_panel(self.req, 'accounts',
                                                 'config', '')
        check_list = response[1].get('check_list', [])
        self.assertEqual([check['doc'] for check in check_list
                          if check['classname'] == 'DummyCheck'],
                         ['A dummy check for unit-testing the interface.'])
        self.assertEqual(response[0], self.cfg_panel_template)
        self._assert_no_msg(self.req)

        # Even using badly defined checks should not stop panel rendering.
        self.env.config.set('account-manager', 'register_check',
                            'BadCheck, DisabledCheck')
        response = self.admin.render_admin_panel(self.req, 'accounts',
                                                 'config', '')
        self.assertEqual(response[1].get('disabled_check'),
                         frozenset(['DisabledCheck']))
        self.assertEqual(response[0], self.cfg_panel_template)
        self._assert_no_msg(self.req)

        # Another custom configuration: No check at all, if you insist.
        self.env.config.set('account-manager', 'register_check', '')
        self.assertFalse(self.acctmgr.register_checks)
        response = self.admin.render_admin_panel(self.req, 'accounts',
                                                 'config', '')
        self.assertEqual(response[0], self.cfg_panel_template)
        self._assert_no_msg(self.req)

    def _assert_no_msg(self, req):
        self.assertEqual(req.chrome['notices'], [])
        self.assertEqual(req.chrome['warnings'], [])


class UserAdminPanelTestCase(_BaseTestCase):
    def setUp(self):
        _BaseTestCase.setUp(self)
        self.user_panel_template = 'admin_users.html'
        self.admin = UserAdminPanel(self.env)

    def test_render_user_admin_panel(self):
        response = self.admin.render_admin_panel(self.req, 'accounts',
                                                 'users', '')
        # Panel must use the appropriate template.
        self.assertEqual(response[0], self.user_panel_template)
        self._assert_no_msg(self.req)

    def _assert_no_msg(self, req):
        self.assertEqual(req.chrome['notices'], [])
        self.assertEqual(req.chrome['warnings'], [])


def test_suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(ExtensionOrderTestCase))
    suite.addTest(unittest.makeSuite(AccountManagerAdminPanelTestCase))
    suite.addTest(unittest.makeSuite(UserAdminPanelTestCase))
    return suite


if __name__ == '__main__':
    unittest.main(defaultTest='test_suite')
