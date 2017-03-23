# -*- coding: utf-8 -*-
#
# Copyright (C) 2012,2013 Steffen Hoffmann <hoff.st@web.de>
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
#
# Author: Steffen Hoffmann <hoff.st@web.de>

import shutil
import tempfile
import unittest
from Cookie import SimpleCookie as Cookie

from trac.core import TracError
from trac.perm import PermissionCache, PermissionSystem
from trac.test import EnvironmentStub, Mock
from trac.web.session import Session

from acct_mgr.api import AccountManager
from acct_mgr.db import SessionStore


class _BaseTestCase(unittest.TestCase):
    def setUp(self):
        self.env = EnvironmentStub(default_data=True,
                                   enable=['trac.*', 'acct_mgr.api.*',
                                           'acct_mgr.db.SessionStore',
                                           'acct_mgr.pwhash.*',
                                           'acct_mgr.htfile.HtDigestStore']
                                   )
        self.env.path = tempfile.mkdtemp()
        self.perm = PermissionSystem(self.env)

    def tearDown(self):
        # Really close db connections.
        self.env.shutdown()
        shutil.rmtree(self.env.path)


class AccountManagerTestCase(_BaseTestCase):
    def setUp(self):
        _BaseTestCase.setUp(self)
        self.mgr = AccountManager(self.env)

        self.store = SessionStore(self.env)
        self.store.set_password('user', 'passwd')
        args = dict(username='user', name='', email='')
        incookie = Cookie()
        incookie['trac_session'] = '123456'
        self.req = Mock(authname='', args=args, authenticated=True,
                        base_path='/', callbacks=dict(),
                        chrome={'warnings': [], 'notices': []},
                        href=Mock(prefs=lambda x: None),
                        incookie=incookie, outcookie=Cookie(),
                        redirect=lambda x: None)
        self.req.path_info = '/'

        # Tests

    def test_set_password(self):
        # Can't work without at least one password store.
        self.assertRaises(TracError, self.mgr.set_password, 'user', 'passwd')
        self.env.config.set(
            'account-manager', 'password_store', 'SessionStore')
        self.mgr.set_password('user', 'passwd')
        # Refuse to overwrite existing credentials, if requested.
        self.assertRaises(TracError, self.mgr.set_password, 'user', 'passwd',
                          overwrite=False)

    def test_approval_admin_keep_perm(self):
        self.perm.grant_permission('admin', 'ACCTMGR_ADMIN')

        # Some elevated permission action.
        action = 'USER_VIEW'
        self.assertFalse(action in PermissionCache(self.env))

        req = self.req
        req.perm = PermissionCache(self.env, 'admin')
        req.session = Session(self.env, req)
        req.session.save()
        self.mgr.pre_process_request(req, None)
        self.assertTrue(action in req.perm)

        # Mock an authenticated request with account approval pending.
        req.session['approval'] = 'pending'
        req.session.save()
        # Don't touch admin user requests.
        self.mgr.pre_process_request(req, None)
        self.assertTrue(action in req.perm)

    def test_approval_user_strip_perm(self):
        # Some elevated permission action.
        action = 'USER_VIEW'
        self.assertFalse(action in PermissionCache(self.env))
        self.perm.grant_permission('user', action)

        req = self.req
        req.perm = PermissionCache(self.env, 'user')
        req.session = Session(self.env, req)
        req.session.save()
        self.mgr.pre_process_request(req, None)
        self.assertTrue(action in req.perm)

        # Mock an authenticated request with account approval pending.
        req.session['approval'] = 'pending'
        req.session.save()
        # Remove elevated permission, if account approval is pending.
        self.mgr.pre_process_request(req, None)
        self.assertFalse(action in req.perm)

    def test_maybe_update_hash(self):
        # Configure another, primary password store.
        self.env.config.set('account-manager', 'password_store',
                            'HtDigestStore, SessionStore')
        self.env.config.set('account-manager', 'htdigest_file', '.htdigest')

        self.env.db_transaction("""
                INSERT INTO session_attribute (sid,authenticated,name,value)
                VALUES (%s,%s,%s,%s)
                """, ('user', 1, 'password_refreshed', '1'))

        # Refresh not happening due to 'password_refreshed' attribute.
        self.mgr._maybe_update_hash('user', 'passwd')
        for _, in self.env.db_query("""
                SELECT value FROM session_attribute
                WHERE sid='user'
                 AND authenticated=1
                 AND name='password'
                """):
            break
        else:
            self.fail("Session attribute 'password' not found.")

        self.env.db_transaction("""
            DELETE FROM session_attribute
            WHERE sid='user'
             AND authenticated=1
             AND name='password_refreshed'
            """)
        # Refresh (and effectively migrate) user credentials.
        self.mgr._maybe_update_hash('user', 'passwd')
        for _, in self.env.db_query("""
                SELECT value
                FROM session_attribute
                WHERE sid='user'
                 AND authenticated=1
                 AND name='password'
                """):
            self.fail("Session attribute 'password' should not be found.")

        for value, in self.env.db_query("""
                SELECT value
                FROM session_attribute
                WHERE sid='user'
                 AND authenticated=1
                 AND name='password_refreshed'
                """):
            self.assertEqual('1', value)
            break
        else:
            self.fail("Session attribute 'password_refreshed' not found.")


class PermissionTestCase(_BaseTestCase):
    def setUp(self):
        _BaseTestCase.setUp(self)
        self.req = Mock()
        self.actions = ['ACCTMGR_ADMIN', 'ACCTMGR_CONFIG_ADMIN',
                        'ACCTMGR_USER_ADMIN', 'EMAIL_VIEW', 'USER_VIEW']

        # Tests

    def test_available_actions(self):
        for action in self.actions:
            self.failIf(action not in self.perm.get_actions())

    def test_available_actions_no_perms(self):
        for action in self.actions:
            self.assertFalse(self.perm.check_permission(action, 'anonymous'))

    def test_available_actions_config_admin(self):
        user = 'config_admin'
        self.perm.grant_permission(user, 'ACCTMGR_CONFIG_ADMIN')
        actions = [self.actions[0]] + self.actions[2:]
        for action in actions:
            self.assertFalse(self.perm.check_permission(action, user))

    def test_available_actions_user_admin(self):
        user = 'user_admin'
        self.perm.grant_permission(user, 'ACCTMGR_USER_ADMIN')
        for action in self.actions[2:]:
            self.assertTrue(self.perm.check_permission(action, user))
        for action in self.actions[:2] + ['TRAC_ADMIN']:
            self.assertFalse(self.perm.check_permission(action, user))

    def test_available_actions_full_perms(self):
        perm_map = dict(acctmgr_admin='ACCTMGR_ADMIN',
                        trac_admin='TRAC_ADMIN')
        for user in perm_map:
            self.perm.grant_permission(user, perm_map[user])
            for action in self.actions:
                self.assertTrue(self.perm.check_permission(action, user))
            if user != 'trac_admin':
                self.assertFalse(self.perm.check_permission('TRAC_ADMIN',
                                                            user))


def test_suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(AccountManagerTestCase))
    suite.addTest(unittest.makeSuite(PermissionTestCase))
    return suite


if __name__ == '__main__':
    unittest.main(defaultTest='test_suite')
