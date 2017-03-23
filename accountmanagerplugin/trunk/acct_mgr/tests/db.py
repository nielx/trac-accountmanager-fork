# -*- coding: utf-8 -*-
#
# Copyright (C) 2007 Matthew Good <trac@matt-good.net>
# Copyright (C) 2011,2012 Steffen Hoffmann <hoff.st@web.de>
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
#
# Author: Matthew Good <trac@matt-good.net>

import unittest

from trac.test import EnvironmentStub

from acct_mgr.db import SessionStore


class _BaseTestCase(unittest.TestCase):
    def setUp(self):
        self.env = EnvironmentStub(enable=['trac.*', 'acct_mgr.*'])
        self.env.config.set('account-manager', 'password_store',
                            'SessionStore')
        self.store = SessionStore(self.env)

    def test_get_users(self):
        with self.env.db_transaction as db:
            db.executemany("""
                INSERT INTO session_attribute (sid,authenticated,name,value)
                VALUES (%s,1,'password',%s)
                """, [('a', 'a'), ('b', 'b'), ('c', 'c')])

        self.assertEqual(set(['a', 'b', 'c']), set(self.store.get_users()))

    def test_has_user(self):
        self.env.db_transaction("""
            INSERT INTO session_attribute (sid,authenticated,name,value)
            VALUES (%s,'1','password',%s)
            """, ('bar', 'bar'))

        self.assertFalse(self.store.has_user('foo'))
        self.assertTrue(self.store.has_user('bar'))

    def test_create_user(self):
        self.assertFalse(self.store.has_user('foo'))
        self.store.set_password('foo', 'password')
        self.assertTrue(self.store.has_user('foo'))

    def test_overwrite(self):
        self.assertTrue(self.store.set_password('foo', 'pass1'))
        self.assertFalse(self.store.set_password('foo', 'pass2',
                                                 overwrite=False))
        self.assertTrue(self.store.check_password('foo', 'pass1'))
        self.assertTrue(self.store.set_password('bar', 'pass',
                                                overwrite=False))

    def test_update_password(self):
        self.store.set_password('foo', 'pass1')
        self.assertFalse(self.store.check_password('foo', 'pass2'))
        self.store.set_password('foo', 'pass2')
        self.assertTrue(self.store.check_password('foo', 'pass2'))
        self.store.set_password('foo', 'pass3', 'pass2')
        self.assertTrue(self.store.check_password('foo', 'pass3'))

    def test_delete_user(self):
        self.store.set_password('foo', 'password')
        self.assertTrue(self.store.has_user('foo'))
        self.assertTrue(self.store.delete_user('foo'))
        self.assertFalse(self.store.has_user('foo'))

    def test_delete_nonexistant_user(self):
        self.assertFalse(self.store.has_user('foo'))
        self.assertFalse(self.store.delete_user('foo'))

    def test_unicode_username_and_password(self):
        username = u'\u4e60'
        password = u'\u4e61'
        self.store.set_password(username, password)
        self.assertTrue(self.store.check_password(username, password))


class HtDigestTestCase(_BaseTestCase):
    def setUp(self):
        super(HtDigestTestCase, self).setUp()
        self.env.config.set('account-manager', 'hash_method',
                            'HtDigestHashMethod')
        self.env.config.set('account-manager', 'db_htdigest_realm',
                            'TestRealm')


class HtPasswdTestCase(_BaseTestCase):
    def setUp(self):
        super(HtPasswdTestCase, self).setUp()
        self.env.config.set('account-manager', 'hash_method',
                            'HtPasswdHashMethod')


def test_suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(HtDigestTestCase))
    suite.addTest(unittest.makeSuite(HtPasswdTestCase))
    return suite


if __name__ == '__main__':
    unittest.main(defaultTest='test_suite')
