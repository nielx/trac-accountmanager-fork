# -*- coding: utf-8 -*-
#
# Copyright (C) 2012 Steffen Hoffmann <hoff.st@web.de>
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
#
# Author: Steffen Hoffmann <hoff.st@web.de>

import new
import pkg_resources
import shutil
import tempfile
import time
import unittest
from Cookie import SimpleCookie as Cookie

from trac import __version__ as VERSION
from trac.test import EnvironmentStub, Mock
from trac.web.session import Session

from acct_mgr.model import (
    change_uid, del_user_attribute, delete_user, get_user_attribute,
    last_seen, prime_auth_session, set_user_attribute, user_known)


class ModelTestCase(unittest.TestCase):
    def setUp(self):
        self.env = EnvironmentStub(default_data=True, enable=['trac.*'])
        self.env.path = tempfile.mkdtemp()

    def tearDown(self):
        # Really close db connections.
        self.env.shutdown()
        shutil.rmtree(self.env.path)

    # Helpers

    def _create_session(self, user, authenticated=1, name='', email=''):
        args = dict(username=user, name=name, email=email)
        incookie = Cookie()
        incookie['trac_session'] = '123456'
        self.req = Mock(authname=bool(authenticated) and user or 'anonymous',
                        args=args, base_path='/',
                        chrome=dict(warnings=list()),
                        href=Mock(prefs=lambda x: None),
                        incookie=incookie, outcookie=Cookie(),
                        redirect=lambda x: None)
        self.req.session = Session(self.env, self.req)
        self.req.session.save()

    def test_last_seen(self):
        user = 'user'

        # Use basic function.
        self.assertEqual(last_seen(self.env), [])
        self._create_session(user)
        # Devel: Not fail-safe, will produce random false-negatives.
        now = time.time()
        self.assertEqual(last_seen(self.env), [(user, int(now))])

        # Use 1st optional kwarg.
        self.assertEqual(last_seen(self.env, user), [(user, int(now))])
        user = 'anotheruser'
        self.assertEqual(last_seen(self.env, user), [])
        # Don't care for anonymous session IDs.
        self._create_session(user, False)
        self.assertEqual(last_seen(self.env, user), [])

    def test_user_known(self):
        user = 'user'
        self.assertFalse(user_known(self.env, user))
        # Don't care for anonymous session IDs.
        self._create_session(user, False)
        self.assertFalse(user_known(self.env, user))
        self._create_session(user)
        self.assertTrue(user_known(self.env, user))

    def test_get_user_attribute(self):
        self.assertEqual(get_user_attribute(self.env, authenticated=None), {})

        with self.env.db_transaction as db:
            db.executemany("""
                INSERT INTO session_attribute (sid,authenticated,name,value)
                VALUES (%s,%s,%s,%s)
                """, [('user', 0, 'attribute1', 'value1'),
                      ('user', 0, 'attribute2', 'value2'),
                      ('user', 1, 'attribute1', 'value1'),
                      ('user', 1, 'attribute2', 'value2'),
                      ('another', 1, 'attribute2', 'value3')])

        no_constraints = get_user_attribute(self.env, authenticated=None)
        # Distinct session IDs form top-level keys.
        self.assertEqual(set(no_constraints.keys()),
                         set([u'user', u'another']))
        # There are probably anonymous sessions named equally to
        # authenticated ones, causing different nested dicts below each
        # session ID.  Btw, only authenticated ones are real usernames.
        self.assertTrue(0 in no_constraints['user'])
        self.assertTrue(1 in no_constraints['user'])
        self.assertFalse(0 in no_constraints['another'])
        self.assertTrue(1 in no_constraints['another'])
        # Touch some of the attributes stored before.
        self.assertTrue(no_constraints['user'][0]['attribute1'], 'value1')
        self.assertTrue(no_constraints['user'][1]['attribute2'], 'value2')
        self.assertEqual(no_constraints['another'].get(0), None)
        self.assertTrue(no_constraints['another'][1]['attribute2'], 'value3')

    def test_set_user_attribute(self):
        set_user_attribute(self.env, 'user', 'attribute1', 'value1')

        with self.env.db_query as db:
            for name, value in db("""
                    SELECT name,value FROM session_attribute
                    WHERE sid='user' AND authenticated=1
                    """):
                self.assertEqual(('attribute1', 'value1'), (name, value))
            # Setting an attribute twice will just update the value.
            set_user_attribute(self.env, 'user', 'attribute1', 'value2')
            for name, value in db("""
                    SELECT name,value FROM session_attribute
                    WHERE sid='user' AND authenticated=1
                    """):
                self.assertEqual(('attribute1', 'value2'), (name, value))
            # All values are stored as strings internally, but the function
            # should take care to handle foreseeable abuse gracefully.
            # This is a test for possible regressions of #10772.
            set_user_attribute(self.env, 'user', 'attribute1', 0)
            for name, value in db("""
                    SELECT name,value FROM session_attribute
                    WHERE  sid='user' AND authenticated=1
                    """):
                self.assertEqual(('attribute1', '0'), (name, value))


class KnownUsersCacheUpdateTestCase(unittest.TestCase):

    def setUp(self):
        self.env = EnvironmentStub(default_data=True)
        if pkg_resources.parse_version(VERSION) < \
                pkg_resources.parse_version('1.2'):
            from trac.env import Environment
            self.env.get_known_users = \
                new.instancemethod(Environment.get_known_users, self.env, None)

    def tearDown(self):
        self.env.shutdown()
        self.env.reset_db()

    def _insert_user(self):
        sid = 'user1'
        name = 'User One'
        email = 'user1@example.org'
        prime_auth_session(self.env, sid)
        set_user_attribute(self.env, sid, 'name', name)
        set_user_attribute(self.env, sid, 'email', email)
        return sid, name, email

    def test_set_user_attribute(self):
        sid, name, email = self._insert_user()
        new_email = 'user1@domain.org'

        known_users = list(self.env.get_known_users())
        self.assertEqual([(sid, name, email)], known_users)
        set_user_attribute(self.env, sid, 'email', new_email)
        known_users = list(self.env.get_known_users())
        self.assertEqual([(sid, name, new_email)], known_users)

    def test_change_uid(self):
        sid, name, email = self._insert_user()
        new_sid = 'user2'

        known_users = list(self.env.get_known_users())
        self.assertEqual([(sid, name, email)], known_users)
        change_uid(self.env, sid, new_sid, [], False)
        known_users = list(self.env.get_known_users())
        self.assertEqual([(new_sid, name, email)], known_users)

    def test_prime_auth_session(self):
        """The known_users cache is updated after inserting a session."""
        self.assertEqual(0, len(list(self.env.get_known_users())))
        sid = 'user1'

        prime_auth_session(self.env, sid)

        known_users = list(self.env.get_known_users())
        self.assertEqual(1, len(known_users))
        self.assertEqual(sid, known_users[0][0])
        self.assertIsNone(known_users[0][1])
        self.assertIsNone(known_users[0][2])

    def test_del_user_attribute(self):
        sid, name, email = self._insert_user()

        known_users = list(self.env.get_known_users())
        self.assertEqual([(sid, name, email)], known_users)
        del_user_attribute(self.env, sid, attribute='name')
        known_users = list(self.env.get_known_users())
        self.assertEqual([(sid, None, email)], known_users)

    def test_delete_user(self):
        sid = self._insert_user()[0]

        self.assertEqual(1, len(list(self.env.get_known_users())))
        delete_user(self.env, sid)
        self.assertEqual(0, len(list(self.env.get_known_users())))


def test_suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(ModelTestCase))
    suite.addTest(unittest.makeSuite(KnownUsersCacheUpdateTestCase))
    return suite


if __name__ == '__main__':
    unittest.main(defaultTest='test_suite')
